// Package vulncheck provides a vulnerability source backed by the VulnCheck API.
package vulncheck

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/git-pkgs/purl"
	"github.com/git-pkgs/vulns"
)

const (
	DefaultAPIURL  = "https://api.vulncheck.com/v3"
	DefaultTimeout = 30 * time.Second
)

// Source implements vulns.Source using the VulnCheck API.
// Note: VulnCheck requires authentication via bearer token.
type Source struct {
	httpClient *http.Client
	baseURL    string
	token      string
}

// Option configures a Source.
type Option func(*Source)

// WithHTTPClient sets a custom HTTP client.
func WithHTTPClient(c *http.Client) Option {
	return func(s *Source) {
		s.httpClient = c
	}
}

// WithBaseURL sets a custom API base URL.
func WithBaseURL(url string) Option {
	return func(s *Source) {
		s.baseURL = url
	}
}

// WithToken sets the VulnCheck API token. Required for all requests.
func WithToken(token string) Option {
	return func(s *Source) {
		s.token = token
	}
}

// New creates a new VulnCheck source.
// A token must be provided via WithToken for the source to work.
func New(opts ...Option) *Source {
	s := &Source{
		httpClient: &http.Client{Timeout: DefaultTimeout},
		baseURL:    DefaultAPIURL,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Name returns "vulncheck".
func (s *Source) Name() string {
	return "vulncheck"
}

// Query returns vulnerabilities affecting the package identified by the PURL.
func (s *Source) Query(ctx context.Context, p *purl.PURL) ([]vulns.Vulnerability, error) {
	if s.token == "" {
		return nil, fmt.Errorf("vulncheck: token required")
	}

	reqURL := fmt.Sprintf("%s/purl?purl=%s", s.baseURL, url.QueryEscape(p.String()))

	httpReq, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+s.token)

	resp, err := s.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("query failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	var apiResp purlResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	return convertVulnerabilities(apiResp.Data, p), nil
}

// QueryBatch queries multiple packages. VulnCheck doesn't have a batch API,
// so this makes individual requests.
func (s *Source) QueryBatch(ctx context.Context, purls []*purl.PURL) ([][]vulns.Vulnerability, error) {
	results := make([][]vulns.Vulnerability, len(purls))
	for i, p := range purls {
		v, err := s.Query(ctx, p)
		if err != nil {
			return nil, fmt.Errorf("querying %s: %w", p.String(), err)
		}
		results[i] = v
	}
	return results, nil
}

// Get fetches a specific vulnerability by ID.
func (s *Source) Get(ctx context.Context, id string) (*vulns.Vulnerability, error) {
	if s.token == "" {
		return nil, fmt.Errorf("vulncheck: token required")
	}

	// VulnCheck uses /v3/cve/{cve_id} for individual CVE lookups
	httpReq, err := http.NewRequestWithContext(ctx, "GET", s.baseURL+"/cve/"+url.PathEscape(id), nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+s.token)

	resp, err := s.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("get vulnerability failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	var apiResp cveResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	if len(apiResp.Data) == 0 {
		return nil, nil
	}

	result := convertCVE(apiResp.Data[0])
	return &result, nil
}

func convertVulnerabilities(data purlData, p *purl.PURL) []vulns.Vulnerability {
	var result []vulns.Vulnerability

	for _, cve := range data.CVEs {
		v := vulns.Vulnerability{
			ID: cve,
		}

		// Add affected package info
		affected := vulns.Affected{
			Package: vulns.Package{
				Ecosystem: purl.EcosystemToOSV(p.Type),
				Name:      p.FullName(),
				PURL:      p.String(),
			},
		}

		v.Affected = append(v.Affected, affected)
		result = append(result, v)
	}

	// Also process structured vulnerabilities if available
	for _, vuln := range data.Vulnerabilities {
		v := vulns.Vulnerability{
			ID: vuln.Detection,
		}

		affected := vulns.Affected{
			Package: vulns.Package{
				Ecosystem: purl.EcosystemToOSV(p.Type),
				Name:      p.FullName(),
				PURL:      p.String(),
			},
		}

		// Add fixed version info
		if vuln.FixedVersion != "" {
			affected.Ranges = append(affected.Ranges, vulns.Range{
				Type: "ECOSYSTEM",
				Events: []vulns.Event{
					{Introduced: "0"},
					{Fixed: vuln.FixedVersion},
				},
			})
		}

		v.Affected = append(v.Affected, affected)
		result = append(result, v)
	}

	return result
}

func convertCVE(cve cveData) vulns.Vulnerability {
	v := vulns.Vulnerability{
		ID:      cve.CVE,
		Summary: cve.Description,
	}

	if cve.Published != "" {
		if t, err := time.Parse(time.RFC3339, cve.Published); err == nil {
			v.Published = t
		}
	}
	if cve.Modified != "" {
		if t, err := time.Parse(time.RFC3339, cve.Modified); err == nil {
			v.Modified = t
		}
	}

	if cve.CVSSv3Score > 0 {
		v.Severity = append(v.Severity, vulns.Severity{
			Type:  "CVSS_V3",
			Score: fmt.Sprintf("%.1f", cve.CVSSv3Score),
		})
	}

	for _, ref := range cve.References {
		v.References = append(v.References, vulns.Reference{
			Type: "WEB",
			URL:  ref,
		})
	}

	return v
}

// API response types

type purlResponse struct {
	Meta purlMeta `json:"_meta"`
	Data purlData `json:"data"`
}

type purlMeta struct {
	PURL          string `json:"purl"`
	Timestamp     string `json:"timestamp"`
	TotalDocuments int    `json:"total_documents"`
}

type purlData struct {
	CVEs            []string          `json:"cves"`
	Vulnerabilities []vulnCheckVuln   `json:"vulnerabilities"`
}

type vulnCheckVuln struct {
	Detection    string `json:"detection"`
	FixedVersion string `json:"fixed_version"`
}

type cveResponse struct {
	Data []cveData `json:"data"`
}

type cveData struct {
	CVE         string   `json:"cve"`
	Description string   `json:"description"`
	Published   string   `json:"published"`
	Modified    string   `json:"modified"`
	CVSSv3Score float64  `json:"cvss_v3_score"`
	References  []string `json:"references"`
}
