// Package vl provides a vulnerability source backed by vulnerability-lookup.org (CIRCL).
package vl

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/git-pkgs/purl"
	"github.com/git-pkgs/vulns"
)

const (
	DefaultAPIURL  = "https://vulnerability.circl.lu/api"
	DefaultTimeout = 30 * time.Second
)

// Source implements vulns.Source using the vulnerability-lookup API.
type Source struct {
	httpClient *http.Client
	baseURL    string
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

// New creates a new vulnerability-lookup source.
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

// Name returns "vulnerability-lookup".
func (s *Source) Name() string {
	return "vulnerability-lookup"
}

// Query returns vulnerabilities affecting the package identified by the PURL.
// Note: vulnerability-lookup uses vendor/product search, so this maps the PURL
// to vendor/product as best as possible.
func (s *Source) Query(ctx context.Context, p *purl.PURL) ([]vulns.Vulnerability, error) {
	vendor, product := purlToVendorProduct(p)
	if vendor == "" || product == "" {
		return nil, nil
	}

	url := fmt.Sprintf("%s/vulnerability/search/%s/%s",
		s.baseURL, url.PathEscape(vendor), url.PathEscape(product))

	httpReq, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

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

	var apiResp searchResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	return s.convertVulnerabilities(apiResp.Data, p), nil
}

// QueryBatch queries multiple packages. Vulnerability-lookup doesn't have a batch API,
// so this makes individual requests.
func (s *Source) QueryBatch(ctx context.Context, purls []*purl.PURL) ([][]vulns.Vulnerability, error) {
	results := make([][]vulns.Vulnerability, len(purls))
	for i, p := range purls {
		vulns, err := s.Query(ctx, p)
		if err != nil {
			return nil, fmt.Errorf("querying %s: %w", p.String(), err)
		}
		results[i] = vulns
	}
	return results, nil
}

// Get fetches a specific vulnerability by ID.
func (s *Source) Get(ctx context.Context, id string) (*vulns.Vulnerability, error) {
	httpReq, err := http.NewRequestWithContext(ctx, "GET", s.baseURL+"/vulnerability/"+url.PathEscape(id), nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

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

	var apiVuln apiVulnerability
	if err := json.NewDecoder(resp.Body).Decode(&apiVuln); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	result := convertVulnerability(apiVuln, nil)
	return &result, nil
}

func (s *Source) convertVulnerabilities(apiVulns []apiVulnerability, p *purl.PURL) []vulns.Vulnerability {
	var result []vulns.Vulnerability
	for _, av := range apiVulns {
		result = append(result, convertVulnerability(av, p))
	}
	return result
}

func convertVulnerability(av apiVulnerability, p *purl.PURL) vulns.Vulnerability {
	v := vulns.Vulnerability{
		ID:      av.ID,
		Summary: av.Summary,
		Details: av.Description,
	}

	// Parse timestamps
	if av.Published != "" {
		if t, err := time.Parse(time.RFC3339, av.Published); err == nil {
			v.Published = t
		}
	}
	if av.Modified != "" {
		if t, err := time.Parse(time.RFC3339, av.Modified); err == nil {
			v.Modified = t
		}
	}

	// Add aliases (other CVE IDs, GHSA IDs, etc.)
	v.Aliases = av.Aliases

	// Add references
	for _, ref := range av.References {
		v.References = append(v.References, vulns.Reference{
			Type: "WEB",
			URL:  ref,
		})
	}

	// Add severity from CVSS
	if av.CVSSv3Score > 0 {
		v.Severity = append(v.Severity, vulns.Severity{
			Type:  "CVSS_V3",
			Score: fmt.Sprintf("%.1f", av.CVSSv3Score),
		})
	}
	if av.CVSSv3Vector != "" {
		v.Severity = append(v.Severity, vulns.Severity{
			Type:  "CVSS_V3",
			Score: av.CVSSv3Vector,
		})
	}

	// Add affected packages from CPE data
	if p != nil {
		affected := vulns.Affected{
			Package: vulns.Package{
				Ecosystem: purl.EcosystemToOSV(p.Type),
				Name:      p.FullName(),
				PURL:      p.String(),
			},
		}
		// Note: vulnerability-lookup doesn't always provide version ranges
		// in a structured format, so we may not have precise affected ranges
		v.Affected = append(v.Affected, affected)
	}

	return v
}

// purlToVendorProduct maps a PURL to vendor/product for vulnerability-lookup.
// The mapping varies by ecosystem.
func purlToVendorProduct(p *purl.PURL) (vendor, product string) {
	name := p.FullName()

	switch p.Type {
	case "npm":
		// npm: vendor is often the scope or "npm", product is the package name
		if p.Namespace != "" {
			return strings.TrimPrefix(p.Namespace, "@"), p.Name
		}
		return "npm", name

	case "pypi":
		return "pypi", strings.ToLower(name)

	case "gem":
		return "rubygems", name

	case "cargo":
		return "rust", name

	case "golang":
		// For Go, vendor is often the org/user, product is the repo/module
		parts := strings.Split(name, "/")
		if len(parts) >= 2 {
			return parts[len(parts)-2], parts[len(parts)-1]
		}
		return "golang", name

	case "maven":
		// Maven: group:artifact - vendor is group, product is artifact
		if p.Namespace != "" {
			return p.Namespace, p.Name
		}
		return "maven", name

	case "composer":
		// Composer: vendor/package
		if p.Namespace != "" {
			return p.Namespace, p.Name
		}
		return "composer", name

	case "nuget":
		return "nuget", name

	default:
		return p.Type, name
	}
}

// API response types

type searchResponse struct {
	Data []apiVulnerability `json:"data"`
}

type apiVulnerability struct {
	ID           string   `json:"id"`
	Summary      string   `json:"summary"`
	Description  string   `json:"description"`
	Published    string   `json:"published"`
	Modified     string   `json:"modified"`
	Aliases      []string `json:"aliases"`
	References   []string `json:"references"`
	CVSSv3Score  float64  `json:"cvss_v3_score"`
	CVSSv3Vector string   `json:"cvss_v3_vector"`
	CWEs         []string `json:"cwe"`
}
