// Package nvd provides a vulnerability source backed by the NIST NVD API.
package nvd

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
	DefaultAPIURL  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	DefaultTimeout = 30 * time.Second
)

// Source implements vulns.Source using the NVD API.
// Note: NVD is CVE-focused and queries by CPE, not package name directly.
// PURL-to-CPE mapping is approximate.
type Source struct {
	httpClient *http.Client
	baseURL    string
	apiKey     string
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

// WithAPIKey sets the NVD API key. Optional but recommended to avoid rate limits.
// Without a key: 5 requests per 30 seconds.
// With a key: 50 requests per 30 seconds.
func WithAPIKey(key string) Option {
	return func(s *Source) {
		s.apiKey = key
	}
}

// New creates a new NVD source.
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

// Name returns "nvd".
func (s *Source) Name() string {
	return "nvd"
}

// Query returns vulnerabilities affecting the package identified by the PURL.
// NVD uses CPE for matching, so this converts the PURL to a CPE search.
func (s *Source) Query(ctx context.Context, p *purl.PURL) ([]vulns.Vulnerability, error) {
	// Build keyword search from package name
	// NVD doesn't have great PURL support, so we search by keyword
	keyword := p.Name
	if p.Namespace != "" {
		keyword = p.Namespace + " " + p.Name
	}

	reqURL := fmt.Sprintf("%s?keywordSearch=%s", s.baseURL, url.QueryEscape(keyword))
	if p.Version != "" {
		reqURL += "&versionStart=" + url.QueryEscape(p.Version)
		reqURL += "&versionStartType=including"
		reqURL += "&versionEnd=" + url.QueryEscape(p.Version)
		reqURL += "&versionEndType=including"
	}

	httpReq, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	if s.apiKey != "" {
		httpReq.Header.Set("apiKey", s.apiKey)
	}

	resp, err := s.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}

	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("rate limited: consider using WithAPIKey")
	}

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("query failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	var nvdResp nvdResponse
	if err := json.NewDecoder(resp.Body).Decode(&nvdResp); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	return convertVulnerabilities(nvdResp.Vulnerabilities, p), nil
}

// QueryBatch queries multiple packages. NVD doesn't have a batch API,
// so this makes individual requests with rate limiting.
func (s *Source) QueryBatch(ctx context.Context, purls []*purl.PURL) ([][]vulns.Vulnerability, error) {
	results := make([][]vulns.Vulnerability, len(purls))

	// NVD rate limits: 5 req/30s without key, 50 req/30s with key
	delay := 6 * time.Second
	if s.apiKey != "" {
		delay = 600 * time.Millisecond
	}

	for i, p := range purls {
		if i > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}
		}

		v, err := s.Query(ctx, p)
		if err != nil {
			return nil, fmt.Errorf("querying %s: %w", p.String(), err)
		}
		results[i] = v
	}
	return results, nil
}

// Get fetches a specific vulnerability by CVE ID.
func (s *Source) Get(ctx context.Context, id string) (*vulns.Vulnerability, error) {
	if !strings.HasPrefix(strings.ToUpper(id), "CVE-") {
		return nil, nil // Not a CVE ID
	}

	reqURL := fmt.Sprintf("%s?cveId=%s", s.baseURL, url.QueryEscape(id))

	httpReq, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	if s.apiKey != "" {
		httpReq.Header.Set("apiKey", s.apiKey)
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

	var nvdResp nvdResponse
	if err := json.NewDecoder(resp.Body).Decode(&nvdResp); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	if len(nvdResp.Vulnerabilities) == 0 {
		return nil, nil
	}

	vulnList := convertVulnerabilities(nvdResp.Vulnerabilities, nil)
	if len(vulnList) == 0 {
		return nil, nil
	}
	return &vulnList[0], nil
}

func convertVulnerabilities(nvdVulns []nvdVulnerability, p *purl.PURL) []vulns.Vulnerability {
	var result []vulns.Vulnerability

	for _, nv := range nvdVulns {
		cve := nv.CVE
		v := vulns.Vulnerability{
			ID:      cve.ID,
			Summary: getEnglishDescription(cve.Descriptions),
		}

		// Parse timestamps
		if cve.Published != "" {
			if t, err := time.Parse(time.RFC3339, cve.Published); err == nil {
				v.Published = t
			}
		}
		if cve.LastModified != "" {
			if t, err := time.Parse(time.RFC3339, cve.LastModified); err == nil {
				v.Modified = t
			}
		}

		// Add references
		for _, ref := range cve.References {
			v.References = append(v.References, vulns.Reference{
				Type: "WEB",
				URL:  ref.URL,
			})
		}

		// Add CVSS severity
		if len(cve.Metrics.CVSSMetricV31) > 0 {
			m := cve.Metrics.CVSSMetricV31[0]
			v.Severity = append(v.Severity, vulns.Severity{
				Type:  "CVSS_V3",
				Score: m.CVSSData.VectorString,
			})
		} else if len(cve.Metrics.CVSSMetricV30) > 0 {
			m := cve.Metrics.CVSSMetricV30[0]
			v.Severity = append(v.Severity, vulns.Severity{
				Type:  "CVSS_V3",
				Score: m.CVSSData.VectorString,
			})
		} else if len(cve.Metrics.CVSSMetricV2) > 0 {
			m := cve.Metrics.CVSSMetricV2[0]
			v.Severity = append(v.Severity, vulns.Severity{
				Type:  "CVSS_V2",
				Score: m.CVSSData.VectorString,
			})
		}

		// Add affected package info if we have a PURL
		if p != nil {
			affected := vulns.Affected{
				Package: vulns.Package{
					Ecosystem: purl.EcosystemToOSV(p.Type),
					Name:      p.FullName(),
					PURL:      p.String(),
				},
			}
			v.Affected = append(v.Affected, affected)
		}

		result = append(result, v)
	}

	return result
}

func getEnglishDescription(descriptions []nvdDescription) string {
	for _, d := range descriptions {
		if d.Lang == "en" {
			return d.Value
		}
	}
	if len(descriptions) > 0 {
		return descriptions[0].Value
	}
	return ""
}

// NVD API response types

type nvdResponse struct {
	ResultsPerPage  int                `json:"resultsPerPage"`
	StartIndex      int                `json:"startIndex"`
	TotalResults    int                `json:"totalResults"`
	Vulnerabilities []nvdVulnerability `json:"vulnerabilities"`
}

type nvdVulnerability struct {
	CVE nvdCVE `json:"cve"`
}

type nvdCVE struct {
	ID           string           `json:"id"`
	Published    string           `json:"published"`
	LastModified string           `json:"lastModified"`
	Descriptions []nvdDescription `json:"descriptions"`
	References   []nvdReference   `json:"references"`
	Metrics      nvdMetrics       `json:"metrics"`
}

type nvdDescription struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type nvdReference struct {
	URL    string   `json:"url"`
	Source string   `json:"source"`
	Tags   []string `json:"tags"`
}

type nvdMetrics struct {
	CVSSMetricV31 []nvdCVSSMetric `json:"cvssMetricV31"`
	CVSSMetricV30 []nvdCVSSMetric `json:"cvssMetricV30"`
	CVSSMetricV2  []nvdCVSSMetric `json:"cvssMetricV2"`
}

type nvdCVSSMetric struct {
	Source   string      `json:"source"`
	Type     string      `json:"type"`
	CVSSData nvdCVSSData `json:"cvssData"`
}

type nvdCVSSData struct {
	Version      string  `json:"version"`
	VectorString string  `json:"vectorString"`
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}
