// Package depsdev provides a vulnerability source backed by Google's deps.dev API.
package depsdev

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
	DefaultAPIURL  = "https://api.deps.dev/v3alpha"
	DefaultTimeout = 30 * time.Second
)

// Source implements vulns.Source using the deps.dev API.
// This is a free API with no authentication required.
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

// New creates a new deps.dev source.
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

// Name returns "deps.dev".
func (s *Source) Name() string {
	return "deps.dev"
}

// Query returns vulnerabilities affecting the package identified by the PURL.
func (s *Source) Query(ctx context.Context, p *purl.PURL) ([]vulns.Vulnerability, error) {
	system := purlTypeToSystem(p.Type)
	if system == "" {
		return nil, nil // Unsupported ecosystem
	}

	// Use PURL lookup endpoint
	reqURL := fmt.Sprintf("%s/purl/%s", s.baseURL, url.PathEscape(p.String()))

	httpReq, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
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

	var purlResp purlResponse
	if err := json.NewDecoder(resp.Body).Decode(&purlResp); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	// Fetch advisories for each advisory key
	var result []vulns.Vulnerability
	for _, key := range purlResp.Version.AdvisoryKeys {
		adv, err := s.getAdvisory(ctx, key.ID)
		if err != nil {
			continue // Skip failed advisory fetches
		}
		if adv != nil {
			result = append(result, *adv)
		}
	}

	return result, nil
}

// QueryBatch queries multiple packages at once using the batch endpoint.
func (s *Source) QueryBatch(ctx context.Context, purls []*purl.PURL) ([][]vulns.Vulnerability, error) {
	if len(purls) == 0 {
		return nil, nil
	}

	// deps.dev batch endpoint supports up to 5000 requests
	const batchSize = 5000
	results := make([][]vulns.Vulnerability, len(purls))

	for i := 0; i < len(purls); i += batchSize {
		end := i + batchSize
		if end > len(purls) {
			end = len(purls)
		}
		batch := purls[i:end]

		// Build batch request
		var requests []batchRequest
		for _, p := range batch {
			requests = append(requests, batchRequest{
				Purl: p.String(),
			})
		}

		reqBody, err := json.Marshal(batchQueryRequest{Requests: requests})
		if err != nil {
			return nil, fmt.Errorf("marshaling batch request: %w", err)
		}

		httpReq, err := http.NewRequestWithContext(ctx, "POST", s.baseURL+"/purlbatch", strings.NewReader(string(reqBody)))
		if err != nil {
			return nil, fmt.Errorf("creating request: %w", err)
		}
		httpReq.Header.Set("Content-Type", "application/json")

		resp, err := s.httpClient.Do(httpReq)
		if err != nil {
			return nil, fmt.Errorf("executing request: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			respBody, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			return nil, fmt.Errorf("batch query failed with status %d: %s", resp.StatusCode, string(respBody))
		}

		var batchResp batchQueryResponse
		if err := json.NewDecoder(resp.Body).Decode(&batchResp); err != nil {
			_ = resp.Body.Close()
			return nil, fmt.Errorf("decoding response: %w", err)
		}
		_ = resp.Body.Close()

		// Process batch results
		for j, r := range batchResp.Responses {
			if r.Version == nil {
				continue
			}
			var vulnList []vulns.Vulnerability
			for _, key := range r.Version.AdvisoryKeys {
				adv, err := s.getAdvisory(ctx, key.ID)
				if err != nil {
					continue
				}
				if adv != nil {
					vulnList = append(vulnList, *adv)
				}
			}
			results[i+j] = vulnList
		}
	}

	return results, nil
}

// Get fetches a specific vulnerability by ID (OSV ID).
func (s *Source) Get(ctx context.Context, id string) (*vulns.Vulnerability, error) {
	return s.getAdvisory(ctx, id)
}

func (s *Source) getAdvisory(ctx context.Context, id string) (*vulns.Vulnerability, error) {
	httpReq, err := http.NewRequestWithContext(ctx, "GET", s.baseURL+"/advisories/"+url.PathEscape(id), nil)
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
		return nil, fmt.Errorf("get advisory failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	var adv advisoryResponse
	if err := json.NewDecoder(resp.Body).Decode(&adv); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	return convertAdvisory(adv), nil
}

func convertAdvisory(adv advisoryResponse) *vulns.Vulnerability {
	v := &vulns.Vulnerability{
		ID:      adv.AdvisoryKey.ID,
		Summary: adv.Title,
		Aliases: adv.Aliases,
	}

	if adv.URL != "" {
		v.References = append(v.References, vulns.Reference{
			Type: "ADVISORY",
			URL:  adv.URL,
		})
	}

	// Add CVSS score if available
	if adv.CVSSScore > 0 {
		v.Severity = append(v.Severity, vulns.Severity{
			Type:  "CVSS_V3",
			Score: fmt.Sprintf("%.1f", adv.CVSSScore),
		})
	}

	return v
}

// purlTypeToSystem converts a PURL type to deps.dev system name.
func purlTypeToSystem(purlType string) string {
	switch purlType {
	case "npm":
		return "NPM"
	case "pypi":
		return "PYPI"
	case "maven":
		return "MAVEN"
	case "cargo":
		return "CARGO"
	case "golang":
		return "GO"
	case "nuget":
		return "NUGET"
	case "gem":
		return "RUBYGEMS"
	default:
		return ""
	}
}

// API types

type purlResponse struct {
	Version *versionInfo `json:"version"`
}

type versionInfo struct {
	AdvisoryKeys []advisoryKey `json:"advisoryKeys"`
}

type advisoryKey struct {
	ID string `json:"id"`
}

type advisoryResponse struct {
	AdvisoryKey advisoryKey `json:"advisoryKey"`
	URL         string      `json:"url"`
	Title       string      `json:"title"`
	Aliases     []string    `json:"aliases"`
	CVSSScore   float64     `json:"cvss3Score"`
}

type batchQueryRequest struct {
	Requests []batchRequest `json:"requests"`
}

type batchRequest struct {
	Purl string `json:"purl"`
}

type batchQueryResponse struct {
	Responses []batchResponse `json:"responses"`
}

type batchResponse struct {
	Version *versionInfo `json:"version"`
}
