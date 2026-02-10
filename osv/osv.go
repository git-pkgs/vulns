// Package osv provides a vulnerability source backed by the OSV API.
package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/git-pkgs/purl"
	"github.com/git-pkgs/vulns"
)

const (
	DefaultAPIURL  = "https://api.osv.dev/v1"
	DefaultTimeout = 30 * time.Second
)

// Source implements vulns.Source using the OSV API.
type Source struct {
	httpClient *http.Client
	baseURL    string
	userAgent  string
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

// WithUserAgent sets the User-Agent header for API requests.
func WithUserAgent(ua string) Option {
	return func(s *Source) {
		s.userAgent = ua
	}
}

// New creates a new OSV source.
func New(opts ...Option) *Source {
	s := &Source{
		httpClient: &http.Client{Timeout: DefaultTimeout},
		baseURL:    DefaultAPIURL,
		userAgent:  "vulns",
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Name returns "osv".
func (s *Source) Name() string {
	return "osv"
}

// Query returns vulnerabilities affecting the package identified by the PURL.
func (s *Source) Query(ctx context.Context, p *purl.PURL) ([]vulns.Vulnerability, error) {
	ecosystem := purl.EcosystemToOSV(p.Type)
	name := p.FullName()

	req := queryRequest{
		Version: p.Version,
		Package: packageRef{
			Ecosystem: ecosystem,
			Name:      name,
		},
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshaling request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", s.baseURL+"/query", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("User-Agent", s.userAgent)

	resp, err := s.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("query failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	var queryResp queryResponse
	if err := json.NewDecoder(resp.Body).Decode(&queryResp); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	return queryResp.Vulns, nil
}

// QueryBatch queries multiple packages at once.
func (s *Source) QueryBatch(ctx context.Context, purls []*purl.PURL) ([][]vulns.Vulnerability, error) {
	if len(purls) == 0 {
		return nil, nil
	}

	queries := make([]queryRequest, len(purls))
	for i, p := range purls {
		queries[i] = queryRequest{
			Version: p.Version,
			Package: packageRef{
				Ecosystem: purl.EcosystemToOSV(p.Type),
				Name:      p.FullName(),
			},
		}
	}

	// OSV batch API has a limit of 1000 queries per request
	const batchSize = 1000
	var allResults [][]vulns.Vulnerability

	for i := 0; i < len(queries); i += batchSize {
		end := i + batchSize
		if end > len(queries) {
			end = len(queries)
		}
		batch := queries[i:end]

		req := batchQueryRequest{Queries: batch}
		body, err := json.Marshal(req)
		if err != nil {
			return nil, fmt.Errorf("marshaling request: %w", err)
		}

		httpReq, err := http.NewRequestWithContext(ctx, "POST", s.baseURL+"/querybatch", bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("creating request: %w", err)
		}
		httpReq.Header.Set("Content-Type", "application/json")
		httpReq.Header.Set("User-Agent", s.userAgent)

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

		for _, result := range batchResp.Results {
			allResults = append(allResults, result.Vulns)
		}
	}

	return allResults, nil
}

// Get fetches a specific vulnerability by ID.
func (s *Source) Get(ctx context.Context, id string) (*vulns.Vulnerability, error) {
	httpReq, err := http.NewRequestWithContext(ctx, "GET", s.baseURL+"/vulns/"+id, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	httpReq.Header.Set("User-Agent", s.userAgent)

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

	var vuln vulns.Vulnerability
	if err := json.NewDecoder(resp.Body).Decode(&vuln); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	return &vuln, nil
}

// Internal request/response types for the OSV API

type queryRequest struct {
	Commit  string     `json:"commit,omitempty"`
	Version string     `json:"version,omitempty"`
	Package packageRef `json:"package,omitempty"`
}

type packageRef struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	PURL      string `json:"purl,omitempty"`
}

type queryResponse struct {
	Vulns []vulns.Vulnerability `json:"vulns,omitempty"`
}

type batchQueryRequest struct {
	Queries []queryRequest `json:"queries"`
}

type batchQueryResponse struct {
	Results []queryResponse `json:"results"`
}
