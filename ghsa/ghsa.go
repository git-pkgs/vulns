// Package ghsa provides a vulnerability source backed by the GitHub Security Advisory API.
package ghsa

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/git-pkgs/purl"
	"github.com/git-pkgs/vulns"
)

const (
	DefaultAPIURL  = "https://api.github.com"
	DefaultTimeout = 30 * time.Second
)

// Source implements vulns.Source using the GitHub Security Advisory API.
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

// WithToken sets the GitHub API token. Optional for public advisory data,
// but recommended to avoid rate limits.
func WithToken(token string) Option {
	return func(s *Source) {
		s.token = token
	}
}

// New creates a new GHSA source.
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

// Name returns "ghsa".
func (s *Source) Name() string {
	return "ghsa"
}

// Query returns vulnerabilities affecting the package identified by the PURL.
func (s *Source) Query(ctx context.Context, p *purl.PURL) ([]vulns.Vulnerability, error) {
	ecosystem := purlTypeToGHSA(p.Type)
	if ecosystem == "" {
		return nil, nil // Unsupported ecosystem
	}

	// Build the query URL
	url := fmt.Sprintf("%s/advisories?ecosystem=%s&package=%s&per_page=100",
		s.baseURL, ecosystem, p.FullName())

	if p.Version != "" {
		url += "&affects=" + p.Version
	}

	advisories, err := s.fetchAdvisories(ctx, url)
	if err != nil {
		return nil, err
	}

	return s.convertAdvisories(advisories, p.Version), nil
}

// QueryBatch queries multiple packages. GHSA doesn't have a batch API,
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
	if !strings.HasPrefix(id, "GHSA-") {
		return nil, nil // Not a GHSA ID
	}

	httpReq, err := http.NewRequestWithContext(ctx, "GET", s.baseURL+"/advisories/"+id, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	s.setHeaders(httpReq)

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

	var adv advisory
	if err := json.NewDecoder(resp.Body).Decode(&adv); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	vulns := s.convertAdvisories([]advisory{adv}, "")
	if len(vulns) == 0 {
		return nil, nil
	}
	return &vulns[0], nil
}

func (s *Source) setHeaders(req *http.Request) {
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if s.token != "" {
		req.Header.Set("Authorization", "Bearer "+s.token)
	}
}

func (s *Source) fetchAdvisories(ctx context.Context, url string) ([]advisory, error) {
	httpReq, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	s.setHeaders(httpReq)

	resp, err := s.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("query failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	var advisories []advisory
	if err := json.NewDecoder(resp.Body).Decode(&advisories); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	return advisories, nil
}

func (s *Source) convertAdvisories(advisories []advisory, version string) []vulns.Vulnerability {
	var result []vulns.Vulnerability

	for _, adv := range advisories {
		v := vulns.Vulnerability{
			ID:        adv.GHSAID,
			Summary:   adv.Summary,
			Details:   adv.Description,
			Aliases:   adv.Identifiers.CVEs(),
			Published: adv.PublishedAt,
			Modified:  adv.UpdatedAt,
		}

		if adv.WithdrawnAt != nil {
			v.Withdrawn = adv.WithdrawnAt
		}

		// Add references
		for _, ref := range adv.References {
			v.References = append(v.References, vulns.Reference{
				Type: "WEB",
				URL:  ref,
			})
		}
		if adv.HTMLURL != "" {
			v.References = append(v.References, vulns.Reference{
				Type: "ADVISORY",
				URL:  adv.HTMLURL,
			})
		}

		// Add severity
		if adv.Severity != "" {
			v.Severity = append(v.Severity, vulns.Severity{
				Type:  "GHSA",
				Score: adv.Severity,
			})
		}
		if adv.CVSS != nil && adv.CVSS.Score > 0 {
			v.Severity = append(v.Severity, vulns.Severity{
				Type:  "CVSS_V3",
				Score: fmt.Sprintf("%.1f", adv.CVSS.Score),
			})
		}

		// Convert vulnerabilities to affected packages
		for _, vuln := range adv.Vulnerabilities {
			affected := vulns.Affected{
				Package: vulns.Package{
					Ecosystem: ghsaToOSVEcosystem(vuln.Package.Ecosystem),
					Name:      vuln.Package.Name,
				},
			}

			// Parse version range
			events := parseVersionRange(vuln.VulnerableVersionRange, vuln.FirstPatchedVersion)
			if len(events) > 0 {
				affected.Ranges = append(affected.Ranges, vulns.Range{
					Type:   "ECOSYSTEM",
					Events: events,
				})
			}

			v.Affected = append(v.Affected, affected)
		}

		result = append(result, v)
	}

	return result
}

// parseVersionRange converts GHSA version range syntax to OSV events.
// GHSA uses syntax like ">= 1.0, < 2.0" or "= 1.5.0"
func parseVersionRange(rangeStr, patchedVersion string) []vulns.Event {
	var events []vulns.Event

	if rangeStr == "" {
		return events
	}

	// Split on comma for multiple constraints
	parts := strings.Split(rangeStr, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		if strings.HasPrefix(part, ">=") {
			v := strings.TrimSpace(strings.TrimPrefix(part, ">="))
			events = append(events, vulns.Event{Introduced: v})
		} else if strings.HasPrefix(part, ">") {
			v := strings.TrimSpace(strings.TrimPrefix(part, ">"))
			events = append(events, vulns.Event{Introduced: v})
		} else if strings.HasPrefix(part, "<=") {
			v := strings.TrimSpace(strings.TrimPrefix(part, "<="))
			events = append(events, vulns.Event{LastAffected: v})
		} else if strings.HasPrefix(part, "<") {
			v := strings.TrimSpace(strings.TrimPrefix(part, "<"))
			events = append(events, vulns.Event{Fixed: v})
		} else if strings.HasPrefix(part, "=") {
			v := strings.TrimSpace(strings.TrimPrefix(part, "="))
			// Exact version: introduced and immediately fixed after
			events = append(events, vulns.Event{Introduced: v})
			events = append(events, vulns.Event{LastAffected: v})
		}
	}

	// Add patched version as fixed if provided and not already present
	if patchedVersion != "" {
		hasFixed := false
		for _, e := range events {
			if e.Fixed != "" {
				hasFixed = true
				break
			}
		}
		if !hasFixed {
			events = append(events, vulns.Event{Fixed: patchedVersion})
		}
	}

	// If no introduced event, assume from the beginning
	hasIntroduced := false
	for _, e := range events {
		if e.Introduced != "" {
			hasIntroduced = true
			break
		}
	}
	if !hasIntroduced && len(events) > 0 {
		events = append([]vulns.Event{{Introduced: "0"}}, events...)
	}

	return events
}

// purlTypeToGHSA converts a PURL type to GHSA ecosystem name.
func purlTypeToGHSA(purlType string) string {
	switch purlType {
	case "npm":
		return "npm"
	case "gem":
		return "rubygems"
	case "pypi":
		return "pip"
	case "maven":
		return "maven"
	case "nuget":
		return "nuget"
	case "cargo":
		return "rust"
	case "composer":
		return "composer"
	case "golang":
		return "go"
	case "hex":
		return "erlang"
	case "pub":
		return "pub"
	case "swift":
		return "swift"
	default:
		return ""
	}
}

// ghsaToOSVEcosystem converts GHSA ecosystem names to OSV ecosystem names.
func ghsaToOSVEcosystem(ghsaEco string) string {
	switch ghsaEco {
	case "npm":
		return "npm"
	case "rubygems":
		return "RubyGems"
	case "pip":
		return "PyPI"
	case "maven":
		return "Maven"
	case "nuget":
		return "NuGet"
	case "rust":
		return "crates.io"
	case "composer":
		return "Packagist"
	case "go":
		return "Go"
	case "erlang":
		return "Hex"
	case "pub":
		return "Pub"
	case "swift":
		return "SwiftPM"
	default:
		return ghsaEco
	}
}

// API response types

type advisory struct {
	GHSAID          string          `json:"ghsa_id"`
	CVEID           string          `json:"cve_id"`
	HTMLURL         string          `json:"html_url"`
	Summary         string          `json:"summary"`
	Description     string          `json:"description"`
	Severity        string          `json:"severity"`
	CVSS            *cvssInfo       `json:"cvss,omitempty"`
	Identifiers     identifiers     `json:"identifiers"`
	References      []string        `json:"references"`
	PublishedAt     time.Time       `json:"published_at"`
	UpdatedAt       time.Time       `json:"updated_at"`
	WithdrawnAt     *time.Time      `json:"withdrawn_at"`
	Vulnerabilities []vulnerability `json:"vulnerabilities"`
}

type cvssInfo struct {
	Score      float64 `json:"score"`
	VectorStr  string  `json:"vector_string"`
}

type identifiers struct {
	CVE  []identifier `json:"CVE"`
	GHSA []identifier `json:"GHSA"`
}

func (i identifiers) CVEs() []string {
	var result []string
	for _, id := range i.CVE {
		result = append(result, id.Value)
	}
	return result
}

type identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type vulnerability struct {
	Package                packageInfo `json:"package"`
	VulnerableVersionRange string      `json:"vulnerable_version_range"`
	FirstPatchedVersion    string      `json:"first_patched_version"`
}

type packageInfo struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}
