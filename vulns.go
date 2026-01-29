// Package vulns provides a unified interface for querying vulnerability data
// from various sources. It uses PURL (Package URL) as the primary identifier
// and OSV (Open Source Vulnerabilities) format as the canonical data model.
package vulns

import (
	"context"
	"time"

	"github.com/git-pkgs/purl"
)

// Source represents a vulnerability data source.
type Source interface {
	// Name returns the name of this source (e.g., "osv", "nvd").
	Name() string

	// Query returns vulnerabilities affecting the package identified by the PURL.
	// If the PURL includes a version, only vulnerabilities affecting that version
	// are returned. If no version is specified, all known vulnerabilities for the
	// package are returned.
	Query(ctx context.Context, p *purl.PURL) ([]Vulnerability, error)

	// QueryBatch queries multiple packages at once. Returns a slice of results
	// in the same order as the input PURLs.
	QueryBatch(ctx context.Context, purls []*purl.PURL) ([][]Vulnerability, error)

	// Get fetches a specific vulnerability by its ID.
	Get(ctx context.Context, id string) (*Vulnerability, error)
}

// Vulnerability represents a security vulnerability in OSV format.
// This is the canonical format used across all sources.
type Vulnerability struct {
	ID               string         `json:"id"`
	Summary          string         `json:"summary,omitempty"`
	Details          string         `json:"details,omitempty"`
	Aliases          []string       `json:"aliases,omitempty"`
	Modified         time.Time      `json:"modified"`
	Published        time.Time      `json:"published"`
	Withdrawn        *time.Time     `json:"withdrawn,omitempty"`
	References       []Reference    `json:"references,omitempty"`
	Affected         []Affected     `json:"affected,omitempty"`
	Severity         []Severity     `json:"severity,omitempty"`
	Credits          []Credit       `json:"credits,omitempty"`
	DatabaseSpecific map[string]any `json:"database_specific,omitempty"`
}

// Reference is a link to more information about a vulnerability.
type Reference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// Affected describes which package versions are affected.
type Affected struct {
	Package           Package        `json:"package"`
	Ranges            []Range        `json:"ranges,omitempty"`
	Versions          []string       `json:"versions,omitempty"`
	EcosystemSpecific map[string]any `json:"ecosystem_specific,omitempty"`
	DatabaseSpecific  map[string]any `json:"database_specific,omitempty"`
}

// Package identifies a package.
type Package struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	PURL      string `json:"purl,omitempty"`
}

// Range describes a version range.
type Range struct {
	Type   string  `json:"type"`
	Events []Event `json:"events,omitempty"`
}

// Event is a version event (introduced, fixed, etc).
type Event struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}

// Severity describes the severity of a vulnerability.
type Severity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// Credit gives credit to vulnerability reporters/fixers.
type Credit struct {
	Name    string   `json:"name"`
	Contact []string `json:"contact,omitempty"`
	Type    string   `json:"type,omitempty"`
}

// SeverityLevel returns a normalized severity level (critical, high, medium, low, unknown).
func (v *Vulnerability) SeverityLevel() string {
	for _, sev := range v.Severity {
		if cvss, err := CVSSFromSeverity(sev); err == nil {
			return cvss.Level
		}
	}

	if v.DatabaseSpecific != nil {
		if severity, ok := v.DatabaseSpecific["severity"].(string); ok {
			switch severity {
			case "CRITICAL", "critical":
				return "critical"
			case "HIGH", "high":
				return "high"
			case "MODERATE", "MEDIUM", "moderate", "medium":
				return "medium"
			case "LOW", "low":
				return "low"
			}
		}
	}

	return "unknown"
}

// CVSSScore returns the highest CVSS score if available, or -1 if not.
func (v *Vulnerability) CVSSScore() float64 {
	var highest float64 = -1
	for _, sev := range v.Severity {
		if cvss, err := CVSSFromSeverity(sev); err == nil && cvss.Score > highest {
			highest = cvss.Score
		}
	}
	return highest
}

// CVSS returns parsed CVSS information from the vulnerability's severity data.
// Returns nil if no CVSS information is available.
func (v *Vulnerability) CVSS() *CVSS {
	for _, sev := range v.Severity {
		if cvss, err := CVSSFromSeverity(sev); err == nil {
			return cvss
		}
	}
	return nil
}

// FixedVersion returns the first fixed version for the given package, if available.
func (v *Vulnerability) FixedVersion(ecosystem, name string) string {
	for _, a := range v.Affected {
		if !matchesPackage(a.Package, ecosystem, name) {
			continue
		}
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if e.Fixed != "" {
					return e.Fixed
				}
			}
		}
	}
	return ""
}

// IsVersionAffected checks if a specific version of a package is affected.
func (v *Vulnerability) IsVersionAffected(ecosystem, name, version string) bool {
	for _, a := range v.Affected {
		if !matchesPackage(a.Package, ecosystem, name) {
			continue
		}
		if isAffectedVersion(a, version) {
			return true
		}
	}
	return false
}

func matchesPackage(pkg Package, ecosystem, name string) bool {
	pkgEco := purl.NormalizeEcosystem(pkg.Ecosystem)
	checkEco := purl.NormalizeEcosystem(ecosystem)
	return pkgEco == checkEco && pkg.Name == name
}

// scanFloat parses a float from the beginning of a string.
// Used internally for parsing bare CVSS scores.
func scanFloat(s string, v *float64) (int, error) {
	var f float64
	n := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= '0' && c <= '9' {
			f = f*10 + float64(c-'0')
			n++
		} else if c == '.' {
			n++
			frac := 0.1
			for i++; i < len(s); i++ {
				c := s[i]
				if c >= '0' && c <= '9' {
					f += float64(c-'0') * frac
					frac /= 10
					n++
				} else {
					break
				}
			}
			break
		} else {
			break
		}
	}
	if n == 0 {
		return 0, &parseError{}
	}
	*v = f
	return n, nil
}

type parseError struct{}

func (e *parseError) Error() string { return "parse error" }
