package vulns

import (
	"testing"
	"time"
)

func TestVulnerabilitySeverityLevel(t *testing.T) {
	tests := []struct {
		name     string
		vuln     Vulnerability
		expected string
	}{
		{
			name: "critical from cvss v3 score",
			vuln: Vulnerability{
				Severity: []Severity{{Type: "CVSS_V3", Score: "9.8"}},
			},
			expected: "critical",
		},
		{
			name: "high from cvss v3 vector",
			vuln: Vulnerability{
				Severity: []Severity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}},
			},
			expected: "high",
		},
		{
			name: "medium from database_specific",
			vuln: Vulnerability{
				DatabaseSpecific: map[string]any{"severity": "MODERATE"},
			},
			expected: "medium",
		},
		{
			name: "unknown when no severity info",
			vuln: Vulnerability{},
			expected: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.vuln.SeverityLevel()
			if got != tt.expected {
				t.Errorf("SeverityLevel() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestVulnerabilityCVSSScore(t *testing.T) {
	tests := []struct {
		name     string
		vuln     Vulnerability
		expected float64
	}{
		{
			name: "parses bare score",
			vuln: Vulnerability{
				Severity: []Severity{{Type: "CVSS_V3", Score: "7.5"}},
			},
			expected: 7.5,
		},
		{
			name: "parses v3.1 vector",
			vuln: Vulnerability{
				Severity: []Severity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}},
			},
			expected: 7.5,
		},
		{
			name: "returns -1 when no cvss",
			vuln: Vulnerability{},
			expected: -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.vuln.CVSSScore()
			if got != tt.expected {
				t.Errorf("CVSSScore() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestVulnerabilityFixedVersion(t *testing.T) {
	vuln := Vulnerability{
		Affected: []Affected{
			{
				Package: Package{Ecosystem: "npm", Name: "lodash"},
				Ranges: []Range{
					{
						Type: "ECOSYSTEM",
						Events: []Event{
							{Introduced: "0"},
							{Fixed: "4.17.21"},
						},
					},
				},
			},
		},
	}

	got := vuln.FixedVersion("npm", "lodash")
	if got != "4.17.21" {
		t.Errorf("FixedVersion() = %q, want %q", got, "4.17.21")
	}

	got = vuln.FixedVersion("npm", "other")
	if got != "" {
		t.Errorf("FixedVersion() for different package = %q, want empty", got)
	}
}

func TestVulnerabilityIsVersionAffected(t *testing.T) {
	vuln := Vulnerability{
		Affected: []Affected{
			{
				Package: Package{Ecosystem: "npm", Name: "lodash"},
				Ranges: []Range{
					{
						Type: "SEMVER",
						Events: []Event{
							{Introduced: "4.0.0"},
							{Fixed: "4.17.21"},
						},
					},
				},
			},
		},
	}

	tests := []struct {
		version  string
		expected bool
	}{
		{"4.17.20", true},
		{"4.17.21", false},
		{"4.0.0", true},
		{"3.9.0", false},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			got := vuln.IsVersionAffected("npm", "lodash", tt.version)
			if got != tt.expected {
				t.Errorf("IsVersionAffected(%q) = %v, want %v", tt.version, got, tt.expected)
			}
		})
	}
}

func TestVulnerabilityCVSS(t *testing.T) {
	vuln := Vulnerability{
		Severity: []Severity{
			{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"},
		},
	}

	cvss := vuln.CVSS()
	if cvss == nil {
		t.Fatal("CVSS() returned nil")
	}
	if cvss.Version != "3.1" {
		t.Errorf("CVSS().Version = %q, want %q", cvss.Version, "3.1")
	}
	if cvss.Score != 10.0 {
		t.Errorf("CVSS().Score = %v, want %v", cvss.Score, 10.0)
	}
	if cvss.Level != "critical" {
		t.Errorf("CVSS().Level = %q, want %q", cvss.Level, "critical")
	}
}

func TestVulnerabilityJSONSerialization(t *testing.T) {
	vuln := Vulnerability{
		ID:        "CVE-2021-12345",
		Summary:   "Test vulnerability",
		Published: time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC),
		Severity:  []Severity{{Type: "CVSS_V3", Score: "7.5"}},
		Affected: []Affected{
			{
				Package: Package{Ecosystem: "npm", Name: "test-pkg"},
			},
		},
	}

	if vuln.ID != "CVE-2021-12345" {
		t.Errorf("unexpected ID: %s", vuln.ID)
	}
}
