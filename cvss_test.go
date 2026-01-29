package vulns

import (
	"testing"
)

func TestParseCVSS(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantVer   string
		wantScore float64
		wantLevel string
		wantErr   bool
	}{
		{
			name:      "cvss v2.0 vector",
			input:     "AV:N/AC:L/Au:N/C:P/I:P/A:P",
			wantVer:   "2.0",
			wantScore: 7.5,
			wantLevel: "high",
		},
		{
			name:      "cvss v3.0 vector",
			input:     "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
			wantVer:   "3.0",
			wantScore: 7.5,
			wantLevel: "high",
		},
		{
			name:      "cvss v3.1 vector",
			input:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
			wantVer:   "3.1",
			wantScore: 7.5,
			wantLevel: "high",
		},
		{
			name:      "cvss v3.1 critical",
			input:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
			wantVer:   "3.1",
			wantScore: 10.0,
			wantLevel: "critical",
		},
		{
			name:      "cvss v4.0 vector",
			input:     "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
			wantVer:   "4.0",
			wantScore: 9.3,
			wantLevel: "critical",
		},
		{
			name:      "bare score",
			input:     "7.5",
			wantScore: 7.5,
			wantLevel: "high",
		},
		{
			name:      "bare score critical",
			input:     "9.8",
			wantScore: 9.8,
			wantLevel: "critical",
		},
		{
			name:      "bare score low",
			input:     "2.1",
			wantScore: 2.1,
			wantLevel: "low",
		},
		{
			name:    "invalid input",
			input:   "not a cvss",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseCVSS(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseCVSS(%q) expected error, got nil", tt.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseCVSS(%q) unexpected error: %v", tt.input, err)
			}
			if tt.wantVer != "" && got.Version != tt.wantVer {
				t.Errorf("Version = %q, want %q", got.Version, tt.wantVer)
			}
			if got.Score != tt.wantScore {
				t.Errorf("Score = %v, want %v", got.Score, tt.wantScore)
			}
			if got.Level != tt.wantLevel {
				t.Errorf("Level = %q, want %q", got.Level, tt.wantLevel)
			}
		})
	}
}

func TestCVSSFromSeverity(t *testing.T) {
	tests := []struct {
		name      string
		sev       Severity
		wantScore float64
		wantErr   bool
	}{
		{
			name:      "cvss v3 bare score",
			sev:       Severity{Type: "CVSS_V3", Score: "8.5"},
			wantScore: 8.5,
		},
		{
			name:      "cvss v3 vector",
			sev:       Severity{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
			wantScore: 7.5,
		},
		{
			name:      "cvss v2",
			sev:       Severity{Type: "CVSS_V2", Score: "AV:N/AC:L/Au:N/C:P/I:P/A:P"},
			wantScore: 7.5,
		},
		{
			name:    "ghsa severity string",
			sev:     Severity{Type: "GHSA", Score: "HIGH"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CVSSFromSeverity(tt.sev)
			if tt.wantErr {
				if err == nil {
					t.Errorf("CVSSFromSeverity expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("CVSSFromSeverity unexpected error: %v", err)
			}
			if got.Score != tt.wantScore {
				t.Errorf("Score = %v, want %v", got.Score, tt.wantScore)
			}
		})
	}
}
