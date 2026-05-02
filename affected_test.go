package vulns

import (
	"testing"
)

func TestAffectedVersionRange(t *testing.T) {
	tests := []struct {
		name     string
		affected Affected
		want     string
	}{
		{
			name: "single range",
			affected: Affected{
				Ranges: []Range{{
					Type: "ECOSYSTEM",
					Events: []Event{
						{Introduced: "1.0.0"},
						{Fixed: "1.5.0"},
					},
				}},
			},
			want: ">=1.0.0|<1.5.0",
		},
		{
			name: "multiple intervals",
			affected: Affected{
				Ranges: []Range{{
					Type: "ECOSYSTEM",
					Events: []Event{
						{Introduced: "1.0.0"},
						{Fixed: "1.5.0"},
						{Introduced: "2.0.0"},
						{Fixed: "2.5.0"},
					},
				}},
			},
			want: ">=1.0.0|<1.5.0|>=2.0.0|<2.5.0",
		},
		{
			name: "introduced at zero with fix",
			affected: Affected{
				Ranges: []Range{{
					Type: "ECOSYSTEM",
					Events: []Event{
						{Introduced: "0"},
						{Fixed: "1.2.0"},
					},
				}},
			},
			want: "<1.2.0",
		},
		{
			name: "introduced at zero no fix",
			affected: Affected{
				Ranges: []Range{{
					Type: "ECOSYSTEM",
					Events: []Event{
						{Introduced: "0"},
					},
				}},
			},
			want: "*",
		},
		{
			name: "trailing introduced no fix",
			affected: Affected{
				Ranges: []Range{{
					Type: "ECOSYSTEM",
					Events: []Event{
						{Introduced: "1.0.0"},
						{Fixed: "1.5.0"},
						{Introduced: "2.0.0"},
					},
				}},
			},
			want: ">=1.0.0|<1.5.0|>=2.0.0",
		},
		{
			name: "last affected",
			affected: Affected{
				Ranges: []Range{{
					Type: "ECOSYSTEM",
					Events: []Event{
						{Introduced: "1.0.0"},
						{LastAffected: "1.9.0"},
					},
				}},
			},
			want: ">=1.0.0|<=1.9.0",
		},
		{
			name: "explicit versions",
			affected: Affected{
				Versions: []string{"1.0.0", "1.1.0", "1.2.0"},
			},
			want: "=1.0.0|=1.1.0|=1.2.0",
		},
		{
			name: "empty",
			affected: Affected{},
			want:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := AffectedVersionRange(tt.affected)
			if got != tt.want {
				t.Errorf("AffectedVersionRange() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestVersionInRangeMultiInterval(t *testing.T) {
	events := []Event{
		{Introduced: "0"},
		{Fixed: "1.0.0"},
		{Introduced: "2.0.0"},
		{Fixed: "3.0.0"},
	}

	tests := []struct {
		version string
		want    bool
	}{
		{"0.5.0", true},
		{"1.0.0", false},
		{"1.5.0", false},
		{"2.0.0", true},
		{"2.5.0", true},
		{"3.0.0", false},
		{"4.0.0", false},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			got := versionInRange(events, tt.version)
			if got != tt.want {
				t.Errorf("versionInRange(%q) = %v, want %v", tt.version, got, tt.want)
			}
		})
	}
}

func TestVersionInRangeMultiIntervalLastAffected(t *testing.T) {
	events := []Event{
		{Introduced: "1.0.0"},
		{LastAffected: "1.9.0"},
		{Introduced: "3.0.0"},
		{LastAffected: "3.9.0"},
	}

	tests := []struct {
		version string
		want    bool
	}{
		{"0.5.0", false},
		{"1.0.0", true},
		{"1.5.0", true},
		{"1.9.0", true},
		{"2.0.0", false},
		{"3.0.0", true},
		{"3.9.0", true},
		{"4.0.0", false},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			got := versionInRange(events, tt.version)
			if got != tt.want {
				t.Errorf("versionInRange(%q) = %v, want %v", tt.version, got, tt.want)
			}
		})
	}
}
