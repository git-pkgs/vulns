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
