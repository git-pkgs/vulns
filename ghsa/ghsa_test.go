package ghsa

import "testing"

func TestGHSAToOSVEcosystem(t *testing.T) {
	tests := []struct {
		name      string
		ecosystem string
		want      string
	}{
		{
			name:      "swift uses the OSV schema ecosystem name",
			ecosystem: ecoSwift,
			want:      "SwiftURL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ghsaToOSVEcosystem(tt.ecosystem); got != tt.want {
				t.Errorf("ghsaToOSVEcosystem(%q) = %q, want %q", tt.ecosystem, got, tt.want)
			}
		})
	}
}
