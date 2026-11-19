package nvd

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/git-pkgs/purl"
)

// largeResponse builds an NVD response with count CVEs, each carrying the
// configurations and weaknesses that real responses include but Query ignores.
// NVD returns at most 2,000 CVEs per page.
func largeResponse(tb testing.TB, count int) []byte {
	tb.Helper()
	entries := make([]map[string]any, count)
	for i := range count {
		references := make([]map[string]any, 8)
		for j := range references {
			references[j] = map[string]any{
				"url":    fmt.Sprintf("https://example.com/advisories/%d/%d", i, j),
				"source": "security@example.com",
				"tags":   []string{"Third Party Advisory", "Patch"},
			}
		}
		matches := make([]map[string]any, 12)
		for j := range matches {
			matches[j] = map[string]any{
				"vulnerable":          true,
				"criteria":            fmt.Sprintf("cpe:2.3:a:example:package:1.%d.%d:*:*:*:*:*:*:*", i, j),
				"versionEndExcluding": fmt.Sprintf("1.%d.%d", i, j+1),
				"matchCriteriaId":     fmt.Sprintf("00000000-0000-0000-0000-%012d", i*100+j),
			}
		}
		entries[i] = map[string]any{"cve": map[string]any{
			"id":               fmt.Sprintf("CVE-2026-%05d", i),
			"sourceIdentifier": "security@example.com",
			"published":        "2026-01-02T03:04:05.678",
			"lastModified":     "2026-02-03T04:05:06.789",
			"vulnStatus":       "Analyzed",
			"descriptions": []map[string]string{
				{"lang": "en", "value": fmt.Sprintf("A crafted request to example package %d can execute code on the server through the template engine.", i)},
				{"lang": "es", "value": "Una solicitud manipulada puede ejecutar codigo en el servidor."},
			},
			"metrics": map[string]any{
				"cvssMetricV31": []map[string]any{{"source": "nvd@nist.gov", "type": "Primary", "cvssData": map[string]any{
					"version": "3.1", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "baseScore": 9.8, "baseSeverity": "CRITICAL",
				}}},
				"cvssMetricV2": []map[string]any{{"source": "nvd@nist.gov", "type": "Primary", "cvssData": map[string]any{
					"version": "2.0", "vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P", "baseScore": 7.5,
				}}},
			},
			"weaknesses":     []map[string]any{{"source": "nvd@nist.gov", "type": "Primary", "description": []map[string]string{{"lang": "en", "value": "CWE-94"}}}},
			"configurations": []map[string]any{{"nodes": []map[string]any{{"operator": "OR", "negate": false, "cpeMatch": matches}}}},
			"references":     references,
		}}
	}
	data, err := json.Marshal(map[string]any{
		"resultsPerPage":  count,
		"startIndex":      0,
		"totalResults":    count,
		"format":          "NVD_CVE",
		"version":         "2.0",
		"timestamp":       "2026-11-18T18:00:00.000",
		"vulnerabilities": entries,
	})
	if err != nil {
		tb.Fatal(err)
	}
	return data
}

func TestQueryLargeResponse(t *testing.T) {
	const count = 2000
	p, _ := purl.Parse("pkg:npm/example@1.0.0")
	got, err := newStaticSource(largeResponse(t, count)).Query(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != count {
		t.Fatalf("got %d vulnerabilities, want %d", len(got), count)
	}
	last := got[count-1]
	if last.ID != fmt.Sprintf("CVE-2026-%05d", count-1) || len(last.References) != 8 || len(last.Severity) != 1 || last.Severity[0].Type != "CVSS_V3" {
		t.Fatalf("last = %+v", last)
	}
}

func BenchmarkQueryLargeResponse(b *testing.B) {
	p, _ := purl.Parse("pkg:npm/example@1.0.0")
	src := newStaticSource(largeResponse(b, 2000))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := src.Query(context.Background(), p); err != nil {
			b.Fatal(err)
		}
	}
}
