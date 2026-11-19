package nvd

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/git-pkgs/purl"
	"github.com/git-pkgs/vulns"
)

// staticTransport answers every request with the same JSON body.
type staticTransport struct {
	status int
	body   []byte
}

func (t staticTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: t.status,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(t.body)),
		Request:    req,
	}, nil
}

func newStaticSource(status int, body []byte) *Source {
	return New(WithHTTPClient(&http.Client{Transport: staticTransport{status: status, body: body}}))
}

// fixtureResponse has members before and after "vulnerabilities", unused
// fields inside each CVE, and one entry per CVSS selection branch.
const fixtureResponse = `{
  "resultsPerPage": 4,
  "startIndex": 0,
  "totalResults": 4,
  "format": "NVD_CVE",
  "version": "2.0",
  "timestamp": "2026-11-18T18:20:00.000",
  "vulnerabilities": [
    {"cve": {
      "id": "CVE-2021-44228",
      "sourceIdentifier": "security@apache.org",
      "published": "2021-12-10T10:15:09.143Z",
      "lastModified": "2026-08-11T19:33:44.513Z",
      "vulnStatus": "Analyzed",
      "descriptions": [
        {"lang": "es", "value": "Descripcion"},
        {"lang": "en", "value": "Apache Log4j2 JNDI features"}
      ],
      "metrics": {
        "cvssMetricV31": [
          {"source": "nvd@nist.gov", "type": "Primary", "cvssData": {"version": "3.1", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "baseScore": 10.0, "baseSeverity": "CRITICAL"}},
          {"source": "other", "type": "Secondary", "cvssData": {"version": "3.1", "vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"}}
        ],
        "cvssMetricV30": [{"cvssData": {"version": "3.0", "vectorString": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"}}],
        "cvssMetricV2": [{"cvssData": {"version": "2.0", "vectorString": "AV:N/AC:M/Au:N/C:C/I:C/A:C"}}],
        "ssvcV203": [{"source": "x", "ssvcData": {"options": [{"Exploitation": "active"}]}}]
      },
      "weaknesses": [{"source": "nvd@nist.gov", "description": [{"lang": "en", "value": "CWE-502"}]}],
      "configurations": [{"nodes": [{"operator": "OR", "cpeMatch": [{"vulnerable": true, "criteria": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*"}]}]}],
      "references": [
        {"url": "https://logging.apache.org/log4j/2.x/security.html", "source": "security@apache.org", "tags": ["Vendor Advisory"]},
        {"url": "https://example.com/second", "source": "x"}
      ]
    }},
    {"cve": {
      "id": "CVE-2018-0001",
      "published": "2018-01-10T22:29:00.123Z",
      "descriptions": [{"lang": "en", "value": "v3.0 and v2 only"}],
      "metrics": {
        "cvssMetricV30": [{"cvssData": {"vectorString": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}],
        "cvssMetricV2": [{"cvssData": {"vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P"}}]
      }
    }},
    {"cve": {
      "id": "CVE-2005-0001",
      "descriptions": [{"lang": "en", "value": "v2 only"}],
      "metrics": {"cvssMetricV2": [{"cvssData": {"vectorString": "AV:L/AC:L/Au:N/C:C/I:C/A:C"}}]}
    }},
    {"cve": {
      "id": "CVE-2026-0002",
      "descriptions": [{"lang": "fr", "value": "Pas d'anglais"}],
      "metrics": {}
    }}
  ],
  "trailing": {"nested": [1, 2, {"deep": "value"}]}
}`

func TestQueryDecodesResponse(t *testing.T) {
	p, err := purl.Parse("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1")
	if err != nil {
		t.Fatal(err)
	}

	got, err := newStaticSource(http.StatusOK, []byte(fixtureResponse)).Query(context.Background(), p)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got) != 4 {
		t.Fatalf("got %d vulnerabilities, want 4", len(got))
	}

	first := got[0]
	if first.ID != "CVE-2021-44228" || first.Summary != "Apache Log4j2 JNDI features" {
		t.Errorf("first = %q %q", first.ID, first.Summary)
	}
	if want := time.Date(2021, 12, 10, 10, 15, 9, 143000000, time.UTC); !first.Published.Equal(want) {
		t.Errorf("Published = %v, want %v", first.Published, want)
	}
	if want := time.Date(2026, 8, 11, 19, 33, 44, 513000000, time.UTC); !first.Modified.Equal(want) {
		t.Errorf("Modified = %v, want %v", first.Modified, want)
	}
	wantRefs := []vulns.Reference{
		{Type: "WEB", URL: "https://logging.apache.org/log4j/2.x/security.html"},
		{Type: "WEB", URL: "https://example.com/second"},
	}
	if len(first.References) != len(wantRefs) {
		t.Fatalf("References = %+v", first.References)
	}
	for i := range wantRefs {
		if first.References[i] != wantRefs[i] {
			t.Errorf("References[%d] = %+v, want %+v", i, first.References[i], wantRefs[i])
		}
	}
	if len(first.Affected) != 1 || first.Affected[0].Package.PURL != p.String() || first.Affected[0].Package.Name != p.FullName() {
		t.Errorf("Affected = %+v", first.Affected)
	}

	wantSeverity := []vulns.Severity{
		{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"},
		{Type: "CVSS_V3", Score: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
		{Type: "CVSS_V2", Score: "AV:L/AC:L/Au:N/C:C/I:C/A:C"},
	}
	for i, want := range wantSeverity {
		if len(got[i].Severity) != 1 || got[i].Severity[0] != want {
			t.Errorf("%s Severity = %+v, want [%+v]", got[i].ID, got[i].Severity, want)
		}
	}

	last := got[3]
	if last.Summary != "Pas d'anglais" || len(last.Severity) != 0 || !last.Published.IsZero() {
		t.Errorf("last = %+v", last)
	}
}

func TestQueryEmptyAndNullVulnerabilities(t *testing.T) {
	p, _ := purl.Parse("pkg:npm/left-pad@1.0.0")
	for _, body := range []string{
		`{"resultsPerPage": 0, "totalResults": 0, "vulnerabilities": []}`,
		`{"resultsPerPage": 0, "totalResults": 0, "vulnerabilities": null}`,
		`{"resultsPerPage": 0, "totalResults": 0}`,
	} {
		got, err := newStaticSource(http.StatusOK, []byte(body)).Query(context.Background(), p)
		if err != nil {
			t.Errorf("%s: %v", body, err)
		}
		if got != nil {
			t.Errorf("%s: got %+v, want nil", body, got)
		}
	}
}

func TestQueryMalformedResponse(t *testing.T) {
	p, _ := purl.Parse("pkg:npm/left-pad@1.0.0")
	for _, body := range []string{
		fixtureResponse[:len(fixtureResponse)/2],
		`[]`,
		`{"vulnerabilities": {"cve": {}}}`,
		`{"vulnerabilities": [{"cve": {"id": 7}}]}`,
	} {
		if _, err := newStaticSource(http.StatusOK, []byte(body)).Query(context.Background(), p); err == nil {
			t.Errorf("%.40q: no error", body)
		} else if !strings.Contains(err.Error(), "decoding response") {
			t.Errorf("%.40q: error %q lacks the decoding prefix", body, err)
		}
	}
}

func TestGetReturnsFirstVulnerability(t *testing.T) {
	src := newStaticSource(http.StatusOK, []byte(fixtureResponse))
	got, err := src.Get(context.Background(), "CVE-2021-44228")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got == nil || got.ID != "CVE-2021-44228" || len(got.Affected) != 0 {
		t.Fatalf("Get = %+v", got)
	}

	empty := newStaticSource(http.StatusOK, []byte(`{"vulnerabilities": []}`))
	if got, err := empty.Get(context.Background(), "CVE-2021-44228"); err != nil || got != nil {
		t.Fatalf("Get on empty = %+v, %v", got, err)
	}
}
