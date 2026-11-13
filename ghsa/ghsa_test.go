package ghsa

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/git-pkgs/purl"
)

func TestQueryFiltersByAffects(t *testing.T) {
	tests := []struct {
		purl          string
		wantEcosystem string
		wantAffects   string
	}{
		{"pkg:npm/lodash@4.17.20", "npm", "lodash@4.17.20"},
		{"pkg:npm/lodash", "npm", "lodash"},
		{"pkg:npm/%40babel/traverse@7.0.0", "npm", "@babel/traverse@7.0.0"},
		{"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "maven", "org.apache.logging.log4j:log4j-core@2.14.1"},
		{"pkg:golang/github.com/Masterminds/goutils@1.1.0", "go", "github.com/Masterminds/goutils@1.1.0"},
		{"pkg:swift/github.com/apple/swift-nio@2.0.0", "swift", "github.com/apple/swift-nio@2.0.0"},
	}

	for _, tt := range tests {
		t.Run(tt.purl, func(t *testing.T) {
			var got url.Values
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got = r.URL.Query()
				_, _ = w.Write([]byte(`[{
					"ghsa_id": "GHSA-xxxx-xxxx-xxxx",
					"identifiers": [
						{"type": "GHSA", "value": "GHSA-xxxx-xxxx-xxxx"},
						{"type": "CVE", "value": "CVE-2020-0001"}
					]
				}]`))
			}))
			defer server.Close()

			p, err := purl.Parse(tt.purl)
			if err != nil {
				t.Fatal(err)
			}
			results, err := New(WithBaseURL(server.URL)).Query(context.Background(), p)
			if err != nil {
				t.Fatal(err)
			}
			if len(results) != 1 || results[0].ID != "GHSA-xxxx-xxxx-xxxx" {
				t.Fatalf("results = %+v, want one advisory", results)
			}
			if aliases := results[0].Aliases; len(aliases) != 1 || aliases[0] != "CVE-2020-0001" {
				t.Errorf("aliases = %v, want [CVE-2020-0001]", aliases)
			}
			if got.Get("ecosystem") != tt.wantEcosystem {
				t.Errorf("ecosystem = %q, want %q", got.Get("ecosystem"), tt.wantEcosystem)
			}
			if got.Get("affects") != tt.wantAffects {
				t.Errorf("affects = %q, want %q", got.Get("affects"), tt.wantAffects)
			}
			if got.Has("package") {
				t.Errorf("sent package=%q, which the advisories API ignores", got.Get("package"))
			}
		})
	}
}

func TestQueryFollowsPagination(t *testing.T) {
	var afters []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		after := r.URL.Query().Get("after")
		afters = append(afters, after)
		if r.URL.Query().Get("affects") != "tensorflow" {
			t.Errorf("affects = %q on page after=%q", r.URL.Query().Get("affects"), after)
		}
		switch after {
		case "":
			next := "http://" + r.Host + "/advisories?ecosystem=pip&affects=tensorflow&per_page=100&after=cursor1"
			w.Header().Set("Link", "<"+next+`>; rel="next"`)
			_, _ = w.Write([]byte(`[{"ghsa_id":"GHSA-aaaa-aaaa-aaaa"}]`))
		case "cursor1":
			prev := "http://" + r.Host + "/advisories?before=cursor1"
			w.Header().Set("Link", "<"+prev+`>; rel="prev"`)
			_, _ = w.Write([]byte(`[{"ghsa_id":"GHSA-bbbb-bbbb-bbbb"}]`))
		default:
			t.Errorf("unexpected page after=%q", after)
		}
	}))
	defer server.Close()

	p, err := purl.Parse("pkg:pypi/tensorflow")
	if err != nil {
		t.Fatal(err)
	}
	results, err := New(WithBaseURL(server.URL)).Query(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 || results[0].ID != "GHSA-aaaa-aaaa-aaaa" || results[1].ID != "GHSA-bbbb-bbbb-bbbb" {
		t.Errorf("results = %+v, want both pages in order", results)
	}
	if len(afters) != 2 {
		t.Errorf("requests = %q, want 2", afters)
	}
}

func TestQueryStopsAtMaxPages(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Link", "<http://"+r.Host+`/advisories?after=again>; rel="next"`)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer server.Close()

	p, err := purl.Parse("pkg:pypi/tensorflow")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(WithBaseURL(server.URL)).Query(context.Background(), p); err == nil {
		t.Error("Query err = nil, want page limit error")
	}
	if requests != maxPages {
		t.Errorf("requests = %d, want %d", requests, maxPages)
	}
}

func TestSwiftRegistryIdentityRejected(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		_, _ = w.Write([]byte(`[]`))
	}))
	defer server.Close()
	source := New(WithBaseURL(server.URL))

	registry, err := purl.Parse("pkg:swift/apple/swift-nio@2.0.0")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := source.Query(context.Background(), registry); !errors.Is(err, ErrUnsupportedIdentity) {
		t.Errorf("Query err = %v, want ErrUnsupportedIdentity", err)
	}
	if _, err := source.QueryBatch(context.Background(), []*purl.PURL{registry}); !errors.Is(err, ErrUnsupportedIdentity) {
		t.Errorf("QueryBatch err = %v, want ErrUnsupportedIdentity", err)
	}
	if requests != 0 {
		t.Fatalf("unsupported identities reached GHSA: %d requests", requests)
	}
}

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
