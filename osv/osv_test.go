package osv

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/git-pkgs/purl"
)

func TestQuery(t *testing.T) {
	fixture := loadFixture(t, "query_response.json")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/query" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Method != "POST" {
			t.Errorf("unexpected method: %s", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(fixture)
	}))
	defer server.Close()

	source := New(WithBaseURL(server.URL))
	p := purl.MakePURL("npm", "lodash", "4.17.20")

	vulns, err := source.Query(context.Background(), p)
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}

	if len(vulns) != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", len(vulns))
	}

	v := vulns[0]
	if v.ID != "GHSA-jf85-cpcp-j695" {
		t.Errorf("unexpected ID: %s", v.ID)
	}
	if v.Summary != "Prototype Pollution in lodash" {
		t.Errorf("unexpected summary: %s", v.Summary)
	}
	if len(v.Aliases) != 1 || v.Aliases[0] != "CVE-2020-8203" {
		t.Errorf("unexpected aliases: %v", v.Aliases)
	}
	if len(v.Affected) != 1 {
		t.Errorf("expected 1 affected, got %d", len(v.Affected))
	}
	if v.Affected[0].Package.Name != "lodash" {
		t.Errorf("unexpected package name: %s", v.Affected[0].Package.Name)
	}
}

func TestQueryBatch(t *testing.T) {
	fixture := loadFixture(t, "batch_query_response.json")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/querybatch" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(fixture)
	}))
	defer server.Close()

	source := New(WithBaseURL(server.URL))
	purls := []*purl.PURL{
		purl.MakePURL("npm", "lodash", "4.17.20"),
		purl.MakePURL("npm", "express", "4.17.1"),
	}

	results, err := source.QueryBatch(context.Background(), purls)
	if err != nil {
		t.Fatalf("QueryBatch failed: %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	// First package has 1 vulnerability
	if len(results[0]) != 1 {
		t.Errorf("expected 1 vulnerability for lodash, got %d", len(results[0]))
	}

	// Second package has no vulnerabilities
	if len(results[1]) != 0 {
		t.Errorf("expected 0 vulnerabilities for express, got %d", len(results[1]))
	}
}

func TestGet(t *testing.T) {
	fixture := loadFixture(t, "get_vulnerability_response.json")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/vulns/GHSA-jf85-cpcp-j695" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Method != "GET" {
			t.Errorf("unexpected method: %s", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(fixture)
	}))
	defer server.Close()

	source := New(WithBaseURL(server.URL))

	v, err := source.Get(context.Background(), "GHSA-jf85-cpcp-j695")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if v == nil {
		t.Fatal("expected vulnerability, got nil")
	}
	if v.ID != "GHSA-jf85-cpcp-j695" {
		t.Errorf("unexpected ID: %s", v.ID)
	}
}

func TestGetNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	source := New(WithBaseURL(server.URL))

	v, err := source.Get(context.Background(), "NONEXISTENT")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if v != nil {
		t.Errorf("expected nil, got %v", v)
	}
}

func TestQueryNoVulnerabilities(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"vulns": []}`))
	}))
	defer server.Close()

	source := New(WithBaseURL(server.URL))
	p := purl.MakePURL("npm", "safe-package", "1.0.0")

	vulns, err := source.Query(context.Background(), p)
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}

	if len(vulns) != 0 {
		t.Errorf("expected 0 vulnerabilities, got %d", len(vulns))
	}
}

func TestName(t *testing.T) {
	source := New()
	if source.Name() != "osv" {
		t.Errorf("unexpected name: %s", source.Name())
	}
}

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	path := filepath.Join("testdata", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to load fixture %s: %v", name, err)
	}
	return data
}
