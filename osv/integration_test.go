package osv

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/git-pkgs/purl"
)

// TestEndToEndVulnerabilityWorkflow tests a complete workflow of querying
// and processing vulnerability data as git-pkgs would use it.
func TestEndToEndVulnerabilityWorkflow(t *testing.T) {
	fixture := loadFixture(t, "query_response.json")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(fixture)
	}))
	defer server.Close()

	source := New(WithBaseURL(server.URL))
	p := purl.MakePURL("npm", "lodash", "4.17.20")

	// Step 1: Query for vulnerabilities
	vulns, err := source.Query(context.Background(), p)
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if len(vulns) == 0 {
		t.Fatal("expected vulnerabilities")
	}

	v := vulns[0]

	// Step 2: Check severity level
	level := v.SeverityLevel()
	if level != "high" {
		t.Errorf("expected severity level 'high', got '%s'", level)
	}

	// Step 3: Get CVSS score
	score := v.CVSSScore()
	if score < 7.0 || score > 8.0 {
		t.Errorf("expected CVSS score around 7.4, got %f", score)
	}

	// Step 4: Get full CVSS details
	cvss := v.CVSS()
	if cvss == nil {
		t.Fatal("expected CVSS details")
	}
	if cvss.Version != "3.1" {
		t.Errorf("expected CVSS version 3.1, got %s", cvss.Version)
	}

	// Step 5: Check if version is affected
	if !v.IsVersionAffected("npm", "lodash", "4.17.18") {
		t.Error("expected version 4.17.18 to be affected")
	}
	if v.IsVersionAffected("npm", "lodash", "4.17.19") {
		t.Error("expected version 4.17.19 to NOT be affected (it's the fix)")
	}
	if v.IsVersionAffected("npm", "lodash", "4.17.20") {
		t.Error("expected version 4.17.20 to NOT be affected")
	}

	// Step 6: Get fixed version
	fixed := v.FixedVersion("npm", "lodash")
	if fixed != "4.17.19" {
		t.Errorf("expected fixed version '4.17.19', got '%s'", fixed)
	}

	// Step 7: Check aliases (CVE)
	if len(v.Aliases) == 0 || v.Aliases[0] != "CVE-2020-8203" {
		t.Errorf("expected alias CVE-2020-8203, got %v", v.Aliases)
	}

	// Step 8: Check references
	if len(v.References) == 0 {
		t.Error("expected references")
	}
}

// TestBatchQueryWorkflow tests batch querying multiple packages
func TestBatchQueryWorkflow(t *testing.T) {
	fixture := loadFixture(t, "batch_query_response.json")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(fixture)
	}))
	defer server.Close()

	source := New(WithBaseURL(server.URL))

	// Query multiple packages at once
	purls := []*purl.PURL{
		purl.MakePURL("npm", "lodash", "4.17.20"),
		purl.MakePURL("npm", "express", "4.17.1"),
	}

	results, err := source.QueryBatch(context.Background(), purls)
	if err != nil {
		t.Fatalf("QueryBatch failed: %v", err)
	}

	// Check results match input order
	if len(results) != len(purls) {
		t.Fatalf("expected %d results, got %d", len(purls), len(results))
	}

	// lodash has vulnerabilities
	if len(results[0]) == 0 {
		t.Error("expected vulnerabilities for lodash")
	}

	// express has no vulnerabilities in this fixture
	if len(results[1]) != 0 {
		t.Errorf("expected no vulnerabilities for express, got %d", len(results[1]))
	}

	// Verify we can process each result
	for i, vulnList := range results {
		for _, v := range vulnList {
			// These shouldn't panic
			_ = v.SeverityLevel()
			_ = v.CVSSScore()
			_ = v.CVSS()
			_ = v.FixedVersion(purls[i].Type, purls[i].FullName())
		}
	}
}

// TestErrorHandling tests various error conditions
func TestErrorHandling(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       string
		wantErr    bool
	}{
		{
			name:       "server error",
			statusCode: 500,
			body:       "internal server error",
			wantErr:    true,
		},
		{
			name:       "invalid json",
			statusCode: 200,
			body:       "not json",
			wantErr:    true,
		},
		{
			name:       "empty response",
			statusCode: 200,
			body:       "{}",
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer server.Close()

			source := New(WithBaseURL(server.URL))
			p := purl.MakePURL("npm", "test", "1.0.0")

			_, err := source.Query(context.Background(), p)
			if tt.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// TestMultipleAffectedPackages tests vulnerabilities affecting multiple packages
func TestMultipleAffectedPackages(t *testing.T) {
	response := `{
		"vulns": [{
			"id": "TEST-001",
			"summary": "Test vulnerability",
			"affected": [
				{
					"package": {"ecosystem": "npm", "name": "pkg-a"},
					"ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]
				},
				{
					"package": {"ecosystem": "npm", "name": "pkg-b"},
					"ranges": [{"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "1.5.0"}]}]
				}
			]
		}]
	}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(response))
	}))
	defer server.Close()

	source := New(WithBaseURL(server.URL))
	p := purl.MakePURL("npm", "pkg-a", "1.0.0")

	vulns, err := source.Query(context.Background(), p)
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}

	v := vulns[0]

	// Check pkg-a version matching
	if !v.IsVersionAffected("npm", "pkg-a", "1.0.0") {
		t.Error("pkg-a@1.0.0 should be affected")
	}
	if v.IsVersionAffected("npm", "pkg-a", "2.0.0") {
		t.Error("pkg-a@2.0.0 should NOT be affected")
	}

	// Check pkg-b version matching
	if !v.IsVersionAffected("npm", "pkg-b", "1.2.0") {
		t.Error("pkg-b@1.2.0 should be affected")
	}
	if v.IsVersionAffected("npm", "pkg-b", "0.9.0") {
		t.Error("pkg-b@0.9.0 should NOT be affected (before introduced)")
	}
	if v.IsVersionAffected("npm", "pkg-b", "1.5.0") {
		t.Error("pkg-b@1.5.0 should NOT be affected (fixed)")
	}

	// Check fixed versions for each package
	if fixed := v.FixedVersion("npm", "pkg-a"); fixed != "2.0.0" {
		t.Errorf("expected pkg-a fixed version 2.0.0, got %s", fixed)
	}
	if fixed := v.FixedVersion("npm", "pkg-b"); fixed != "1.5.0" {
		t.Errorf("expected pkg-b fixed version 1.5.0, got %s", fixed)
	}
}
