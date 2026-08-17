package from_vulns

import (
	"testing"

	"github.com/git-pkgs/purl"
)

// TestMakePURLNPM mirrors osv/osv_test.go:30
//
//	p := purl.MakePURL("npm", "lodash", "4.17.20")
//
// and the field reads the target performs on the resulting *purl.PURL:
//
//	p.Type      vl/vl.go:222 (switch case "npm"), ghsa/ghsa.go:80, grypedb/grypedb.go:233
//	p.Namespace nvd/nvd.go:81 (compared to ""), vl/vl.go:225
//	p.Name      nvd/nvd.go:80, vl/vl.go:226
//	p.Version   osv/osv.go:77, ghsa/ghsa.go:89 (compared to "")
func TestMakePURLNPM(t *testing.T) {
	p := purl.MakePURL("npm", "lodash", "4.17.20")
	if p == nil {
		t.Fatalf(`MakePURL("npm", "lodash", "4.17.20") returned nil`)
	}
	if p.Type != "npm" {
		t.Errorf("p.Type = %q, want %q", p.Type, "npm")
	}
	if p.Namespace != "" {
		t.Errorf("p.Namespace = %q, want %q", p.Namespace, "")
	}
	if p.Name != "lodash" {
		t.Errorf("p.Name = %q, want %q", p.Name, "lodash")
	}
	if p.Version != "4.17.20" {
		t.Errorf("p.Version = %q, want %q", p.Version, "4.17.20")
	}
}

// TestMakePURLSlice mirrors osv/osv_test.go:72-74
//
//	purls := []*purl.PURL{
//	    purl.MakePURL("npm", "lodash", "4.17.20"),
//	    purl.MakePURL("npm", "express", "4.17.1"),
//	}
//
// and the range at osv/osv.go:122 plus indexed access at
// osv/integration_test.go:131 (purls[i].Type, purls[i].FullName()).
func TestMakePURLSlice(t *testing.T) {
	purls := []*purl.PURL{
		purl.MakePURL("npm", "lodash", "4.17.20"),
		purl.MakePURL("npm", "express", "4.17.1"),
	}
	if len(purls) != 2 {
		t.Fatalf("len(purls) = %d, want 2", len(purls))
	}
	wantNames := []string{"lodash", "express"}
	wantVersions := []string{"4.17.20", "4.17.1"}
	for i, p := range purls {
		if p == nil {
			t.Fatalf("purls[%d] is nil", i)
		}
		if p.Type != "npm" {
			t.Errorf("purls[%d].Type = %q, want %q", i, p.Type, "npm")
		}
		if p.Name != wantNames[i] {
			t.Errorf("purls[%d].Name = %q, want %q", i, p.Name, wantNames[i])
		}
		if p.Version != wantVersions[i] {
			t.Errorf("purls[%d].Version = %q, want %q", i, p.Version, wantVersions[i])
		}
	}
}

// TestPURLString mirrors depsdev/depsdev.go:72 and vulncheck/vulncheck.go:78
// where p.String() is escaped into a request URL, and grypedb/grypedb.go:307,
// nvd/nvd.go:266, vl/vl.go:206, vulncheck/vulncheck.go:177 where it is stored
// in vulns.Package.PURL.
func TestPURLString(t *testing.T) {
	p := purl.MakePURL("npm", "lodash", "4.17.20")
	if p == nil {
		t.Fatalf("MakePURL returned nil")
	}
	got := p.String()
	want := "pkg:npm/lodash@4.17.20"
	if got != want {
		t.Errorf("p.String() = %q, want %q", got, want)
	}
}

// TestPURLFullName mirrors osv/osv.go:74
//
//	name := p.FullName()
//
// which is sent to the OSV API as the package name, and
// osv/integration_test.go:131 which passes it to Vulnerability.FixedVersion.
func TestPURLFullName(t *testing.T) {
	p := purl.MakePURL("npm", "lodash", "4.17.20")
	if p == nil {
		t.Fatalf("MakePURL returned nil")
	}
	got := p.FullName()
	want := "lodash"
	if got != want {
		t.Errorf("p.FullName() = %q, want %q", got, want)
	}
}

// TestEcosystemToOSV mirrors osv/osv.go:73
//
//	ecosystem := purl.EcosystemToOSV(p.Type)
//
// where p.Type is "npm" via MakePURL("npm", ...) at osv/osv_test.go:30. The
// result is placed in the OSV /query request body which requires the
// literal "npm" for that ecosystem.
func TestEcosystemToOSV(t *testing.T) {
	p := purl.MakePURL("npm", "lodash", "4.17.20")
	if p == nil {
		t.Fatalf("MakePURL returned nil")
	}
	got := purl.EcosystemToOSV(p.Type)
	want := "npm"
	if got != want {
		t.Errorf("EcosystemToOSV(%q) = %q, want %q", p.Type, got, want)
	}
}

// TestNormalizeEcosystem mirrors vulns.go:180-182
//
//	pkgEco := purl.NormalizeEcosystem(pkg.Ecosystem)
//	checkEco := purl.NormalizeEcosystem(ecosystem)
//	return pkgEco == checkEco && pkg.Name == name
//
// where pkg.Ecosystem is "npm" (vulns_test.go:94) and ecosystem is "npm"
// (vulns_test.go:108, osv/integration_test.go:131 via purls[i].Type).
func TestNormalizeEcosystem(t *testing.T) {
	pkgEco := purl.NormalizeEcosystem("npm")
	checkEco := purl.NormalizeEcosystem("npm")
	if pkgEco != checkEco {
		t.Fatalf(`NormalizeEcosystem("npm") not stable across calls: %q vs %q`, pkgEco, checkEco)
	}
	if pkgEco != "npm" {
		t.Errorf(`NormalizeEcosystem("npm") = %q, want %q`, pkgEco, "npm")
	}
}
