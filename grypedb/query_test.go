package grypedb

import (
	"context"
	"database/sql"
	"path/filepath"
	"slices"
	"testing"

	"github.com/git-pkgs/purl"
)

// newFixtureDB writes a minimal v6 database: openssl for deb and rpm, each
// linked to different advisories under different releases.
func newFixtureDB(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vulnerability.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	for _, stmt := range []string{
		`CREATE TABLE db_metadata (model INTEGER)`,
		`INSERT INTO db_metadata VALUES (6)`,
		`CREATE TABLE blobs (id INTEGER PRIMARY KEY, value TEXT)`,
		`CREATE TABLE packages (id INTEGER PRIMARY KEY, ecosystem TEXT, name TEXT)`,
		`CREATE TABLE vulnerability_handles (id INTEGER PRIMARY KEY, name TEXT, blob_id INTEGER,
			published_date DATETIME, modified_date DATETIME)`,
		`CREATE TABLE operating_systems (id INTEGER PRIMARY KEY, name TEXT, release_id TEXT,
			major_version TEXT, minor_version TEXT, label_version TEXT, codename TEXT, channel TEXT)`,
		`CREATE TABLE affected_package_handles (id INTEGER PRIMARY KEY, vulnerability_id INTEGER,
			operating_system_id INTEGER, package_id INTEGER, blob_id INTEGER)`,
		`CREATE TABLE operating_system_specifier_overrides (alias TEXT, version TEXT, version_pattern TEXT,
			codename TEXT, channel TEXT, replacement TEXT, replacement_major_version TEXT,
			replacement_minor_version TEXT, replacement_label_version TEXT, replacement_channel TEXT,
			rolling NUMERIC, applicable_client_db_schemas TEXT)`,
		`INSERT INTO packages VALUES (1, 'deb', 'openssl'), (2, 'rpm', 'openssl')`,
		`INSERT INTO operating_systems VALUES
			(1, 'debian', 'debian', '12', '', '', 'bookworm', ''),
			(2, 'debian', 'debian', '11', '', '', 'bullseye', ''),
			(3, 'ubuntu', 'ubuntu', '22', '4', '', 'jammy', ''),
			(4, 'redhat', 'rhel', '9', '', '', '', ''),
			(5, 'redhat', 'rhel', '9', '0', '', '', 'eus')`,
		`INSERT INTO vulnerability_handles (id, name, blob_id) VALUES
			(1, 'DEBIAN-12-ONLY', 1), (2, 'DEBIAN-11-ONLY', 2), (3, 'UBUNTU-22.04-ONLY', 3),
			(4, 'RHEL-9', 4), (5, 'RHEL-9.0-EUS', 5)`,
		`INSERT INTO affected_package_handles (vulnerability_id, operating_system_id, package_id, blob_id) VALUES
			(1, 1, 1, 1), (2, 2, 1, 2), (3, 3, 1, 3), (4, 4, 2, 4), (5, 5, 2, 5)`,
		`INSERT INTO operating_system_specifier_overrides (alias, version, version_pattern, codename, replacement,
			rolling, applicable_client_db_schemas) VALUES
			('rocky', '', '', '', 'rhel', 0, ''),
			('debian', '', '', '', 'ubuntu', 0, '< 6.0.3')`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	return path
}

func TestQueryFiltersOSPackagesByDistro(t *testing.T) {
	s, err := New(newFixtureDB(t))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()

	tests := []struct {
		purl string
		want []string
	}{
		{"pkg:deb/debian/openssl@3.0.11-1?distro=debian-12", []string{"DEBIAN-12-ONLY"}},
		{"pkg:deb/debian/openssl@3.0.11-1?distro=bookworm", []string{"DEBIAN-12-ONLY"}},
		{"pkg:deb/debian/openssl@3.0.11-1", []string{"DEBIAN-11-ONLY", "DEBIAN-12-ONLY"}},
		{"pkg:deb/ubuntu/openssl@3.0.2?distro=ubuntu-22.04", []string{"UBUNTU-22.04-ONLY"}},
		{"pkg:deb/ubuntu/openssl@3.0.2?distro=ubuntu-v22.04", []string{"UBUNTU-22.04-ONLY"}},
		{"pkg:deb/openssl@3.0.11-1", []string{"DEBIAN-11-ONLY", "DEBIAN-12-ONLY", "UBUNTU-22.04-ONLY"}},
		{"pkg:deb/debian/openssl@3.0.11-1?distro=debian-99", nil},
		{"pkg:rpm/redhat/openssl@3.0.7-1?distro=rhel-9", []string{"RHEL-9"}},
		{"pkg:rpm/rocky/openssl@3.0.7-1?distro=rocky-9", []string{"RHEL-9"}},
		{"pkg:rpm/redhat/openssl@3.0.7-1?distro=rhel-9.0+eus", []string{"RHEL-9"}},
	}
	for _, tt := range tests {
		t.Run(tt.purl, func(t *testing.T) {
			p, err := purl.Parse(tt.purl)
			if err != nil {
				t.Fatal(err)
			}
			got, err := s.Query(context.Background(), p)
			if err != nil {
				t.Fatal(err)
			}
			var ids []string
			for _, v := range got {
				ids = append(ids, v.ID)
			}
			slices.Sort(ids)
			if !slices.Equal(ids, tt.want) {
				t.Errorf("got %v, want %v", ids, tt.want)
			}
		})
	}
}

func TestOSSpecifierFromPURL(t *testing.T) {
	tests := []struct {
		purl string
		want *osSpecifier
	}{
		{"pkg:deb/debian/openssl?distro=debian-12", &osSpecifier{name: "debian", major: "12"}},
		{"pkg:deb/ubuntu/openssl?distro=ubuntu-22.04", &osSpecifier{name: "ubuntu", major: "22", minor: "4"}},
		{"pkg:rpm/redhat/openssl?distro=rhel-9.2.1", &osSpecifier{name: "rhel", major: "9", minor: "2", rest: "1"}},
		{"pkg:deb/debian/openssl?distro=bookworm", &osSpecifier{name: "debian", label: "bookworm"}},
		{"pkg:apk/alpine/openssl?distro=alpine-edge", &osSpecifier{name: "alpine", label: "edge"}},
		{"pkg:apk/wolfi/openssl?distro=wolfi", &osSpecifier{name: "wolfi"}},
		{"pkg:deb/debian/openssl", &osSpecifier{name: "debian"}},
		{"pkg:deb/ubuntu/openssl?distro=ubuntu-22.04+esm", &osSpecifier{name: "ubuntu", major: "22", minor: "4"}},
		{"pkg:deb/ubuntu/openssl?distro=ubuntu-jammy+esm", &osSpecifier{name: "ubuntu", label: "jammy"}},
		{"pkg:rpm/opensuse/openssl?distro=opensuse-leap-15.5", &osSpecifier{name: "opensuse-leap", major: "15", minor: "5"}},
		{"pkg:rpm/redhat/openssl?distro=rhel:9", &osSpecifier{name: "rhel", major: "9"}},
		{"pkg:rpm/opensuse/openssl?distro=opensuse-leap", &osSpecifier{name: "opensuse-leap"}},
		{"pkg:deb/ubuntu/openssl?distro=ubuntu-v22.04", &osSpecifier{name: "ubuntu", major: "22", minor: "4"}},
		{"pkg:deb/openssl", nil},
	}
	for _, tt := range tests {
		p, err := purl.Parse(tt.purl)
		if err != nil {
			t.Fatal(err)
		}
		got := osSpecifierFromPURL(p)
		if (got == nil) != (tt.want == nil) || (got != nil && *got != *tt.want) {
			t.Errorf("%s: got %+v, want %+v", tt.purl, got, tt.want)
		}
	}
}
