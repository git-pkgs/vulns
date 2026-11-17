package grypedb

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"strings"

	"github.com/git-pkgs/purl"
)

// osPackageTypes are the PURL types whose advisories the v6 DB records per
// operating system release, through affected_package_handles.operating_system_id.
var osPackageTypes = map[string]bool{"apk": true, "deb": true, "rpm": true}

// osSpecifier mirrors grype's OSSpecifier.
type osSpecifier struct {
	name, major, minor, rest, label string
}

// osSpecifierFromPURL reads a bare codename such as "distro=jessie" as a label
// of the namespace's distribution, where grype would read it as a name.
func osSpecifierFromPURL(p *purl.PURL) *osSpecifier {
	spec := &osSpecifier{name: p.Namespace}
	distro := strings.TrimSpace(p.Qualifier("distro"))
	name, version := splitDistro(distro)
	switch {
	case version != "":
		spec.name = name
		spec.setVersion(version)
	case distro == "":
	case spec.name == "" || strings.EqualFold(name, spec.name) || strings.EqualFold(name, opensuseLeap):
		spec.name = name
	default:
		spec.setVersion(distro)
	}
	if spec.name == "" {
		return nil
	}
	return spec
}

// opensuseLeap is the one distribution ID with a hyphen in it.
const opensuseLeap = "opensuse-leap"

// splitDistro splits at the first "-", ":" or "@", keeping "opensuse-leap" whole.
func splitDistro(s string) (name, version string) {
	if strings.EqualFold(s, opensuseLeap) {
		return s, ""
	}
	n := len(opensuseLeap)
	if len(s) > n && strings.EqualFold(s[:n], opensuseLeap) && strings.ContainsRune("-:@", rune(s[n])) {
		return s[:n], s[n+1:]
	}
	if i := strings.IndexAny(s, "-:@"); i >= 0 {
		return s[:i], s[i+1:]
	}
	return s, ""
}

func (o *osSpecifier) setVersion(v string) {
	// A "+esm" or "+eus" channel is dropped: channel rows carry fix data, and the
	// release's vulnerabilities are linked to its vanilla row.
	base, _, _ := strings.Cut(v, "+")
	if !strings.ContainsAny(base, "0123456789") {
		o.label = base
		return
	}
	parts := strings.SplitN(strings.TrimPrefix(base, "v"), ".", 3)
	o.major = trimZeroes(parts[0])
	if len(parts) > 1 {
		o.minor = trimZeroes(parts[1])
	}
	if len(parts) > 2 {
		o.rest = parts[2]
	}
}

func (o *osSpecifier) version() string {
	switch {
	case o.major == "":
		return o.label
	case o.minor == "":
		return o.major
	case o.rest == "":
		return o.major + "." + o.minor
	default:
		return o.major + "." + o.minor + "." + o.rest
	}
}

// trimZeroes matches grype, which stores 22.04 as major "22", minor "4".
func trimZeroes(s string) string {
	t := strings.TrimLeft(s, "0")
	if t == "" && s != "" {
		return "0"
	}
	return t
}

// applyOSAlias skips any override limited by applicable_client_db_schemas,
// since those constraints are against grype's client schema version.
func (s *Source) applyOSAlias(ctx context.Context, spec *osSpecifier) error {
	rows, err := s.db.QueryContext(ctx, `
		SELECT version, version_pattern, codename, replacement,
			replacement_major_version, replacement_minor_version, replacement_label_version, rolling
		FROM operating_system_specifier_overrides
		WHERE alias = ? COLLATE NOCASE
		AND (applicable_client_db_schemas IS NULL OR applicable_client_db_schemas = '')
		ORDER BY rowid
	`, spec.name)
	if err != nil {
		return fmt.Errorf("querying os aliases: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var version, pattern, codename sql.NullString
		var name, major, minor, label sql.NullString
		var rolling bool
		if err := rows.Scan(&version, &pattern, &codename, &name, &major, &minor, &label, &rolling); err != nil {
			return fmt.Errorf("scanning os alias: %w", err)
		}
		if codename.String != "" && codename.String != spec.label {
			continue
		}
		if version.String != "" && version.String != spec.version() {
			continue
		}
		if pattern.String != "" {
			re, err := regexp.Compile(pattern.String)
			if err != nil || !re.MatchString(spec.version()) {
				continue
			}
		}
		if name.Valid {
			spec.name = name.String
		}
		if rolling {
			spec.major, spec.minor, spec.rest = "", "", ""
		}
		if major.Valid {
			spec.major = major.String
		}
		if minor.Valid {
			spec.minor = minor.String
		}
		if label.Valid {
			spec.label = label.String
		}
		break
	}
	return rows.Err()
}

func (s *Source) operatingSystemIDs(ctx context.Context, spec *osSpecifier) ([]int64, error) {
	if err := s.applyOSAlias(ctx, spec); err != nil {
		return nil, err
	}
	where := "(name = ? COLLATE NOCASE OR release_id = ? COLLATE NOCASE) AND (channel IS NULL OR channel = '')"
	args := []any{spec.name, spec.name}
	if spec.label != "" {
		where += " AND (codename = ? COLLATE NOCASE OR label_version = ? COLLATE NOCASE)"
		args = append(args, spec.label, spec.label)
	}
	if spec.major == "" {
		return s.selectOSIDs(ctx, where, args)
	}

	var tries [][]any
	if spec.minor != "" {
		tries = append(tries, []any{"major_version = ? AND minor_version = ?", spec.major, spec.minor})
	}
	tries = append(tries,
		[]any{"major_version = ? AND minor_version = ''", spec.major},
		[]any{"major_version = ?", spec.major},
	)
	for _, try := range tries {
		ids, err := s.selectOSIDs(ctx, where+" AND "+try[0].(string), append(append([]any{}, args...), try[1:]...))
		if err != nil || len(ids) > 0 {
			return ids, err
		}
	}
	return nil, nil
}

func (s *Source) selectOSIDs(ctx context.Context, where string, args []any) ([]int64, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id FROM operating_systems WHERE "+where, args...)
	if err != nil {
		return nil, fmt.Errorf("querying operating systems: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scanning operating system: %w", err)
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}
