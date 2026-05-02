package vulns

import (
	"github.com/git-pkgs/vers"
)

// isAffectedVersion checks if a version is affected according to the Affected entry.
func isAffectedVersion(affected Affected, version string) bool {
	for _, v := range affected.Versions {
		if v == version {
			return true
		}
	}

	for _, r := range affected.Ranges {
		if r.Type != "SEMVER" && r.Type != "ECOSYSTEM" {
			continue
		}
		if versionInRange(r.Events, version) {
			return true
		}
	}

	return false
}

func versionInRange(events []Event, version string) bool {
	inRange := false
	for _, e := range events {
		if e.Introduced != "" {
			if e.Introduced == "0" || vers.Compare(version, e.Introduced) >= 0 {
				inRange = true
			}
		}
		if e.Fixed != "" && inRange && vers.Compare(version, e.Fixed) >= 0 {
			inRange = false
		}
		if e.LastAffected != "" && inRange && vers.Compare(version, e.LastAffected) > 0 {
			inRange = false
		}
	}
	return inRange
}

// AffectedVersionRange returns a vers range string representing the affected versions.
// Events are processed sequentially, emitting a constraint for each
// introduced/fixed or introduced/lastAffected pair.
func AffectedVersionRange(affected Affected) string {
	if len(affected.Versions) > 0 {
		return versionsToRange(affected.Versions)
	}

	var parts []string
	for _, r := range affected.Ranges {
		parts = append(parts, rangeEventParts(r.Events)...)
	}

	if len(parts) == 0 {
		return ""
	}

	result := parts[0]
	for _, p := range parts[1:] {
		result += "|" + p
	}
	return result
}

func rangeEventParts(events []Event) []string {
	var parts []string
	var introduced string
	for _, e := range events {
		if e.Introduced != "" {
			introduced = e.Introduced
		}
		if e.Fixed != "" && introduced != "" {
			parts = append(parts, formatRange(introduced, "<"+e.Fixed))
			introduced = ""
		}
		if e.LastAffected != "" && introduced != "" {
			parts = append(parts, formatRange(introduced, "<="+e.LastAffected))
			introduced = ""
		}
	}
	if introduced != "" {
		parts = append(parts, formatRange(introduced, ""))
	}
	return parts
}

func formatRange(introduced, bound string) string {
	if introduced == "0" {
		if bound == "" {
			return "*"
		}
		return bound
	}
	if bound == "" {
		return ">=" + introduced
	}
	return ">=" + introduced + "|" + bound
}

func versionsToRange(versions []string) string {
	if len(versions) == 0 {
		return ""
	}
	result := "=" + versions[0]
	for _, v := range versions[1:] {
		result += "|=" + v
	}
	return result
}
