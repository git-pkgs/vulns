package vulns

import (
	"github.com/git-pkgs/vers"
)

// isAffectedVersion checks if a version is affected according to the Affected entry.
func isAffectedVersion(affected Affected, version string) bool {
	// Check explicit versions list first
	for _, v := range affected.Versions {
		if v == version {
			return true
		}
	}

	// Check version ranges
	for _, r := range affected.Ranges {
		if r.Type != "SEMVER" && r.Type != "ECOSYSTEM" {
			continue
		}

		inRange := false
		for _, e := range r.Events {
			if e.Introduced != "" {
				// "0" means all versions from the beginning
				if e.Introduced == "0" {
					inRange = true
				} else if vers.Compare(version, e.Introduced) >= 0 {
					inRange = true
				}
			}
			if e.Fixed != "" && inRange {
				if vers.Compare(version, e.Fixed) >= 0 {
					inRange = false
				}
			}
			if e.LastAffected != "" && inRange {
				if vers.Compare(version, e.LastAffected) > 0 {
					inRange = false
				}
			}
		}
		if inRange {
			return true
		}
	}

	return false
}

// AffectedVersionRange returns a vers range string representing the affected versions.
// Events are processed sequentially, emitting a constraint for each
// introduced/fixed or introduced/lastAffected pair.
func AffectedVersionRange(affected Affected) string {
	// If explicit versions are listed, return them
	if len(affected.Versions) > 0 {
		return versionsToRange(affected.Versions)
	}

	// Build range from events
	var parts []string
	for _, r := range affected.Ranges {
		var introduced string
		for _, e := range r.Events {
			if e.Introduced != "" {
				introduced = e.Introduced
			}
			if e.Fixed != "" && introduced != "" {
				if introduced == "0" {
					parts = append(parts, "<"+e.Fixed)
				} else {
					parts = append(parts, ">="+introduced+"|<"+e.Fixed)
				}
				introduced = ""
			}
			if e.LastAffected != "" && introduced != "" {
				if introduced == "0" {
					parts = append(parts, "<="+e.LastAffected)
				} else {
					parts = append(parts, ">="+introduced+"|<="+e.LastAffected)
				}
				introduced = ""
			}
		}
		// Handle trailing introduced with no fix
		if introduced != "" {
			if introduced == "0" {
				parts = append(parts, "*")
			} else {
				parts = append(parts, ">="+introduced)
			}
		}
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
