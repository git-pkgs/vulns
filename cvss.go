package vulns

import (
	"strings"

	gocvss20 "github.com/pandatix/go-cvss/20"
	gocvss30 "github.com/pandatix/go-cvss/30"
	gocvss31 "github.com/pandatix/go-cvss/31"
	gocvss40 "github.com/pandatix/go-cvss/40"
)

// CVSS holds parsed CVSS information.
type CVSS struct {
	Version string
	Vector  string
	Score   float64
	Level   string
}

// ParseCVSS parses a CVSS vector string and returns structured CVSS information.
// Supports CVSS v2.0, v3.0, v3.1, and v4.0 vectors.
func ParseCVSS(vector string) (*CVSS, error) {
	vector = strings.TrimSpace(vector)

	// Try to detect version from prefix
	switch {
	case strings.HasPrefix(vector, "CVSS:4.0/"):
		return parseCVSS40(vector)
	case strings.HasPrefix(vector, "CVSS:3.1/"):
		return parseCVSS31(vector)
	case strings.HasPrefix(vector, "CVSS:3.0/"):
		return parseCVSS30(vector)
	case strings.HasPrefix(vector, "AV:") || strings.HasPrefix(vector, "(AV:"):
		return parseCVSS20(vector)
	default:
		// Try parsing as a bare score
		var score float64
		if _, err := scanFloat(vector, &score); err == nil && score >= 0 && score <= 10 {
			return &CVSS{
				Score: score,
				Level: scoreToLevel(score),
			}, nil
		}
		// Try v3.1 as most common
		if c, err := parseCVSS31(vector); err == nil {
			return c, nil
		}
		// Try v4.0
		if c, err := parseCVSS40(vector); err == nil {
			return c, nil
		}
		return nil, &parseError{}
	}
}

func parseCVSS20(vector string) (*CVSS, error) {
	// Remove parentheses if present
	vector = strings.Trim(vector, "()")
	cvss, err := gocvss20.ParseVector(vector)
	if err != nil {
		return nil, err
	}
	score := cvss.BaseScore()
	return &CVSS{
		Version: "2.0",
		Vector:  vector,
		Score:   score,
		Level:   scoreToLevel(score),
	}, nil
}

func parseCVSS30(vector string) (*CVSS, error) {
	cvss, err := gocvss30.ParseVector(vector)
	if err != nil {
		return nil, err
	}
	score := cvss.BaseScore()
	return &CVSS{
		Version: "3.0",
		Vector:  vector,
		Score:   score,
		Level:   scoreToLevel(score),
	}, nil
}

func parseCVSS31(vector string) (*CVSS, error) {
	cvss, err := gocvss31.ParseVector(vector)
	if err != nil {
		return nil, err
	}
	score := cvss.BaseScore()
	return &CVSS{
		Version: "3.1",
		Vector:  vector,
		Score:   score,
		Level:   scoreToLevel(score),
	}, nil
}

func parseCVSS40(vector string) (*CVSS, error) {
	cvss, err := gocvss40.ParseVector(vector)
	if err != nil {
		return nil, err
	}
	score := cvss.Score()
	return &CVSS{
		Version: "4.0",
		Vector:  vector,
		Score:   score,
		Level:   scoreToLevel40(score),
	}, nil
}

// scoreToLevel converts a CVSS v2/v3 score to a severity level.
func scoreToLevel(score float64) string {
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	case score > 0:
		return "low"
	default:
		return "none"
	}
}

// scoreToLevel40 converts a CVSS v4.0 score to a severity level.
// CVSS 4.0 uses different thresholds.
func scoreToLevel40(score float64) string {
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	case score >= 0.1:
		return "low"
	default:
		return "none"
	}
}

// CVSSFromSeverity extracts and parses CVSS information from a Severity entry.
func CVSSFromSeverity(sev Severity) (*CVSS, error) {
	switch sev.Type {
	case "CVSS_V2":
		return parseCVSS20(sev.Score)
	case "CVSS_V3", "CVSS_V31":
		// First try parsing as vector, then as bare score
		if c, err := parseCVSS31(sev.Score); err == nil {
			return c, nil
		}
		if c, err := parseCVSS30(sev.Score); err == nil {
			return c, nil
		}
		return ParseCVSS(sev.Score)
	case "CVSS_V4", "CVSS_V40":
		return parseCVSS40(sev.Score)
	default:
		return ParseCVSS(sev.Score)
	}
}
