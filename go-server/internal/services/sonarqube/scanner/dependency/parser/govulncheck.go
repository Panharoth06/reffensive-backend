package parser

import (
	"bufio"
	"bytes"
	"encoding/json"
	"regexp"
	"strings"

	"go-server/internal/services/sonarqube/scanner/dependency"
)

var cvePattern = regexp.MustCompile(`CVE-\d{4}-\d+`)

type govulncheckOSVEntry struct {
	ID      string   `json:"id"`
	Aliases []string `json:"aliases"`
	Summary string   `json:"summary"`
	Details string   `json:"details"`
	Severity []struct {
		Score string `json:"score"`
		Type  string `json:"type"`
	} `json:"severity"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
}

type govulncheckFrame struct {
	Module   string `json:"module"`
	Version  string `json:"version"`
	Package  string `json:"package"`
	Function string `json:"function"`
}

type govulncheckFinding struct {
	OSV          string             `json:"osv"`
	FixedVersion string             `json:"fixed_version"`
	Trace        []govulncheckFrame `json:"trace"`
}

type govulncheckMessage struct {
	OSV     *govulncheckOSVEntry `json:"osv"`
	Finding *govulncheckFinding  `json:"finding"`
}

func ParseGovulncheck(raw []byte) ([]*dependency.Finding, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return []*dependency.Finding{}, nil
	}

	osvByID := make(map[string]govulncheckOSVEntry)
	result := make([]*dependency.Finding, 0)

	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var msg govulncheckMessage
		if err := json.Unmarshal(line, &msg); err != nil {
			return nil, err
		}
		if msg.OSV != nil && strings.TrimSpace(msg.OSV.ID) != "" {
			osvByID[msg.OSV.ID] = *msg.OSV
		}
		if msg.Finding == nil || strings.TrimSpace(msg.Finding.OSV) == "" {
			continue
		}

		entry := osvByID[msg.Finding.OSV]
		frame := firstFrame(msg.Finding.Trace)
		packageName := firstNonEmpty(frame.Package, frame.Module)
		description := firstNonEmpty(entry.Details, entry.Summary)
		cveID := firstNonEmpty(firstAlias(entry.Aliases), entry.ID)
		findingRaw, _ := json.Marshal(msg)
		result = append(result, &dependency.Finding{
			Tool:             "govulncheck",
			Language:         "go",
			PackageName:      packageName,
			Ecosystem:        "go",
			InstalledVersion: frame.Version,
			FixedVersion:     msg.Finding.FixedVersion,
			CVEID:            cveID,
			CVESeverity:      normalizeSeverity(firstNonEmpty(entry.DatabaseSpecific.Severity, severityFromOSV(entry.Severity))),
			Description:      description,
			IsOutdated:       frame.Version != "" && msg.Finding.FixedVersion != "" && frame.Version != msg.Finding.FixedVersion,
			IsVulnerable:     true,
			RawFinding:       findingRaw,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func firstFrame(frames []govulncheckFrame) govulncheckFrame {
	if len(frames) == 0 {
		return govulncheckFrame{}
	}
	return frames[0]
}

func firstAlias(values []string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if strings.HasPrefix(strings.ToUpper(value), "CVE-") {
			return value
		}
	}
	return ""
}

func severityFromOSV(values []struct {
	Score string `json:"score"`
	Type  string `json:"type"`
}) string {
	for _, value := range values {
		score := strings.ToUpper(strings.TrimSpace(value.Score))
		switch {
		case strings.Contains(score, "CRITICAL"):
			return "CRITICAL"
		case strings.Contains(score, "HIGH"):
			return "HIGH"
		case strings.Contains(score, "MEDIUM"):
			return "MEDIUM"
		case strings.Contains(score, "LOW"):
			return "LOW"
		}
	}
	return ""
}

func normalizeSeverity(value string) string {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "CRITICAL":
		return "CRITICAL"
	case "HIGH":
		return "HIGH"
	case "MEDIUM", "MODERATE":
		return "MEDIUM"
	case "LOW":
		return "LOW"
	case "INFO", "INFORMATIONAL":
		return "INFO"
	default:
		return "INFO"
	}
}

func extractCVE(value string) string {
	return cvePattern.FindString(strings.ToUpper(strings.TrimSpace(value)))
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}
