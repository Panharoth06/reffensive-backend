package parser

import (
	"encoding/json"
	"strings"

	"go-server/internal/services/sonarqube/scanner/dependency"
)

func ParseBundlerAudit(raw []byte) ([]*dependency.Finding, error) {
	type advisory struct {
		CVE             string   `json:"cve"`
		Title           string   `json:"title"`
		Severity        string   `json:"severity"`
		PatchedVersions []string `json:"patched_versions"`
	}
	type gem struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	type result struct {
		Type     string   `json:"type"`
		Gem      gem      `json:"gem"`
		Advisory advisory `json:"advisory"`
	}

	var payload struct {
		Results []result `json:"results"`
	}
	if len(raw) == 0 {
		return []*dependency.Finding{}, nil
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		var direct []result
		if err2 := json.Unmarshal(raw, &direct); err2 != nil {
			return nil, err
		}
		payload.Results = direct
	}

	resultItems := make([]*dependency.Finding, 0)
	for _, item := range payload.Results {
		if item.Type != "" && item.Type != "UnpatchedGem" {
			continue
		}
		findingRaw, _ := json.Marshal(item)
		resultItems = append(resultItems, &dependency.Finding{
			Tool:             "bundler-audit",
			Language:         "ruby",
			PackageName:      item.Gem.Name,
			Ecosystem:        "ruby",
			InstalledVersion: item.Gem.Version,
			FixedVersion:     bundlerFirstSlice(item.Advisory.PatchedVersions),
			CVEID:            item.Advisory.CVE,
			CVESeverity:      bundlerNormalizeSeverity(item.Advisory.Severity),
			Description:      item.Advisory.Title,
			IsVulnerable:     true,
			RawFinding:       findingRaw,
		})
	}
	return resultItems, nil
}

func bundlerFirstSlice(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return strings.TrimSpace(values[0])
}

func bundlerNormalizeSeverity(value string) string {
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
