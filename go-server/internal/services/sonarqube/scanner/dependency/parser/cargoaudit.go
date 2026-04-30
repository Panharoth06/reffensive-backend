package parser

import (
	"encoding/json"

	"go-server/internal/services/sonarqube/scanner/dependency"
)

func ParseCargoAudit(raw []byte) ([]*dependency.Finding, error) {
	type advisory struct {
		ID       string `json:"id"`
		Title    string `json:"title"`
		Severity string `json:"severity"`
	}
	type pkg struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	type versions struct {
		Patched []string `json:"patched"`
	}
	type item struct {
		Advisory advisory `json:"advisory"`
		Package  pkg      `json:"package"`
		Versions versions `json:"versions"`
	}
	type report struct {
		Vulnerabilities struct {
			List []item `json:"list"`
		} `json:"vulnerabilities"`
	}

	var payload report
	if len(raw) == 0 {
		return []*dependency.Finding{}, nil
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, err
	}

	result := make([]*dependency.Finding, 0)
	for _, issue := range payload.Vulnerabilities.List {
		findingRaw, _ := json.Marshal(issue)
		result = append(result, &dependency.Finding{
			Tool:             "cargo-audit",
			Language:         "rust",
			PackageName:      issue.Package.Name,
			Ecosystem:        "rust",
			InstalledVersion: issue.Package.Version,
			FixedVersion:     firstSlice(issue.Versions.Patched),
			CVEID:            issue.Advisory.ID,
			CVESeverity:      normalizeSeverity(issue.Advisory.Severity),
			Description:      issue.Advisory.Title,
			IsVulnerable:     true,
			RawFinding:       findingRaw,
		})
	}
	return result, nil
}
