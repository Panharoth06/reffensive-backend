package parser

import (
	"encoding/json"

	"go-server/internal/services/sonarqube/scanner/dependency"
)

func ParseSwift(raw []byte) ([]*dependency.Finding, error) {
	type vulnerability struct {
		Package struct {
			Identity string `json:"identity"`
			Version  string `json:"version"`
		} `json:"package"`
		Advisory struct {
			CVEID       string `json:"cveID"`
			Severity    string `json:"severity"`
			Description string `json:"description"`
		} `json:"advisory"`
	}
	type report struct {
		Vulnerabilities []vulnerability `json:"vulnerabilities"`
	}

	var payload report
	if len(raw) == 0 {
		return []*dependency.Finding{}, nil
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, err
	}

	result := make([]*dependency.Finding, 0)
	for _, item := range payload.Vulnerabilities {
		findingRaw, _ := json.Marshal(item)
		result = append(result, &dependency.Finding{
			Tool:             "swift-audit",
			Language:         "swift",
			PackageName:      item.Package.Identity,
			Ecosystem:        "swift",
			InstalledVersion: item.Package.Version,
			CVEID:            item.Advisory.CVEID,
			CVESeverity:      normalizeSeverity(item.Advisory.Severity),
			Description:      item.Advisory.Description,
			IsVulnerable:     true,
			RawFinding:       findingRaw,
		})
	}
	return result, nil
}
