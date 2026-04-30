package parser

import (
	"encoding/json"

	"go-server/internal/services/sonarqube/scanner/dependency"
)

func ParseComposer(raw []byte) ([]*dependency.Finding, error) {
	type advisory struct {
		PackageName      string `json:"packageName"`
		AffectedVersions string `json:"affectedVersions"`
		CVE              string `json:"cve"`
		Title            string `json:"title"`
		Severity         string `json:"severity"`
	}
	type report struct {
		Advisories map[string][]advisory `json:"advisories"`
	}

	var payload report
	if len(raw) == 0 {
		return []*dependency.Finding{}, nil
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, err
	}

	result := make([]*dependency.Finding, 0)
	for packageName, advisories := range payload.Advisories {
		for _, item := range advisories {
			findingRaw, _ := json.Marshal(item)
			result = append(result, &dependency.Finding{
				Tool:             "composer-audit",
				Language:         "php",
				PackageName:      firstNonEmpty(item.PackageName, packageName),
				Ecosystem:        "php",
				InstalledVersion: item.AffectedVersions,
				CVEID:            item.CVE,
				CVESeverity:      normalizeSeverity(item.Severity),
				Description:      item.Title,
				IsVulnerable:     true,
				RawFinding:       findingRaw,
			})
		}
	}
	return result, nil
}
