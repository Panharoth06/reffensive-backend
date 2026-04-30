package parser

import (
	"encoding/json"

	"go-server/internal/services/sonarqube/scanner/dependency"
)

func ParseDart(raw []byte) ([]*dependency.Finding, error) {
	if len(raw) == 0 {
		return []*dependency.Finding{}, nil
	}

	var audit struct {
		Vulnerabilities []struct {
			Package struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"package"`
			Advisory struct {
				ID          string `json:"id"`
				CVEID       string `json:"cveID"`
				Severity    string `json:"severity"`
				Description string `json:"description"`
			} `json:"advisory"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(raw, &audit); err == nil && len(audit.Vulnerabilities) > 0 {
		result := make([]*dependency.Finding, 0, len(audit.Vulnerabilities))
		for _, item := range audit.Vulnerabilities {
			findingRaw, _ := json.Marshal(item)
			result = append(result, &dependency.Finding{
				Tool:             "dart-pub-audit",
				Language:         "dart",
				PackageName:      item.Package.Name,
				Ecosystem:        "dart",
				InstalledVersion: item.Package.Version,
				CVEID:            firstNonEmpty(item.Advisory.CVEID, item.Advisory.ID),
				CVESeverity:      normalizeSeverity(item.Advisory.Severity),
				Description:      item.Advisory.Description,
				IsVulnerable:     true,
				RawFinding:       findingRaw,
			})
		}
		return result, nil
	}

	var outdated struct {
		Packages []struct {
			Package string `json:"package"`
			Current struct {
				Version string `json:"version"`
			} `json:"current"`
			Latest struct {
				Version string `json:"version"`
			} `json:"latest"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(raw, &outdated); err != nil {
		return nil, err
	}

	result := make([]*dependency.Finding, 0)
	for _, item := range outdated.Packages {
		if item.Current.Version == item.Latest.Version || item.Latest.Version == "" {
			continue
		}
		findingRaw, _ := json.Marshal(item)
		result = append(result, &dependency.Finding{
			Tool:             "dart-pub-audit",
			Language:         "dart",
			PackageName:      item.Package,
			Ecosystem:        "dart",
			InstalledVersion: item.Current.Version,
			LatestVersion:    item.Latest.Version,
			IsOutdated:       true,
			IsVulnerable:     false,
			RawFinding:       findingRaw,
		})
	}
	return result, nil
}
