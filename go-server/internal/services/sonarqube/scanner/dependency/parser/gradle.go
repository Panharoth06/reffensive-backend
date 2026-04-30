package parser

import (
	"encoding/json"
	"strings"

	"go-server/internal/services/sonarqube/scanner/dependency"
)

type dependencyCheckLicense struct {
	Name string `json:"name"`
}

func ParseGradle(raw []byte) ([]*dependency.Finding, error) {
	return parseDependencyCheck(raw, "gradle-dependency-check", "java")
}

func parseDependencyCheck(raw []byte, tool string, language string) ([]*dependency.Finding, error) {
	type vulnerability struct {
		Name        string `json:"name"`
		Severity    string `json:"severity"`
		Description string `json:"description"`
	}
	type dcDependency struct {
		FileName        string          `json:"fileName"`
		Version         string          `json:"version"`
		License         string          `json:"license"`
		Licenses        []dependencyCheckLicense `json:"licenses"`
		Vulnerabilities []vulnerability `json:"vulnerabilities"`
	}
	type report struct {
		Dependencies []dcDependency `json:"dependencies"`
	}

	var payload report
	if len(raw) == 0 {
		return []*dependency.Finding{}, nil
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, err
	}

	result := make([]*dependency.Finding, 0)
	for _, item := range payload.Dependencies {
		licenseName := firstNonEmpty(item.License, firstLicense(item.Licenses))
		for _, issue := range item.Vulnerabilities {
			findingRaw, _ := json.Marshal(issue)
			result = append(result, &dependency.Finding{
				Tool:             tool,
				Language:         language,
				PackageName:      item.FileName,
				Ecosystem:        language,
				InstalledVersion: item.Version,
				CVEID:            issue.Name,
				CVESeverity:      normalizeSeverity(issue.Severity),
				Description:      issue.Description,
				License:          licenseName,
				IsVulnerable:     true,
				RawFinding:       findingRaw,
			})
		}
	}
	return result, nil
}

func firstLicense(values []dependencyCheckLicense) string {
	if len(values) == 0 {
		return ""
	}
	return strings.TrimSpace(values[0].Name)
}
