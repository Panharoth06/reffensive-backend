package parser

import (
	"encoding/json"

	"go-server/internal/services/sonarqube/scanner/dependency"
)

func ParseDotNet(raw []byte) ([]*dependency.Finding, error) {
	type vulnerability struct {
		AdvisoryURL string `json:"advisoryurl"`
		Severity    string `json:"severity"`
	}
	type pkg struct {
		ID              string          `json:"id"`
		ResolvedVersion string          `json:"resolvedVersion"`
		Vulnerabilities []vulnerability `json:"vulnerabilities"`
	}
	type framework struct {
		TopLevelPackages   []pkg `json:"topLevelPackages"`
		TransitivePackages []pkg `json:"transitivePackages"`
	}
	type project struct {
		Frameworks []framework `json:"frameworks"`
	}
	type report struct {
		Projects []project `json:"projects"`
	}

	var payload report
	if len(raw) == 0 {
		return []*dependency.Finding{}, nil
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, err
	}

	result := make([]*dependency.Finding, 0)
	for _, project := range payload.Projects {
		for _, framework := range project.Frameworks {
			for _, pkgItem := range append(framework.TopLevelPackages, framework.TransitivePackages...) {
				for _, issue := range pkgItem.Vulnerabilities {
					findingRaw, _ := json.Marshal(issue)
					result = append(result, &dependency.Finding{
						Tool:             "dotnet-audit",
						Language:         "dotnet",
						PackageName:      pkgItem.ID,
						Ecosystem:        "dotnet",
						InstalledVersion: pkgItem.ResolvedVersion,
						CVEID:            firstNonEmpty(extractCVE(issue.AdvisoryURL), issue.AdvisoryURL),
						CVESeverity:      normalizeSeverity(issue.Severity),
						IsVulnerable:     true,
						RawFinding:       findingRaw,
					})
				}
			}
		}
	}
	return result, nil
}
