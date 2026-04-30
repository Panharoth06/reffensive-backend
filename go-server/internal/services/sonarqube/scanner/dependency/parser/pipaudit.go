package parser

import (
	"encoding/json"

	"go-server/internal/services/sonarqube/scanner/dependency"
)

func ParsePipAudit(raw []byte) ([]*dependency.Finding, error) {
	type vuln struct {
		ID          string   `json:"id"`
		Description string   `json:"description"`
		FixVersions []string `json:"fix_versions"`
	}
	type dep struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Vulns   []vuln `json:"vulns"`
	}
	type report struct {
		Dependencies []dep `json:"dependencies"`
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
		for _, issue := range item.Vulns {
			findingRaw, _ := json.Marshal(issue)
			result = append(result, &dependency.Finding{
				Tool:             "pip-audit",
				Language:         "python",
				PackageName:      item.Name,
				Ecosystem:        "python",
				InstalledVersion: item.Version,
				FixedVersion:     firstSlice(issue.FixVersions),
				CVEID:            issue.ID,
				CVESeverity:      "INFO",
				Description:      issue.Description,
				IsVulnerable:     true,
				RawFinding:       findingRaw,
			})
		}
	}
	return result, nil
}

func firstSlice(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}
