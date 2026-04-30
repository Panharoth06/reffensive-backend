package parser

import (
	"encoding/json"
	"fmt"
	"strings"

	"go-server/internal/services/sonarqube/scanner/dependency"
)

func ParseNpmAudit(raw []byte) ([]*dependency.Finding, error) {
	type viaItem struct {
		Source   int    `json:"source"`
		Name     string `json:"name"`
		Title    string `json:"title"`
		URL      string `json:"url"`
		Severity string `json:"severity"`
	}
	type vulnerability struct {
		Name         string `json:"name"`
		Range        string `json:"range"`
		Severity     string `json:"severity"`
		FixAvailable any    `json:"fixAvailable"`
		Via          []any  `json:"via"`
	}
	type report struct {
		Vulnerabilities map[string]vulnerability `json:"vulnerabilities"`
	}

	var payload report
	if len(raw) == 0 {
		return []*dependency.Finding{}, nil
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, err
	}

	result := make([]*dependency.Finding, 0)
	for name, item := range payload.Vulnerabilities {
		if strings.TrimSpace(item.Severity) == "" {
			continue
		}
		cveID := ""
		description := ""
		for _, rawVia := range item.Via {
			switch value := rawVia.(type) {
			case string:
				if cve := extractCVE(value); cve != "" {
					cveID = cve
				}
				if description == "" {
					description = value
				}
			case map[string]any:
				if description == "" {
					if title, ok := value["title"].(string); ok {
						description = title
					}
				}
				if url, ok := value["url"].(string); ok && cveID == "" {
					cveID = firstNonEmpty(extractCVE(url), extractCVE(fmt.Sprint(value["source"])))
				}
			}
		}
		findingRaw, _ := json.Marshal(item)
		result = append(result, &dependency.Finding{
			Tool:             "npm-audit",
			Language:         "node",
			PackageName:      firstNonEmpty(item.Name, name),
			Ecosystem:        "node",
			InstalledVersion: item.Range,
			FixedVersion:     parseNpmFixAvailable(item.FixAvailable),
			CVEID:            cveID,
			CVESeverity:      normalizeSeverity(item.Severity),
			Description:      description,
			IsVulnerable:     true,
			RawFinding:       findingRaw,
		})
	}
	return result, nil
}

func parseNpmFixAvailable(value any) string {
	switch item := value.(type) {
	case bool:
		return ""
	case string:
		return item
	case map[string]any:
		if name, ok := item["name"].(string); ok {
			return name
		}
		if version, ok := item["version"].(string); ok {
			return version
		}
	}
	return ""
}
