package trivy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Dependency struct {
	PackageName      string
	InstalledVersion string
	FixedVersion     string
	LatestVersion    string
	CVEID            string
	Severity         string
	License          string
	Description      string
	IsVulnerable     bool
	IsOutdated       bool
	HasLicenseIssue  bool
	Ecosystem        string
}

func Parse(reportPath string) ([]*Dependency, error) {
	reportPath = strings.TrimSpace(reportPath)
	if reportPath == "" {
		return nil, fmt.Errorf("trivy report path is required")
	}

	data, err := os.ReadFile(reportPath)
	if err != nil {
		return nil, fmt.Errorf("read trivy report: %w", err)
	}

	var report trivyReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("parse trivy report JSON: %w", err)
	}

	findings := make([]*Dependency, 0)
	for _, result := range report.Results {
		ecosystem := detectEcosystem(result.Target, result.Type)
		for _, vulnerability := range result.Vulnerabilities {
			findings = append(findings, &Dependency{
				PackageName:      vulnerability.PkgName,
				InstalledVersion: vulnerability.InstalledVersion,
				FixedVersion:     vulnerability.FixedVersion,
				CVEID:            vulnerability.VulnerabilityID,
				Severity:         normalizeSeverity(vulnerability.Severity),
				Description:      vulnerability.Description,
				IsVulnerable:     true,
				IsOutdated:       vulnerability.FixedVersion != "",
				Ecosystem:        ecosystem,
			})
		}
		for _, license := range result.Licenses {
			findings = append(findings, &Dependency{
				PackageName:     license.PkgName,
				Severity:        normalizeSeverity(firstNonEmpty(license.Severity, license.Category)),
				License:         license.Name,
				Description:     license.FilePath,
				HasLicenseIssue: true,
				Ecosystem:       ecosystem,
			})
		}
	}
	return findings, nil
}

type trivyReport struct {
	Results []trivyResult `json:"Results"`
}

type trivyResult struct {
	Target          string               `json:"Target"`
	Type            string               `json:"Type"`
	Vulnerabilities []trivyVulnerability `json:"Vulnerabilities"`
	Licenses        []trivyLicense       `json:"Licenses"`
}

type trivyVulnerability struct {
	VulnerabilityID  string `json:"VulnerabilityID"`
	PkgName          string `json:"PkgName"`
	InstalledVersion string `json:"InstalledVersion"`
	FixedVersion     string `json:"FixedVersion"`
	Severity         string `json:"Severity"`
	Description      string `json:"Description"`
}

type trivyLicense struct {
	PkgName  string `json:"PkgName"`
	FilePath string `json:"FilePath"`
	Name     string `json:"Name"`
	Category string `json:"Category"`
	Severity string `json:"Severity"`
}

func detectEcosystem(target, resultType string) string {
	switch strings.ToLower(strings.TrimSpace(resultType)) {
	case "gomod":
		return "GO"
	case "pip", "poetry", "pipenv":
		return "PYTHON"
	case "npm", "yarn", "pnpm", "node-pkg":
		return "NODE"
	case "maven", "gradle":
		return "JAVA"
	case "nuget":
		return "DOTNET"
	case "bundler":
		return "RUBY"
	case "composer":
		return "PHP"
	case "cargo":
		return "RUST"
	}

	name := strings.ToLower(filepath.Base(strings.TrimSpace(target)))
	switch {
	case name == "go.sum" || name == "go.mod":
		return "GO"
	case name == "requirements.txt" || name == "poetry.lock" || name == "pipfile.lock":
		return "PYTHON"
	case name == "package.json" || name == "package-lock.json" || name == "yarn.lock" || name == "pnpm-lock.yaml":
		return "NODE"
	case name == "pom.xml" || name == "build.gradle":
		return "JAVA"
	case strings.HasSuffix(name, ".csproj") || name == "packages.lock.json":
		return "DOTNET"
	case name == "gemfile" || name == "gemfile.lock":
		return "RUBY"
	case name == "composer.json" || name == "composer.lock":
		return "PHP"
	case name == "cargo.toml" || name == "cargo.lock":
		return "RUST"
	default:
		return "OTHER"
	}
}

func normalizeSeverity(value string) string {
	value = strings.ToUpper(strings.TrimSpace(value))
	switch value {
	case "UNKNOWN", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL":
		return value
	default:
		return "UNKNOWN"
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
