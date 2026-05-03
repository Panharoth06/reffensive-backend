package owasp

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
	CVEID            string
	Severity         string
	License          string
	Description      string
	IsVulnerable     bool
	IsOutdated       bool
	Ecosystem        string
}

func Parse(reportPath string) ([]*Dependency, error) {
	reportPath = strings.TrimSpace(reportPath)
	if reportPath == "" {
		return nil, fmt.Errorf("owasp report path is required")
	}

	data, err := os.ReadFile(reportPath)
	if err != nil {
		return nil, fmt.Errorf("read owasp report: %w", err)
	}

	var report dependencyCheckReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("parse owasp report JSON: %w", err)
	}

	findings := make([]*Dependency, 0)
	for _, dependency := range report.Dependencies {
		if len(dependency.Vulnerabilities) == 0 {
			continue
		}

		license := dependency.license()
		ecosystem := detectEcosystem(dependency.fileIdentity())
		for _, vulnerability := range dependency.Vulnerabilities {
			findings = append(findings, &Dependency{
				PackageName:      dependency.FileName,
				InstalledVersion: dependency.Version.String(),
				CVEID:            vulnerability.Name,
				Severity:         vulnerability.Severity,
				License:          license,
				Description:      vulnerability.Description,
				IsVulnerable:     true,
				IsOutdated:       false,
				Ecosystem:        ecosystem,
			})
		}
	}

	return findings, nil
}

type dependencyCheckReport struct {
	Dependencies []owaspDependency `json:"dependencies"`
}

type owaspDependency struct {
	FileName        string               `json:"fileName"`
	FilePath        string               `json:"filePath"`
	Version         textValue            `json:"version"`
	License         textValue            `json:"license"`
	Licenses        []owaspLicense       `json:"licenses"`
	Vulnerabilities []owaspVulnerability `json:"vulnerabilities"`
}

func (d owaspDependency) license() string {
	if value := d.License.String(); value != "" {
		return value
	}

	names := make([]string, 0, len(d.Licenses))
	for _, license := range d.Licenses {
		name := strings.TrimSpace(license.Name.String())
		if name != "" {
			names = append(names, name)
		}
	}
	return strings.Join(names, ", ")
}

func (d owaspDependency) fileIdentity() string {
	if strings.TrimSpace(d.FilePath) != "" {
		return d.FilePath
	}
	return d.FileName
}

type owaspLicense struct {
	Name textValue `json:"name"`
}

type owaspVulnerability struct {
	Name        string `json:"name"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

type textValue string

func (v *textValue) UnmarshalJSON(data []byte) error {
	var raw any
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	switch value := raw.(type) {
	case nil:
		*v = ""
	case string:
		*v = textValue(value)
	case float64:
		*v = textValue(fmt.Sprintf("%v", value))
	case bool:
		*v = textValue(fmt.Sprintf("%t", value))
	default:
		*v = textValue(strings.TrimSpace(string(data)))
	}
	return nil
}

func (v textValue) String() string {
	return strings.TrimSpace(string(v))
}

func detectEcosystem(path string) string {
	name := strings.ToLower(filepath.Base(strings.TrimSpace(path)))
	switch {
	case name == "go.sum":
		return "GO"
	case name == "requirements.txt":
		return "PYTHON"
	case name == "package.json":
		return "NODE"
	case name == "pom.xml":
		return "JAVA"
	case strings.HasSuffix(name, ".csproj"):
		return "DOTNET"
	case name == "gemfile":
		return "RUBY"
	case name == "composer.json":
		return "PHP"
	case name == "cargo.toml":
		return "RUST"
	case name == "build.gradle":
		return "JAVA/KOTLIN"
	case name == "pubspec.yaml":
		return "DART"
	case name == "mix.exs":
		return "ELIXIR"
	case strings.HasSuffix(name, ".sbt"):
		return "SCALA"
	default:
		return "OTHER"
	}
}
