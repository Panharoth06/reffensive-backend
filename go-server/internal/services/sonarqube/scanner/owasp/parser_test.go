package owasp

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseMapsVulnerabilities(t *testing.T) {
	reportPath := filepath.Join(t.TempDir(), "dependency-check-report.json")
	report := `{
		"dependencies": [
			{
				"fileName": "package.json",
				"filePath": "/repo/package.json",
				"version": "1.2.3",
				"license": "MIT",
				"vulnerabilities": [
					{"name": "CVE-2026-0001", "severity": "HIGH", "description": "first issue"},
					{"name": "CVE-2026-0002", "severity": "LOW", "description": "second issue"}
				]
			},
			{
				"fileName": "go.sum",
				"version": "0.1.0",
				"licenses": [{"name": "Apache-2.0"}, {"name": "BSD-3-Clause"}],
				"vulnerabilities": [
					{"name": "CVE-2026-0003", "severity": "CRITICAL", "description": "third issue"}
				]
			},
			{
				"fileName": "requirements.txt",
				"version": "2.0.0",
				"license": "BSD",
				"vulnerabilities": []
			}
		]
	}`
	if err := os.WriteFile(reportPath, []byte(report), 0o600); err != nil {
		t.Fatalf("write report: %v", err)
	}

	got, err := Parse(reportPath)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("len(Parse()) = %d, want 3", len(got))
	}

	first := got[0]
	if first.PackageName != "package.json" ||
		first.InstalledVersion != "1.2.3" ||
		first.CVEID != "CVE-2026-0001" ||
		first.Severity != "HIGH" ||
		first.License != "MIT" ||
		first.Description != "first issue" ||
		!first.IsVulnerable ||
		first.IsOutdated ||
		first.Ecosystem != "NODE" {
		t.Fatalf("unexpected first dependency: %#v", first)
	}

	third := got[2]
	if third.PackageName != "go.sum" ||
		third.License != "Apache-2.0, BSD-3-Clause" ||
		third.Ecosystem != "GO" {
		t.Fatalf("unexpected third dependency: %#v", third)
	}
}

func TestParseRejectsEmptyPath(t *testing.T) {
	if _, err := Parse(" "); err == nil {
		t.Fatal("Parse() error = nil, want error")
	}
}

func TestDetectEcosystem(t *testing.T) {
	tests := map[string]string{
		"go.sum":                      "GO",
		"requirements.txt":            "PYTHON",
		"package.json":                "NODE",
		"pom.xml":                     "JAVA",
		"service.csproj":              "DOTNET",
		"Gemfile":                     "RUBY",
		"composer.json":               "PHP",
		"Cargo.toml":                  "RUST",
		"build.gradle":                "JAVA/KOTLIN",
		"pubspec.yaml":                "DART",
		"mix.exs":                     "ELIXIR",
		"build.sbt":                   "SCALA",
		"/repo/frontend/package.json": "NODE",
		"unknown.lock":                "OTHER",
	}

	for path, want := range tests {
		if got := detectEcosystem(path); got != want {
			t.Fatalf("detectEcosystem(%q) = %q, want %q", path, got, want)
		}
	}
}
