package lang

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"go-server/internal/services/sonarqube/scanner/dependency"
	"go-server/internal/services/sonarqube/scanner/dependency/parser"
)

func ScanJava(ctx context.Context, sourceDir string) ([]*dependency.Finding, error) {
	pomPath := firstExistingFile(filepath.Join(sourceDir, "pom.xml"))
	if pomPath == "" {
		pomPath = findManifest(sourceDir, "pom.xml")
	}
	if pomPath != "" {
		reportPath := filepath.Join(filepath.Dir(pomPath), "target", "dependency-check-report.json")
		_, stderr, code, err := runCommand(
			ctx,
			filepath.Dir(pomPath),
			"mvn",
			"org.owasp:dependency-check-maven:9.0.9:check",
			"-Dformat=JSON",
			"-DfailBuildOnCVSS=11",
		)
		if err != nil && code != 0 {
			return nil, commandError("mvn dependency-check", code, err, stderr)
		}
		raw, err := os.ReadFile(reportPath)
		if err != nil {
			return nil, fmt.Errorf("read maven dependency-check report: %w", err)
		}
		return parser.ParseMaven(raw)
	}

	gradlePath := firstExistingFile(
		filepath.Join(sourceDir, "build.gradle"),
		filepath.Join(sourceDir, "build.gradle.kts"),
	)
	if gradlePath == "" {
		gradlePath = findManifest(sourceDir, "build.gradle", "build.gradle.kts")
	}
	if gradlePath == "" {
		return []*dependency.Finding{}, nil
	}

	_, stderr, code, err := runCommand(
		ctx,
		filepath.Dir(gradlePath),
		"gradle",
		"dependencyCheckAnalyze",
		"-DfailOnError=false",
	)
	if err != nil && code != 0 {
		return nil, commandError("gradle dependencyCheckAnalyze", code, err, stderr)
	}

	reportPath := firstExistingFile(
		filepath.Join(filepath.Dir(gradlePath), "build", "reports", "dependency-check-report.json"),
		filepath.Join(filepath.Dir(gradlePath), "build", "reports", "dependency-check", "dependency-check-report.json"),
	)
	if reportPath == "" {
		return nil, fmt.Errorf("gradle dependency-check report not found in %s", filepath.Dir(gradlePath))
	}
	raw, err := os.ReadFile(reportPath)
	if err != nil {
		return nil, fmt.Errorf("read gradle dependency-check report: %w", err)
	}

	findings, err := parser.ParseGradle(raw)
	if err != nil {
		return nil, err
	}
	if strings.HasSuffix(strings.ToLower(gradlePath), ".kts") {
		for _, finding := range findings {
			finding.Language = "kotlin"
		}
	}
	return findings, nil
}
