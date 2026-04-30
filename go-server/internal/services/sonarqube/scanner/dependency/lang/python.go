package lang

import (
	"context"
	"path/filepath"
	"strings"

	"go-server/internal/services/sonarqube/scanner/dependency"
	"go-server/internal/services/sonarqube/scanner/dependency/parser"
)

func ScanPython(ctx context.Context, sourceDir string) ([]*dependency.Finding, error) {
	manifest := firstExistingFile(
		filepath.Join(sourceDir, "requirements.txt"),
		filepath.Join(sourceDir, "pyproject.toml"),
		filepath.Join(sourceDir, "Pipfile"),
	)
	if manifest == "" {
		manifest = findManifest(sourceDir, "requirements.txt", "pyproject.toml", "Pipfile")
	}

	args := []string{"--format=json", "--output=-"}
	if strings.HasSuffix(strings.ToLower(manifest), "requirements.txt") {
		args = append(args, "-r", manifest)
	}

	stdout, stderr, code, err := runCommand(ctx, sourceDir, "pip-audit", args...)
	if err != nil && code != 1 {
		return nil, commandError("pip-audit", code, err, stderr)
	}
	return parser.ParsePipAudit(stdout)
}
