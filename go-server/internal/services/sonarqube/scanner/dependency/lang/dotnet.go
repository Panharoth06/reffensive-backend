package lang

import (
	"context"
	"path/filepath"

	"go-server/internal/services/sonarqube/scanner/dependency"
	"go-server/internal/services/sonarqube/scanner/dependency/parser"
)

func ScanDotNet(ctx context.Context, sourceDir string) ([]*dependency.Finding, error) {
	projectPath := findManifest(sourceDir, ".csproj", ".fsproj")
	if projectPath == "" {
		return []*dependency.Finding{}, nil
	}

	stdout, stderr, code, err := runCommand(
		ctx,
		filepath.Dir(projectPath),
		"dotnet",
		"list",
		projectPath,
		"package",
		"--vulnerable",
		"--include-transitive",
		"--format",
		"json",
	)
	if err != nil && code != 0 {
		return nil, commandError("dotnet list package", code, err, stderr)
	}
	return parser.ParseDotNet(stdout)
}
