package lang

import (
	"context"
	"fmt"
	"path/filepath"

	"go-server/internal/services/sonarqube/scanner/dependency"
	"go-server/internal/services/sonarqube/scanner/dependency/parser"
)

func ScanNode(ctx context.Context, sourceDir string) ([]*dependency.Finding, error) {
	lockFile := firstExistingFile(
		filepath.Join(sourceDir, "package-lock.json"),
		filepath.Join(sourceDir, "npm-shrinkwrap.json"),
	)
	if lockFile == "" {
		if _, _, code, err := runCommand(ctx, sourceDir, "npm", "install", "--package-lock-only"); err != nil && code != 0 {
			return nil, fmt.Errorf("npm install --package-lock-only failed: %w", err)
		}
	}

	stdout, stderr, code, err := runCommand(ctx, sourceDir, "npm", "audit", "--json")
	if err != nil && code != 1 {
		return nil, commandError("npm audit", code, err, stderr)
	}
	return parser.ParseNpmAudit(stdout)
}
