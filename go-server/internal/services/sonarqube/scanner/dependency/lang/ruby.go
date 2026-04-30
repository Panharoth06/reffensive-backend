package lang

import (
	"context"

	"go-server/internal/services/sonarqube/scanner/dependency"
	"go-server/internal/services/sonarqube/scanner/dependency/parser"
)

func ScanRuby(ctx context.Context, sourceDir string) ([]*dependency.Finding, error) {
	if _, stderr, code, err := runCommand(ctx, sourceDir, "bundle-audit", "update"); err != nil && code != 0 {
		return nil, commandError("bundle-audit update", code, err, stderr)
	}

	stdout, stderr, code, err := runCommand(ctx, sourceDir, "bundle-audit", "check", "--format", "json")
	if err != nil && code != 1 {
		return nil, commandError("bundle-audit check", code, err, stderr)
	}
	return parser.ParseBundlerAudit(stdout)
}
