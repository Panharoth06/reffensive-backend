package lang

import (
	"context"

	"go-server/internal/services/sonarqube/scanner/dependency"
	"go-server/internal/services/sonarqube/scanner/dependency/parser"
)

func ScanRust(ctx context.Context, sourceDir string) ([]*dependency.Finding, error) {
	stdout, stderr, code, err := runCommand(ctx, sourceDir, "cargo", "audit", "--json")
	if err != nil && code != 1 {
		return nil, commandError("cargo audit", code, err, stderr)
	}
	return parser.ParseCargoAudit(stdout)
}
