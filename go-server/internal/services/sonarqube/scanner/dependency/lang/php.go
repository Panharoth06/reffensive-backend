package lang

import (
	"context"

	"go-server/internal/services/sonarqube/scanner/dependency"
	"go-server/internal/services/sonarqube/scanner/dependency/parser"
)

func ScanPHP(ctx context.Context, sourceDir string) ([]*dependency.Finding, error) {
	stdout, stderr, code, err := runCommand(
		ctx,
		sourceDir,
		"composer",
		"audit",
		"--format=json",
		"--no-interaction",
		"--working-dir="+sourceDir,
	)
	if err != nil && code != 1 {
		return nil, commandError("composer audit", code, err, stderr)
	}
	return parser.ParseComposer(stdout)
}
