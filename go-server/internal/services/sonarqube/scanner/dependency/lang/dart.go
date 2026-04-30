package lang

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"syscall"

	"go-server/internal/services/sonarqube/scanner/dependency"
	"go-server/internal/services/sonarqube/scanner/dependency/parser"
)

func ScanDart(ctx context.Context, sourceDir string) ([]*dependency.Finding, error) {
	stdout, _, code, err := dartRunCommand(ctx, sourceDir, "dart", "pub", "audit", "--json")
	if err == nil || code == 1 {
		if findings, parseErr := parser.ParseDart(stdout); parseErr == nil {
			return findings, nil
		}
	}

	stdout, stderr, code, err := dartRunCommand(ctx, sourceDir, "dart", "pub", "outdated", "--json")
	if err != nil && code != 0 {
		return nil, dartCommandError("dart pub outdated", code, err, stderr)
	}
	return parser.ParseDart(stdout)
}

func dartRunCommand(ctx context.Context, dir string, name string, args ...string) ([]byte, []byte, int, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = strings.TrimSpace(dir)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	code := 0
	if err != nil {
		code = dartExitCode(err)
	}
	return stdout.Bytes(), stderr.Bytes(), code, err
}

func dartExitCode(err error) int {
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		return -1
	}
	if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
		return status.ExitStatus()
	}
	return exitErr.ExitCode()
}

func dartCommandError(name string, code int, err error, stderr []byte) error {
	if err == nil {
		return nil
	}
	message := strings.TrimSpace(string(stderr))
	if message == "" {
		return fmt.Errorf("%s failed with exit code %d: %w", name, code, err)
	}
	return fmt.Errorf("%s failed with exit code %d: %w: %s", name, code, err, message)
}
