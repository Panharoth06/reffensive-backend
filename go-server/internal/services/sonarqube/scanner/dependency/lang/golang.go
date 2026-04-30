package lang

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"go-server/internal/services/sonarqube/scanner/dependency"
	"go-server/internal/services/sonarqube/scanner/dependency/parser"
)

const defaultTimeout = 10 * time.Minute

func ScanGo(ctx context.Context, sourceDir string) ([]*dependency.Finding, error) {
	runCtx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()

	stdout, stderr, code, err := runCommand(runCtx, sourceDir, "govulncheck", "-json", "./...")
	if err != nil && code != 1 {
		return nil, commandError("govulncheck", code, err, stderr)
	}
	return parser.ParseGovulncheck(stdout)
}

func runCommand(ctx context.Context, dir string, name string, args ...string) ([]byte, []byte, int, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = strings.TrimSpace(dir)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	code := 0
	if err != nil {
		code = exitCode(err)
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return stdout.Bytes(), stderr.Bytes(), -1, fmt.Errorf("%s timed out", name)
	}
	return stdout.Bytes(), stderr.Bytes(), code, err
}

func exitCode(err error) int {
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		return -1
	}
	if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
		return status.ExitStatus()
	}
	return exitErr.ExitCode()
}

func commandError(name string, code int, err error, stderr []byte) error {
	if err == nil {
		return nil
	}
	message := strings.TrimSpace(string(stderr))
	if message == "" {
		return fmt.Errorf("%s failed with exit code %d: %w", name, code, err)
	}
	return fmt.Errorf("%s failed with exit code %d: %w: %s", name, code, err, message)
}

func firstExistingFile(paths ...string) string {
	for _, path := range paths {
		if strings.TrimSpace(path) == "" {
			continue
		}
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path
		}
	}
	return ""
}

func findFirstBySuffix(sourceDir string, suffixes ...string) string {
	var found string
	_ = filepath.WalkDir(sourceDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			switch strings.ToLower(d.Name()) {
			case ".git", "vendor", "node_modules":
				return filepath.SkipDir
			}
			return nil
		}
		lower := strings.ToLower(filepath.Base(path))
		for _, suffix := range suffixes {
			if strings.HasSuffix(lower, strings.ToLower(suffix)) {
				found = path
				return errors.New("found")
			}
		}
		return nil
	})
	return found
}

func findManifest(sourceDir string, names ...string) string {
	for _, name := range names {
		if path := firstExistingFile(filepath.Join(sourceDir, name)); path != "" {
			return path
		}
	}
	for _, name := range names {
		if path := findFirstBySuffix(sourceDir, name); path != "" {
			return path
		}
	}
	return ""
}
