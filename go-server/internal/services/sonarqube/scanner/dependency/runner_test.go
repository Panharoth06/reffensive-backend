package dependency

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rs/zerolog"
)

func TestRunnerRunAggregatesLanguageErrors(t *testing.T) {
	t.Parallel()

	runner := NewRunner(zerolog.Nop(), Config{})
	if err := runner.RegisterScanner("go", func(ctx context.Context, sourceDir string) ([]*Finding, error) {
		return nil, errors.New("govulncheck failed")
	}); err != nil {
		t.Fatalf("RegisterScanner(go) error = %v", err)
	}
	if err := runner.RegisterScanner("python", func(ctx context.Context, sourceDir string) ([]*Finding, error) {
		return []*Finding{{PackageName: "requests"}}, nil
	}); err != nil {
		t.Fatalf("RegisterScanner(python) error = %v", err)
	}

	findings, err := runner.Run(context.Background(), testdataDir(t, "go-and-python"))
	if len(findings) != 1 {
		t.Fatalf("findings count = %d, want 1", len(findings))
	}
	if err == nil {
		t.Fatal("Run() error = nil, want aggregated language error")
	}
	if !strings.Contains(err.Error(), "GO dependency scan failed") {
		t.Fatalf("Run() error = %q, want GO dependency scan failed", err)
	}
}

func TestRunnerRunReturnsNilWhenNoLanguagesDetected(t *testing.T) {
	t.Parallel()

	runner := NewRunner(zerolog.Nop(), Config{})
	findings, err := runner.Run(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("Run() error = %v, want nil", err)
	}
	if findings != nil {
		t.Fatalf("findings = %#v, want nil", findings)
	}
}

func testdataDir(t *testing.T, name string) string {
	t.Helper()
	dir := t.TempDir()
	switch name {
	case "go-and-python":
		writeFile(t, dir, "go.mod", "module example.com/test\n\ngo 1.25.0\n")
		writeFile(t, dir, "requirements.txt", "requests==2.31.0\n")
	default:
		t.Fatalf("unknown testdata dir %q", name)
	}
	return dir
}

func writeFile(t *testing.T, root, name, contents string) {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("WriteFile(%s) error = %v", path, err)
	}
}
