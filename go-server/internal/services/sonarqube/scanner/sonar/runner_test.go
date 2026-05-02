package sonar

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestScannerArgs(t *testing.T) {
	got := scannerArgs("/tmp/repo", "project-1", "main", "http://localhost:9000", "token-1", true, "4096")
	want := []string{
		"-Dsonar.projectKey=project-1",
		"-Dsonar.projectBaseDir=/tmp/repo",
		"-Dsonar.sources=/tmp/repo",
		"-Dsonar.working.directory=.scannerwork",
		"-Dsonar.host.url=http://localhost:9000",
		"-Dsonar.token=token-1",
		"-Dsonar.branch.name=main",
		"-Dsonar.javascript.node.maxspace=4096",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("scannerArgs() = %#v, want %#v", got, want)
	}
}

func TestScannerArgsWithoutBranch(t *testing.T) {
	got := scannerArgs("/tmp/repo", "project-1", "main", "http://localhost:9000", "token-1", false, "4096")
	want := []string{
		"-Dsonar.projectKey=project-1",
		"-Dsonar.projectBaseDir=/tmp/repo",
		"-Dsonar.sources=/tmp/repo",
		"-Dsonar.working.directory=.scannerwork",
		"-Dsonar.host.url=http://localhost:9000",
		"-Dsonar.token=token-1",
		"-Dsonar.javascript.node.maxspace=4096",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("scannerArgs() = %#v, want %#v", got, want)
	}
}

func TestRunnerConfigFromEnvUsesSonarQubeEnv(t *testing.T) {
	t.Setenv("SONAR_SCANNER_BIN", "custom-sonar-scanner")
	t.Setenv("SONARQUBE_HOST", "http://localhost:9000/")
	t.Setenv("SONARQUBE_TOKEN", "token-1")
	t.Setenv("SONAR_SCAN_TIMEOUT_SECONDS", "600")
	t.Setenv("SONAR_ENABLE_BRANCH_ANALYSIS", "true")
	t.Setenv("SONAR_JS_NODE_MAXSPACE", "6144")

	cfg, err := runnerConfigFromEnv()
	if err != nil {
		t.Fatalf("runnerConfigFromEnv() error = %v", err)
	}

	if cfg.scannerBin != "custom-sonar-scanner" {
		t.Fatalf("scannerBin = %q, want custom-sonar-scanner", cfg.scannerBin)
	}
	if cfg.hostURL != "http://localhost:9000" {
		t.Fatalf("hostURL = %q, want http://localhost:9000", cfg.hostURL)
	}
	if cfg.token != "token-1" {
		t.Fatalf("token = %q, want token-1", cfg.token)
	}
	if cfg.timeout != 10*time.Minute {
		t.Fatalf("timeout = %s, want 10m0s", cfg.timeout)
	}
	if !cfg.enableBranchAnalysis {
		t.Fatal("enableBranchAnalysis = false, want true")
	}
	if cfg.jsNodeMaxSpace != "6144" {
		t.Fatalf("jsNodeMaxSpace = %q, want 6144", cfg.jsNodeMaxSpace)
	}
}

func TestRunnerConfigFromEnvUsesAliasEnv(t *testing.T) {
	t.Setenv("SONAR_HOST_URL", "http://sonar.example")
	t.Setenv("SONAR_TOKEN", "token-2")
	t.Setenv("SONAR_TIMEOUT", "30s")

	cfg, err := runnerConfigFromEnv()
	if err != nil {
		t.Fatalf("runnerConfigFromEnv() error = %v", err)
	}

	if cfg.scannerBin != defaultScannerBin {
		t.Fatalf("scannerBin = %q, want %q", cfg.scannerBin, defaultScannerBin)
	}
	if cfg.hostURL != "http://sonar.example" {
		t.Fatalf("hostURL = %q, want http://sonar.example", cfg.hostURL)
	}
	if cfg.token != "token-2" {
		t.Fatalf("token = %q, want token-2", cfg.token)
	}
	if cfg.timeout != 30*time.Second {
		t.Fatalf("timeout = %s, want 30s", cfg.timeout)
	}
	if cfg.enableBranchAnalysis {
		t.Fatal("enableBranchAnalysis = true, want false by default")
	}
	if cfg.jsNodeMaxSpace != "4096" {
		t.Fatalf("jsNodeMaxSpace = %q, want default 4096", cfg.jsNodeMaxSpace)
	}
}

func TestRunnerConfigFromEnvRequiresHostAndToken(t *testing.T) {
	if _, err := runnerConfigFromEnv(); err == nil {
		t.Fatal("runnerConfigFromEnv() error = nil, want missing host error")
	}

	t.Setenv("SONARQUBE_HOST", "http://localhost:9000")
	if _, err := runnerConfigFromEnv(); err == nil {
		t.Fatal("runnerConfigFromEnv() error = nil, want missing token error")
	}
}

func TestBranchAnalysisUnsupported(t *testing.T) {
	err := errors.New(`sonar-scanner failed: exit status 1
stderr: Validation of project failed:
  o To use the property "sonar.branch.name" and analyze branches, Developer Edition or above is required.`)

	if !branchAnalysisUnsupported(err) {
		t.Fatal("branchAnalysisUnsupported() = false, want true")
	}
}

func TestBranchAnalysisEnabledFromEnv(t *testing.T) {
	t.Setenv("SONAR_ENABLE_BRANCH_ANALYSIS", "true")
	if !branchAnalysisEnabledFromEnv() {
		t.Fatal("branchAnalysisEnabledFromEnv() = false, want true")
	}

	t.Setenv("SONAR_ENABLE_BRANCH_ANALYSIS", "not-a-bool")
	if branchAnalysisEnabledFromEnv() {
		t.Fatal("branchAnalysisEnabledFromEnv() = true, want false for invalid value")
	}
}

func TestJSNodeMaxSpaceFromEnv(t *testing.T) {
	t.Setenv("SONAR_JS_NODE_MAXSPACE", "8192")
	if got := jsNodeMaxSpaceFromEnv(); got != "8192" {
		t.Fatalf("jsNodeMaxSpaceFromEnv() = %q, want 8192", got)
	}

	t.Setenv("SONAR_JS_NODE_MAXSPACE", "bad")
	if got := jsNodeMaxSpaceFromEnv(); got != "4096" {
		t.Fatalf("jsNodeMaxSpaceFromEnv() = %q, want fallback 4096", got)
	}
}
