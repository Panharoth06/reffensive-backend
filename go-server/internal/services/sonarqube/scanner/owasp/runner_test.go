package owasp

import (
	"reflect"
	"testing"
	"time"
)

func TestRunnerArgs(t *testing.T) {
	got := runnerArgs("/tmp/source", "project-1", "/tmp/out")
	want := []string{
		"--project", "project-1",
		"--scan", "/tmp/source",
		"--format", "JSON",
		"--out", "/tmp/out",
		"--data", "/root/.m2/repository/org/owasp/dependency-check/data",
		"--enableExperimental",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("runnerArgs() = %#v, want %#v", got, want)
	}
}

func TestRunnerArgsWithNVDAPIKey(t *testing.T) {
	t.Setenv("OWASP_NVD_API_KEY", "key-1")

	got := runnerArgs("/tmp/source", "project-1", "/tmp/out")
	want := []string{
		"--project", "project-1",
		"--scan", "/tmp/source",
		"--format", "JSON",
		"--out", "/tmp/out",
		"--data", "/root/.m2/repository/org/owasp/dependency-check/data",
		"--enableExperimental",
		"--nvdApiKey", "key-1",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("runnerArgs() = %#v, want %#v", got, want)
	}
}

func TestRunnerArgsFallsBackToLegacyNVDAPIKeyEnv(t *testing.T) {
	t.Setenv("NVD_API_KEY", "key-2")

	got := runnerArgs("/tmp/source", "project-1", "/tmp/out")
	want := []string{
		"--project", "project-1",
		"--scan", "/tmp/source",
		"--format", "JSON",
		"--out", "/tmp/out",
		"--data", "/root/.m2/repository/org/owasp/dependency-check/data",
		"--enableExperimental",
		"--nvdApiKey", "key-2",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("runnerArgs() = %#v, want %#v", got, want)
	}
}

func TestTimeoutFromEnvDuration(t *testing.T) {
	t.Setenv("OWASP_TIMEOUT", "45s")

	if got := timeoutFromEnv(); got != 45*time.Second {
		t.Fatalf("timeoutFromEnv() = %s, want 45s", got)
	}
}

func TestTimeoutFromEnvSeconds(t *testing.T) {
	t.Setenv("OWASP_TIMEOUT", "600")

	if got := timeoutFromEnv(); got != 10*time.Minute {
		t.Fatalf("timeoutFromEnv() = %s, want 10m", got)
	}
}

func TestTimeoutFromEnvDefault(t *testing.T) {
	if got := timeoutFromEnv(); got != defaultTimeout {
		t.Fatalf("timeoutFromEnv() = %s, want %s", got, defaultTimeout)
	}
}
