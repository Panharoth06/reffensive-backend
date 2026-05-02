package trivy

import (
	"reflect"
	"testing"
	"time"
)

func TestRunnerArgs(t *testing.T) {
	got := runnerArgs("/tmp/source", "/tmp/trivy.json", false)
	want := []string{
		"fs", "/tmp/source",
		"--format", "json",
		"--output", "/tmp/trivy.json",
		"--security-checks", "vuln,license",
		"--exit-code", "0",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("runnerArgs() = %#v, want %#v", got, want)
	}
}

func TestTimeoutFromEnvDuration(t *testing.T) {
	t.Setenv("TRIVY_TIMEOUT", "45s")

	if got := timeoutFromEnv(); got != 45*time.Second {
		t.Fatalf("timeoutFromEnv() = %s, want 45s", got)
	}
}

func TestTimeoutFromEnvSeconds(t *testing.T) {
	t.Setenv("TRIVY_TIMEOUT", "600")

	if got := timeoutFromEnv(); got != 10*time.Minute {
		t.Fatalf("timeoutFromEnv() = %s, want 10m", got)
	}
}

func TestTimeoutFromEnvDefault(t *testing.T) {
	if got := timeoutFromEnv(); got != defaultTimeout {
		t.Fatalf("timeoutFromEnv() = %s, want %s", got, defaultTimeout)
	}
}
