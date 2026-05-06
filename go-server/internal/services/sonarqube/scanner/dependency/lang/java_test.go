package lang

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestResolveGradleAnalyzeCommandUsesWrapperWhenPresent(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "gradlew"), []byte("#!/usr/bin/env sh\n"), 0o755); err != nil {
		t.Fatalf("write gradlew: %v", err)
	}

	command, args := resolveGradleAnalyzeCommand(dir)

	if command != "bash" {
		t.Fatalf("command = %q, want %q", command, "bash")
	}
	wantArgs := []string{"./gradlew", "--no-daemon", "dependencyCheckAnalyze", "-DfailOnError=false"}
	if !reflect.DeepEqual(args, wantArgs) {
		t.Fatalf("args = %v, want %v", args, wantArgs)
	}
}

func TestResolveGradleAnalyzeCommandFallsBackToGradle(t *testing.T) {
	dir := t.TempDir()

	command, args := resolveGradleAnalyzeCommand(dir)

	if command != "gradle" {
		t.Fatalf("command = %q, want %q", command, "gradle")
	}
	wantArgs := []string{"--no-daemon", "dependencyCheckAnalyze", "-DfailOnError=false"}
	if !reflect.DeepEqual(args, wantArgs) {
		t.Fatalf("args = %v, want %v", args, wantArgs)
	}
}
