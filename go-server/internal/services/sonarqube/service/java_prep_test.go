package service

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestPrepareSonarPropertiesWithoutJavaSources(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "README.md"), "# hello")

	got, err := prepareSonarProperties(context.Background(), root)
	if err != nil {
		t.Fatalf("prepareSonarProperties() error = %v", err)
	}
	if got != nil {
		t.Fatalf("prepareSonarProperties() = %#v, want nil", got)
	}
}

func TestPrepareSonarPropertiesUsesExistingBinaries(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "src", "main", "java", "com", "example", "App.java"), "class App {}")
	writeTestFile(t, filepath.Join(root, "target", "classes", "com", "example", "App.class"), "compiled")

	got, err := prepareSonarProperties(context.Background(), root)
	if err != nil {
		t.Fatalf("prepareSonarProperties() error = %v", err)
	}

	want := map[string]string{
		"sonar.java.binaries": "target/classes",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("prepareSonarProperties() = %#v, want %#v", got, want)
	}
}

func TestDetectJavaBuildPlansFindsSingleNestedRoot(t *testing.T) {
	root := t.TempDir()
	moduleDir := filepath.Join(root, "services", "api")
	writeTestFile(t, filepath.Join(moduleDir, "pom.xml"), "<project/>")

	plans, err := detectJavaBuildPlans(root)
	if err != nil {
		t.Fatalf("detectJavaBuildPlans() error = %v", err)
	}
	if len(plans) != 1 {
		t.Fatalf("plans count = %d, want 1", len(plans))
	}
	plan := plans[0]
	if plan.workDir != moduleDir {
		t.Fatalf("workDir = %q, want %q", plan.workDir, moduleDir)
	}
	if got := strings.Join(plan.command, " "); got != "mvn -DskipTests compile" {
		t.Fatalf("command = %q, want %q", got, "mvn -DskipTests compile")
	}
}

func TestDetectJavaBuildPlansPrunesNestedModuleRoots(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "pom.xml"), "<project/>")
	writeTestFile(t, filepath.Join(root, "service-a", "pom.xml"), "<project/>")
	writeTestFile(t, filepath.Join(root, "service-b", "build.gradle"), "plugins {}")

	plans, err := detectJavaBuildPlans(root)
	if err != nil {
		t.Fatalf("detectJavaBuildPlans() error = %v", err)
	}
	if len(plans) != 1 {
		t.Fatalf("plans count = %d, want 1", len(plans))
	}
	if plans[0].workDir != root {
		t.Fatalf("workDir = %q, want %q", plans[0].workDir, root)
	}
}

func TestDetectJavaBuildPlansSupportsMultipleIndependentRoots(t *testing.T) {
	root := t.TempDir()
	serviceADir := filepath.Join(root, "service-a")
	serviceBDir := filepath.Join(root, "service-b")
	writeTestFile(t, filepath.Join(serviceADir, "pom.xml"), "<project/>")
	writeTestFile(t, filepath.Join(serviceBDir, "build.gradle"), "plugins {}")

	plans, err := detectJavaBuildPlans(root)
	if err != nil {
		t.Fatalf("detectJavaBuildPlans() error = %v", err)
	}
	if len(plans) != 2 {
		t.Fatalf("plans count = %d, want 2", len(plans))
	}
	if plans[0].workDir != serviceADir {
		t.Fatalf("plans[0].workDir = %q, want %q", plans[0].workDir, serviceADir)
	}
	if plans[1].workDir != serviceBDir {
		t.Fatalf("plans[1].workDir = %q, want %q", plans[1].workDir, serviceBDir)
	}
}

func TestCollectJavaBinaryRoots(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "module-a", "target", "classes", "com", "example", "App.class"), "compiled")
	writeTestFile(t, filepath.Join(root, "module-b", "build", "classes", "java", "main", "com", "example", "Main.class"), "compiled")

	got, err := collectJavaBinaryRoots(root)
	if err != nil {
		t.Fatalf("collectJavaBinaryRoots() error = %v", err)
	}
	want := []string{"module-a/target/classes", "module-b/build/classes/java/main"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("collectJavaBinaryRoots() = %#v, want %#v", got, want)
	}
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
