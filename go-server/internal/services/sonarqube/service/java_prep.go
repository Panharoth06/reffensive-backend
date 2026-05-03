package service

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	scanlogging "go-server/internal/services/sonarqube/scanner/logging"
)

const defaultJavaBuildTimeout = 15 * time.Minute

var skippedSourceDirs = map[string]struct{}{
	".git":         {},
	".scannerwork": {},
	"build":        {},
	"node_modules": {},
	"target":       {},
	"vendor":       {},
}

type javaBuildPlan struct {
	workDir string
	command []string
	label   string
}

func prepareSonarProperties(ctx context.Context, sourceDir string) (map[string]string, error) {
	hasJavaSources, err := repoHasJavaSources(sourceDir)
	if err != nil {
		return nil, fmt.Errorf("detect java sources: %w", err)
	}
	if !hasJavaSources {
		return nil, nil
	}

	binaries, err := collectJavaBinaryRoots(sourceDir)
	if err != nil {
		return nil, fmt.Errorf("collect existing java binaries: %w", err)
	}
	if len(binaries) == 0 {
		plans, err := detectJavaBuildPlans(sourceDir)
		if err != nil {
			return nil, err
		}
		for _, plan := range plans {
			if err := runJavaBuild(ctx, plan); err != nil {
				return nil, err
			}
		}

		binaries, err = collectJavaBinaryRoots(sourceDir)
		if err != nil {
			return nil, fmt.Errorf("collect compiled java binaries: %w", err)
		}
	}
	if len(binaries) == 0 {
		return nil, errors.New("java sources detected but no compiled classes were produced")
	}

	value := strings.Join(binaries, ",")
	scanlogging.Info(ctx, fmt.Sprintf("using SonarQube Java binaries: %s", value))
	return map[string]string{
		"sonar.java.binaries": value,
	}, nil
}

func repoHasJavaSources(sourceDir string) (bool, error) {
	found := false
	err := filepath.WalkDir(sourceDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if shouldSkipSourceDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.EqualFold(filepath.Ext(d.Name()), ".java") {
			found = true
			return errors.New("java-source-found")
		}
		return nil
	})
	if err != nil {
		if err.Error() == "java-source-found" {
			return true, nil
		}
		return false, err
	}
	return found, nil
}

func detectJavaBuildPlans(sourceDir string) ([]javaBuildPlan, error) {
	if plan, ok := buildPlanForDir(sourceDir); ok {
		return []javaBuildPlan{plan}, nil
	}

	candidateDirs, err := findJavaBuildCandidateDirs(sourceDir)
	if err != nil {
		return nil, fmt.Errorf("discover java build files: %w", err)
	}
	if len(candidateDirs) == 0 {
		return nil, errors.New("java sources detected but no Maven or Gradle build file was found")
	}

	buildRoots := pruneNestedBuildDirs(candidateDirs)
	plans := make([]javaBuildPlan, 0, len(buildRoots))
	for _, dir := range buildRoots {
		plan, ok := buildPlanForDir(dir)
		if !ok {
			continue
		}
		plans = append(plans, plan)
	}
	if len(plans) == 0 {
		return nil, fmt.Errorf("java build files were found but no supported build plan could be created from %s", strings.Join(buildRoots, ", "))
	}
	return plans, nil
}

func findJavaBuildCandidateDirs(sourceDir string) ([]string, error) {
	seen := make(map[string]struct{})
	err := filepath.WalkDir(sourceDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if shouldSkipSourceDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}

		switch d.Name() {
		case "pom.xml", "build.gradle", "build.gradle.kts":
			dir := filepath.Dir(path)
			seen[dir] = struct{}{}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	result := make([]string, 0, len(seen))
	for dir := range seen {
		result = append(result, dir)
	}
	sort.Strings(result)
	return result, nil
}

func pruneNestedBuildDirs(dirs []string) []string {
	if len(dirs) <= 1 {
		return dirs
	}

	sortedDirs := append([]string(nil), dirs...)
	sort.Strings(sortedDirs)

	result := make([]string, 0, len(sortedDirs))
	for _, dir := range sortedDirs {
		skip := false
		for _, existing := range result {
			if dir == existing || isChildPath(existing, dir) {
				skip = true
				break
			}
		}
		if !skip {
			result = append(result, dir)
		}
	}
	return result
}

func buildPlanForDir(dir string) (javaBuildPlan, bool) {
	switch {
	case fileExists(filepath.Join(dir, "pom.xml")):
		if fileExists(filepath.Join(dir, "mvnw")) {
			return javaBuildPlan{
				workDir: dir,
				command: []string{"bash", "./mvnw", "-DskipTests", "compile"},
				label:   fmt.Sprintf("Maven wrapper compile in %s", dir),
			}, true
		}
		return javaBuildPlan{
			workDir: dir,
			command: []string{"mvn", "-DskipTests", "compile"},
			label:   fmt.Sprintf("Maven compile in %s", dir),
		}, true
	case fileExists(filepath.Join(dir, "build.gradle")), fileExists(filepath.Join(dir, "build.gradle.kts")):
		if fileExists(filepath.Join(dir, "gradlew")) {
			return javaBuildPlan{
				workDir: dir,
				command: []string{"bash", "./gradlew", "--no-daemon", "classes"},
				label:   fmt.Sprintf("Gradle wrapper classes in %s", dir),
			}, true
		}
		return javaBuildPlan{
			workDir: dir,
			command: []string{"gradle", "--no-daemon", "classes"},
			label:   fmt.Sprintf("Gradle classes in %s", dir),
		}, true
	default:
		return javaBuildPlan{}, false
	}
}

func runJavaBuild(ctx context.Context, plan javaBuildPlan) error {
	scanlogging.Info(ctx, fmt.Sprintf("java sources detected; running %s", plan.label))

	buildCtx, cancel := context.WithTimeout(ctx, defaultJavaBuildTimeout)
	defer cancel()

	cmd := exec.CommandContext(buildCtx, plan.command[0], plan.command[1:]...)
	cmd.Dir = plan.workDir
	output, err := cmd.CombinedOutput()
	if errors.Is(buildCtx.Err(), context.Canceled) {
		return context.Canceled
	}
	if errors.Is(buildCtx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("%s timed out after %s", plan.label, defaultJavaBuildTimeout)
	}
	if err != nil {
		text := strings.TrimSpace(string(output))
		if text == "" {
			return fmt.Errorf("%s failed: %w", plan.label, err)
		}
		return fmt.Errorf("%s failed: %w\n%s", plan.label, err, text)
	}

	scanlogging.Info(ctx, fmt.Sprintf("java build completed: %s", plan.label))
	return nil
}

func collectJavaBinaryRoots(sourceDir string) ([]string, error) {
	seen := make(map[string]struct{})
	err := filepath.WalkDir(sourceDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == ".scannerwork" || d.Name() == "node_modules" || d.Name() == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.EqualFold(filepath.Ext(d.Name()), ".class") {
			return nil
		}

		root := inferJavaBinaryRoot(filepath.Dir(path))
		rel, relErr := filepath.Rel(sourceDir, root)
		if relErr != nil || strings.HasPrefix(rel, "..") {
			seen[filepath.Clean(root)] = struct{}{}
			return nil
		}
		seen[filepath.ToSlash(rel)] = struct{}{}
		return nil
	})
	if err != nil {
		return nil, err
	}

	result := make([]string, 0, len(seen))
	for root := range seen {
		result = append(result, root)
	}
	sort.Strings(result)
	return result, nil
}

func inferJavaBinaryRoot(dir string) string {
	normalized := filepath.ToSlash(dir)
	markers := []string{
		"/target/classes",
		"/build/classes/java/main",
		"/build/classes/kotlin/main",
		"/build/classes",
		"/out/production/classes",
		"/out/classes",
	}
	for _, marker := range markers {
		if idx := strings.Index(normalized, marker); idx >= 0 {
			return filepath.FromSlash(normalized[:idx+len(marker)])
		}
	}
	return dir
}

func isChildPath(parent, child string) bool {
	relative, err := filepath.Rel(parent, child)
	if err != nil {
		return false
	}
	return relative != "." && !strings.HasPrefix(relative, "..")
}

func shouldSkipSourceDir(name string) bool {
	_, ok := skippedSourceDirs[name]
	return ok
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir()
}
