package dependency

import (
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
)

type DetectedLanguage struct {
	Name         string
	ManifestPath string
	BuildTool    string
}

func DetectLanguages(sourceDir string) []DetectedLanguage {
	sourceDir = strings.TrimSpace(sourceDir)
	if sourceDir == "" {
		return []DetectedLanguage{}
	}

	detected := make(map[string]DetectedLanguage)
	priority := make(map[string]int)

	_ = filepath.WalkDir(sourceDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		if d.IsDir() {
			if shouldSkipDetectorDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}

		name, buildTool, ok := detectManifest(path)
		if !ok {
			return nil
		}

		score := manifestPriority(sourceDir, path)
		current, exists := priority[name]
		if !exists || score < current {
			detected[name] = DetectedLanguage{
				Name:         name,
				ManifestPath: path,
				BuildTool:    buildTool,
			}
			priority[name] = score
		}
		return nil
	})

	if len(detected) == 0 {
		return []DetectedLanguage{}
	}

	names := make([]string, 0, len(detected))
	for name := range detected {
		names = append(names, name)
	}
	sort.Strings(names)

	result := make([]DetectedLanguage, 0, len(names))
	for _, name := range names {
		result = append(result, detected[name])
	}
	return result
}

func detectManifest(path string) (language string, buildTool string, ok bool) {
	base := filepath.Base(path)
	lower := strings.ToLower(base)

	switch {
	case lower == "go.mod":
		return "go", "", true
	case lower == "requirements.txt":
		return "python", "", true
	case lower == "pyproject.toml":
		return "python", "", true
	case base == "Pipfile":
		return "python", "", true
	case lower == "package.json":
		return "node", "", true
	case lower == "pom.xml":
		return "java", "maven", true
	case lower == "build.gradle":
		return "java", "gradle", true
	case lower == "build.gradle.kts":
		return "kotlin", "gradle", true
	case lower == "composer.json":
		return "php", "", true
	case lower == "cargo.toml":
		return "rust", "", true
	case base == "Gemfile":
		return "ruby", "", true
	case strings.HasSuffix(lower, ".csproj"), strings.HasSuffix(lower, ".fsproj"):
		return "dotnet", "", true
	case base == "Package.swift":
		return "swift", "", true
	case lower == "pubspec.yaml":
		return "dart", "", true
	default:
		return "", "", false
	}
}

func manifestPriority(sourceDir, path string) int {
	rel, err := filepath.Rel(sourceDir, path)
	if err != nil {
		return 1 << 30
	}
	if rel == "." {
		return 0
	}
	depth := strings.Count(filepath.ToSlash(rel), "/")
	return depth
}

func shouldSkipDetectorDir(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case ".git", "vendor", "node_modules":
		return true
	default:
		return false
	}
}
