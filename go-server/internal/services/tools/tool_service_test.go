package services

import (
	"strings"
	"testing"
)

func TestNormalizeInstallMethod(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		value    string
		imageRef string
		expected string
	}{
		{name: "docker with image ref becomes official image", value: "docker", imageRef: "docker.io/acme/httpx:v1.0.0", expected: "official_image"},
		{name: "official image stays official image", value: "official_image", imageRef: "docker.io/acme/httpx:v1.0.0", expected: "official_image"},
		{name: "custom alias becomes custom build", value: "custom", expected: "custom_build"},
		{name: "empty with image ref defaults to official image", value: "", imageRef: "docker.io/acme/httpx:v1.0.0", expected: "official_image"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := normalizeInstallMethod(tt.value, tt.imageRef); got != tt.expected {
				t.Fatalf("normalizeInstallMethod(%q, %q) = %q, want %q", tt.value, tt.imageRef, got, tt.expected)
			}
		})
	}
}

func TestNormalizeToolName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		value    string
		expected string
	}{
		{name: "trimmed and lowercased", value: "  Subfinder  ", expected: "subfinder"},
		{name: "hyphenated name preserved", value: "Gobuster-Dir", expected: "gobuster-dir"},
		{name: "empty stays empty", value: "   ", expected: ""},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := normalizeToolName(tt.value); got != tt.expected {
				t.Fatalf("normalizeToolName(%q) = %q, want %q", tt.value, got, tt.expected)
			}
		})
	}
}

func TestShouldPullToolImage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		installMethod string
		source        string
		expected      bool
	}{
		{name: "official image pulls", installMethod: "official_image", source: "dockerhub", expected: true},
		{name: "docker alias pulls", installMethod: "docker", source: "dockerhub", expected: true},
		{name: "custom build skips pull", installMethod: "custom_build", source: "dockerhub", expected: false},
		{name: "local source skips pull", installMethod: "", source: "local", expected: false},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := shouldPullToolImage(tt.installMethod, tt.source); got != tt.expected {
				t.Fatalf("shouldPullToolImage(%q, %q) = %t, want %t", tt.installMethod, tt.source, got, tt.expected)
			}
		})
	}
}

func TestShouldQueueToolBuild(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		installMethod string
		imageRef      string
		imageSource   string
		expected      bool
	}{
		{name: "official image queues when upstream image ref present", installMethod: "official_image", imageRef: "docker.io/acme/httpx:v1.0.0", expected: true},
		{name: "docker alias queues when image ref present", installMethod: "docker", imageRef: "docker.io/acme/httpx:v1.0.0", expected: true},
		{name: "custom build queues when source url present", installMethod: "custom_build", imageSource: "https://github.com/OJ/gobuster.git", expected: true},
		{name: "custom build without source does not queue", installMethod: "custom_build", expected: false},
		{name: "official image without image ref does not queue", installMethod: "official_image", imageSource: "dockerhub", expected: false},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := shouldQueueToolBuild(tt.installMethod, tt.imageRef, tt.imageSource); got != tt.expected {
				t.Fatalf("shouldQueueToolBuild(%q, %q, %q) = %t, want %t", tt.installMethod, tt.imageRef, tt.imageSource, got, tt.expected)
			}
		})
	}
}

func TestBuildJobImageSource(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		installMethod string
		imageRef      string
		imageSource   string
		expected      string
	}{
		{name: "official image uses image_ref", installMethod: "official_image", imageRef: "docker.io/acme/httpx:v1.0.0", imageSource: "dockerhub", expected: "docker.io/acme/httpx:v1.0.0"},
		{name: "custom build uses image_source", installMethod: "custom_build", imageSource: "https://github.com/OJ/gobuster.git", expected: "https://github.com/OJ/gobuster.git"},
		{name: "fallback uses image_source", installMethod: "other", imageSource: "value", expected: "value"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := buildJobImageSource(tt.installMethod, tt.imageRef, tt.imageSource); got != tt.expected {
				t.Fatalf("buildJobImageSource(%q, %q, %q) = %q, want %q", tt.installMethod, tt.imageRef, tt.imageSource, got, tt.expected)
			}
		})
	}
}

func TestEnrichBuildConfigJSONAddsToolMetadata(t *testing.T) {
	t.Parallel()

	got := enrichBuildConfigJSON(`{"repository":"docker.io/autooffensive/tools"}`, "tool-id-1", "gitleaks")
	if !strings.Contains(got, `"tool_id":"tool-id-1"`) {
		t.Fatalf("expected tool_id in build config, got %s", got)
	}
	if !strings.Contains(got, `"tool_name":"gitleaks"`) {
		t.Fatalf("expected tool_name in build config, got %s", got)
	}
}
