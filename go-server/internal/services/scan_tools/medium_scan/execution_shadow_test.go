package mediumscan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	advancedscan "go-server/internal/services/scan_tools/advanced_scan"
)

func TestWriteShadowArtifact_IncludesShadowOutput(t *testing.T) {
	t.Parallel()

	artifactRoot := t.TempDir()
	server := &mediumScanServer{artifactRoot: artifactRoot}
	shadow := &advancedscan.CapturedShadowOutput{
		Format:             "jsonl",
		Parser:             "jsonl",
		Transport:          "stdout",
		HostPath:           filepath.Join(artifactRoot, "shadow.jsonl"),
		ContainerPath:      "/tmp/shadow/shadow.jsonl",
		Content:            []byte("{\"host\":\"api.example.com\"}"),
		UsedStdoutFallback: true,
	}

	path, err := server.writeShadowArtifact(
		"job-1",
		"step-2",
		"subfinder",
		&invocationPlan{ImageRef: "projectdiscovery/subfinder:latest", Command: "subfinder", Args: []string{"-d", "example.com"}},
		nil,
		shadow,
		nil,
	)
	if err != nil {
		t.Fatalf("writeShadowArtifact returned error: %v", err)
	}

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%q) returned error: %v", path, err)
	}

	var artifact map[string]any
	if err := json.Unmarshal(body, &artifact); err != nil {
		t.Fatalf("json.Unmarshal returned error: %v", err)
	}

	shadowOutput, ok := artifact["shadow_output"].(map[string]any)
	if !ok {
		t.Fatalf("expected shadow_output object, got %#v", artifact["shadow_output"])
	}
	if got := shadowOutput["format"]; got != "jsonl" {
		t.Fatalf("unexpected shadow format: %#v", got)
	}
	if got := shadowOutput["content"]; got != "{\"host\":\"api.example.com\"}" {
		t.Fatalf("unexpected shadow content: %#v", got)
	}
	if got := shadowOutput["used_stdout_fallback"]; got != true {
		t.Fatalf("unexpected fallback marker: %#v", got)
	}
}

func TestConvertParsedFindings_PreservesStructuredFields(t *testing.T) {
	t.Parallel()

	parsed := convertParsedFindings(&advancedscan.ParsedOutput{
		Findings: []advancedscan.ParsedFinding{
			{
				Title:       "Open port 443",
				Host:        "api.example.com",
				Port:        443,
				Fingerprint: "fingerprint-1",
			},
		},
	})

	if len(parsed) != 1 {
		t.Fatalf("unexpected finding count: got %d want 1", len(parsed))
	}
	if parsed[0].Title != "Open port 443" {
		t.Fatalf("unexpected title: %q", parsed[0].Title)
	}
	if parsed[0].Host != "api.example.com" || parsed[0].Port != 443 {
		t.Fatalf("unexpected host/port: %#v", parsed[0])
	}
	if parsed[0].Fingerprint != "fingerprint-1" {
		t.Fatalf("unexpected fingerprint: %q", parsed[0].Fingerprint)
	}
}
