package advancedscan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	db "go-server/internal/database/sqlc"
)

func TestPrepareShadowOutput_FileTransport(t *testing.T) {
	t.Parallel()

	toolRow := db.Tool{
		ToolName: "nmap",
		ShadowOutputConfig: []byte(`{
			"preferred_format":"xml",
			"formats":{
				"xml":{
					"transport":"file",
					"path_flag":"-oX",
					"parser":"xml",
					"path_mode":"file",
					"file_extension":".xml"
				}
			},
			"default_path":"/tmp/shadow-output-test"
		}`),
	}

	prepared, err := prepareShadowOutput(toolRow, "job-1", "step-2")
	if err != nil {
		t.Fatalf("prepareShadowOutput returned error: %v", err)
	}
	if !prepared.Enabled {
		t.Fatalf("expected shadow output to be enabled")
	}
	if prepared.Transport != "file" {
		t.Fatalf("expected file transport, got %q", prepared.Transport)
	}
	if len(prepared.AddedArgs) != 2 || prepared.AddedArgs[0] != "-oX" {
		t.Fatalf("unexpected args: %#v", prepared.AddedArgs)
	}
	if !strings.HasSuffix(prepared.HostPath, ".xml") {
		t.Fatalf("expected xml host path, got %q", prepared.HostPath)
	}
	if len(prepared.Volumes) != 1 || !strings.Contains(prepared.Volumes[0], "/tmp/shadow-output-test:/tmp/shadow-output-test") {
		t.Fatalf("unexpected volumes: %#v", prepared.Volumes)
	}
}

func TestCaptureShadowOutput_ReadsMountedFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "result.xml")
	if err := os.WriteFile(path, []byte("<nmaprun />"), 0o644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	captured, err := captureShadowOutput(preparedShadowOutput{
		Enabled:       true,
		Format:        "xml",
		Parser:        "xml",
		Transport:     "file",
		HostPath:      path,
		ContainerPath: "/tmp/result.xml",
	}, "")
	if err != nil {
		t.Fatalf("captureShadowOutput returned error: %v", err)
	}
	if string(captured.Content) != "<nmaprun />" {
		t.Fatalf("unexpected captured content: %q", string(captured.Content))
	}
}
