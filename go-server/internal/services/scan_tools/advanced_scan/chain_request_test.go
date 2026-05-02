package advancedscan

import (
	"reflect"
	"testing"

	db "go-server/internal/database/sqlc"

	"github.com/jackc/pgx/v5/pgtype"
)

func TestExtractPipeLines(t *testing.T) {
	stdout := "a.example.com\n\n b.example.com \r\n"
	got := extractPipeLines(stdout)
	want := []string{"a.example.com", "b.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
}

func TestPreparePipelineInput_UsesListFileTransport(t *testing.T) {
	toolRow := db.Tool{
		ToolName:    "naabu",
		ImageRef:    pgtype.Text{String: "projectdiscovery/naabu:v2.5.0", Valid: true},
		InputSchema: []byte(`{"type":"object","fields":[{"key":"host","type":"string","required":true,"flag":"-host"}],"pipeline_input":{"multi_mode":"list_file","list_flag":"-list","target_field":"host"}}`),
	}

	prepared, err := preparePipelineInput(
		toolRow,
		map[string]string{},
		nil,
		[]string{"a.example.com", "b.example.com", "a.example.com"},
		"job-123",
		"step-456",
	)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	wantFlags := []string{"-list", "/tmp/advanced-scan-inputs/job-123_step-456.txt"}
	if !reflect.DeepEqual(prepared.InjectedArgs, wantFlags) {
		t.Fatalf("unexpected injected args:\nwant: %#v\ngot:  %#v", wantFlags, prepared.InjectedArgs)
	}
	if len(prepared.RawCustomFlags) != 0 {
		t.Fatalf("expected no raw custom flags, got %#v", prepared.RawCustomFlags)
	}
	if len(prepared.Files) != 1 {
		t.Fatalf("expected 1 file, got %d", len(prepared.Files))
	}
	if string(prepared.Files[0].Content) != "a.example.com\nb.example.com\n" {
		t.Fatalf("unexpected file content: %q", string(prepared.Files[0].Content))
	}
}

func TestExtractPipelineOutputs_DedupesTrimmedLines(t *testing.T) {
	toolRow := db.Tool{
		ToolName:     "subfinder",
		OutputSchema: []byte(`{"type":"array","pipeline_output":{"mode":"lines","dedupe":true}}`),
	}

	got := extractPipelineOutputs(toolRow, "a.example.com\n\n b.example.com \r\na.example.com\n")
	want := []string{"a.example.com", "b.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
}

func TestExtractPipelineOutputs_RawLinesMode(t *testing.T) {
	// "_line" extract_field means pass raw lines through
	toolRow := db.Tool{
		ToolName:     "httpx",
		OutputSchema: []byte(`{"type":"array","pipeline_output":{"mode":"lines","extract_field":"_line","dedupe":true}}`),
	}

	got := extractPipelineOutputs(toolRow, "https://a.example.com [200] [nginx]\nhttp://b.example.com:8080 [302]\nhttps://a.example.com [200] [nginx]\n")
	want := []string{"https://a.example.com [200] [nginx]", "http://b.example.com:8080 [302]"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
}

func TestExtractPipelineOutputs_ExtractsURLFromJSONL(t *testing.T) {
	// JSONL mode with extract_field: pulls specified field from JSON lines
	toolRow := db.Tool{
		ToolName:     "httpx",
		OutputSchema: []byte(`{"type":"array","pipeline_output":{"mode":"jsonl","extract_field":"url","dedupe":true}}`),
	}

	got := extractPipelineOutputs(toolRow, `{"url":"https://api.example.com","status_code":200}
{"url":"http://edge.example.com:8083","status_code":200}
`)
	want := []string{"https://api.example.com", "http://edge.example.com:8083"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
}

func TestExtractPipelineOutputs_ExtractsHostFromSubfinderJSONL(t *testing.T) {
	toolRow := db.Tool{
		ToolName:     "subfinder",
		OutputSchema: []byte(`{"type":"array","pipeline_output":{"mode":"jsonl","extract_field":"host","dedupe":true}}`),
	}

	got := extractPipelineOutputs(toolRow, `{"host":"api.example.com","sources":["crtsh"]}
{"host":"edge.example.com","sources":["crtsh"]}
`)
	want := []string{"api.example.com", "edge.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
}

func TestExtractPipelineOutputs_FallbackToCommonAliases(t *testing.T) {
	// When extract_field is missing, falls back to url/input/host aliases
	toolRow := db.Tool{
		ToolName:     "httpx",
		OutputSchema: []byte(`{"type":"array","pipeline_output":{"mode":"jsonl","dedupe":true}}`),
	}

	got := extractPipelineOutputs(toolRow, `{"url":"https://a.example.com","status":200}
{"input":"http://b.example.com:8080","status":301}
`)
	want := []string{"https://a.example.com", "http://b.example.com:8080"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
}
