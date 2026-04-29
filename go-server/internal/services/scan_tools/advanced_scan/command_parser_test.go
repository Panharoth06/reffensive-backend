package advancedscan

import (
	"fmt"
	"reflect"
	"testing"

	db "go-server/internal/database/sqlc"

	"github.com/jackc/pgx/v5/pgtype"
)

func TestSplitUnixCommandPipeline_PreservesQuotes(t *testing.T) {
	got, err := splitUnixCommandPipeline(`subfinder -d "example.com" | httpx -path '/admin area' -silent`)
	if err != nil {
		t.Fatalf("splitUnixCommandPipeline returned error: %v", err)
	}

	want := [][]string{
		{"subfinder", "-d", "example.com"},
		{"httpx", "-path", "/admin area", "-silent"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected tokenized pipeline:\nwant: %#v\ngot:  %#v", want, got)
	}
}

func TestParseCommandStepTokens_MapsInputsOptionsAndCustomFlags(t *testing.T) {
	toolRow := db.Tool{
		ToolName:    "custom-tool",
		ImageRef:    pgtype.Text{String: "example/custom-tool:latest", Valid: true},
		InputSchema: []byte(`{"type":"object","fields":[{"key":"domain","type":"string","required":true,"flag":"-d"},{"key":"path","type":"string","required":false}]}`),
		ScanConfig:  []byte(`{"medium":{"options":[{"flag":"-rate","key":"rate","type":"integer"}]},"advanced":{"options":[{"flag":"-silent","key":"silent","type":"boolean"}]}}`),
	}

	step, err := parseCommandStepTokens([]string{"custom-tool", "-d", "example.com", "-silent", "-rate=10", "/healthz", "--raw=keep"}, toolRow)
	if err != nil {
		t.Fatalf("parseCommandStepTokens returned error: %v", err)
	}

	wantArgs := map[string]string{
		"domain": "example.com",
		"silent": "true",
		"rate":   "10",
		"path":   "/healthz",
	}
	if !reflect.DeepEqual(step.ToolArgs, wantArgs) {
		t.Fatalf("unexpected tool args:\nwant: %#v\ngot:  %#v", wantArgs, step.ToolArgs)
	}

	wantFlags := []string{"--raw=keep"}
	if !reflect.DeepEqual(step.RawCustomFlags, wantFlags) {
		t.Fatalf("unexpected custom flags:\nwant: %#v\ngot:  %#v", wantFlags, step.RawCustomFlags)
	}
}

func TestParseUnixCommandToSubmittedSteps_BuildsPipelineAndDerivesTarget(t *testing.T) {
	tools := map[string]db.Tool{
		"subfinder": {
			ToolName:    "subfinder",
			ImageRef:    pgtype.Text{String: "projectdiscovery/subfinder:latest", Valid: true},
			InputSchema: []byte(`{"type":"object","fields":[{"key":"domain","type":"string","required":true,"flag":"-d"}]}`),
			ScanConfig:  []byte(`{"medium":{"options":[]},"advanced":{"options":[{"flag":"-silent","key":"silent","type":"boolean"}]}}`),
		},
		"httpx": {
			ToolName:    "httpx",
			ImageRef:    pgtype.Text{String: "projectdiscovery/httpx:latest", Valid: true},
			InputSchema: []byte(`{"type":"object","fields":[{"key":"target","type":"string","required":false}]}`),
			ScanConfig:  []byte(`{"medium":{"options":[{"flag":"-path","key":"path","type":"string"}]},"advanced":{"options":[{"flag":"-silent","key":"silent","type":"boolean"}]}}`),
		},
	}

	result, err := parseUnixCommandToSubmittedSteps(`subfinder -d example.com | httpx -path /login -silent`, func(toolName string) (db.Tool, error) {
		toolRow, ok := tools[toolName]
		if !ok {
			return db.Tool{}, fmt.Errorf("tool %q not found", toolName)
		}
		return toolRow, nil
	})
	if err != nil {
		t.Fatalf("parseUnixCommandToSubmittedSteps returned error: %v", err)
	}

	if result.DerivedTargetValue != "example.com" {
		t.Fatalf("expected derived target example.com, got %q", result.DerivedTargetValue)
	}
	if len(result.Steps) != 2 {
		t.Fatalf("expected 2 steps, got %d", len(result.Steps))
	}
	if result.Steps[0].ToolName != "subfinder" || result.Steps[1].ToolName != "httpx" {
		t.Fatalf("unexpected tool names: %#v", result.Steps)
	}

	wantFirstArgs := map[string]string{"domain": "example.com"}
	if !reflect.DeepEqual(result.Steps[0].ToolArgs, wantFirstArgs) {
		t.Fatalf("unexpected first step args:\nwant: %#v\ngot:  %#v", wantFirstArgs, result.Steps[0].ToolArgs)
	}

	wantSecondArgs := map[string]string{"path": "/login", "silent": "true"}
	if !reflect.DeepEqual(result.Steps[1].ToolArgs, wantSecondArgs) {
		t.Fatalf("unexpected second step args:\nwant: %#v\ngot:  %#v", wantSecondArgs, result.Steps[1].ToolArgs)
	}
}

func TestParseCommandStepTokens_KeepsUnknownFlagsRawWhenAdvancedOptionsAreEmpty(t *testing.T) {
	toolRow := db.Tool{
		ToolName:    "naabu",
		ImageRef:    pgtype.Text{String: "projectdiscovery/naabu:v2.5.0", Valid: true},
		InputSchema: []byte(`{"type":"object","fields":[{"key":"host","type":"string","required":true,"flag":"-host"}]}`),
		ScanConfig:  []byte(`{"medium":{"options":[{"flag":"-rate","key":"rate","type":"integer"}]},"advanced":{"options":[]}}`),
	}

	step, err := parseCommandStepTokens([]string{"naabu", "-host", "scanme.nmap.org", "-scan-type", "connect", "-rate", "1000"}, toolRow)
	if err != nil {
		t.Fatalf("parseCommandStepTokens returned error: %v", err)
	}

	wantArgs := map[string]string{
		"host": "scanme.nmap.org",
		"rate": "1000",
	}
	if !reflect.DeepEqual(step.ToolArgs, wantArgs) {
		t.Fatalf("unexpected tool args:\nwant: %#v\ngot:  %#v", wantArgs, step.ToolArgs)
	}

	wantFlags := []string{"-scan-type", "connect"}
	if !reflect.DeepEqual(step.RawCustomFlags, wantFlags) {
		t.Fatalf("unexpected custom flags:\nwant: %#v\ngot:  %#v", wantFlags, step.RawCustomFlags)
	}
}
