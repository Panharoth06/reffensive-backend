package mediumscan

import (
	"reflect"
	"testing"
	"time"

	mediumspb "go-server/gen/mediumscan"
	db "go-server/internal/database/sqlc"

	"github.com/jackc/pgx/v5/pgtype"
)

func sampleConfig() ToolConfig {
	return ToolConfig{
		ScanConfig: ScanConfig{
			Medium: MediumConfig{
				Options: []OptionDefinition{
					{Key: "timeout", Flag: "-timeout", Type: OptionTypeInteger},
					{Key: "source", Flag: "-s", Type: OptionTypeString},
					{Key: "silent", Flag: "-silent", Type: OptionTypeBoolean},
					{Key: "headers", Flag: "-header", Type: OptionTypeArray},
				},
			},
		},
	}
}

func TestBuildMediumScanFlags_Success(t *testing.T) {
	cfg := sampleConfig()
	userOptions := map[string]any{
		"timeout": float64(30),
		"source":  "crtsh",
		"silent":  true,
	}

	flags, err := BuildMediumScanFlags(cfg, userOptions)
	if err != nil {
		t.Fatalf("BuildMediumScanFlags returned error: %v", err)
	}

	want := []string{"-timeout", "30", "-s", "crtsh", "-silent"}
	if !reflect.DeepEqual(flags, want) {
		t.Fatalf("unexpected flags: got %v want %v", flags, want)
	}
}

func TestBuildMediumScanFlags_BooleanFalseExcluded(t *testing.T) {
	cfg := sampleConfig()
	userOptions := map[string]any{
		"silent": false,
	}

	flags, err := BuildMediumScanFlags(cfg, userOptions)
	if err != nil {
		t.Fatalf("BuildMediumScanFlags returned error: %v", err)
	}

	if len(flags) != 0 {
		t.Fatalf("expected no flags when boolean is false, got %v", flags)
	}
}

func TestBuildMediumScanFlags_DoesNotInjectSilentByDefault(t *testing.T) {
	cfg := sampleConfig()
	userOptions := map[string]any{
		"timeout": float64(15),
	}

	flags, err := BuildMediumScanFlags(cfg, userOptions)
	if err != nil {
		t.Fatalf("BuildMediumScanFlags returned error: %v", err)
	}

	want := []string{"-timeout", "15"}
	if !reflect.DeepEqual(flags, want) {
		t.Fatalf("unexpected flags: got %v want %v", flags, want)
	}
}

func TestBuildMediumScanFlags_ArrayRepeatsFlag(t *testing.T) {
	cfg := sampleConfig()
	userOptions := map[string]any{
		"headers": []any{"X-Test: one", "Authorization: Bearer token"},
	}

	flags, err := BuildMediumScanFlags(cfg, userOptions)
	if err != nil {
		t.Fatalf("BuildMediumScanFlags returned error: %v", err)
	}

	want := []string{"-header", "X-Test: one", "-header", "Authorization: Bearer token"}
	if !reflect.DeepEqual(flags, want) {
		t.Fatalf("unexpected flags: got %v want %v", flags, want)
	}
}

func TestBuildMediumScanFlags_ArraySupportsJSONString(t *testing.T) {
	cfg := sampleConfig()
	userOptions := map[string]any{
		"headers": `["X-Test: one","X-Test: two"]`,
	}

	flags, err := BuildMediumScanFlags(cfg, userOptions)
	if err != nil {
		t.Fatalf("BuildMediumScanFlags returned error: %v", err)
	}

	want := []string{"-header", "X-Test: one", "-header", "X-Test: two"}
	if !reflect.DeepEqual(flags, want) {
		t.Fatalf("unexpected flags: got %v want %v", flags, want)
	}
}

func TestBuildMediumScanFlags_NoSilentOptionNoDefaultInjection(t *testing.T) {
	cfg := ToolConfig{
		ScanConfig: ScanConfig{
			Medium: MediumConfig{
				Options: []OptionDefinition{
					{Key: "timeout", Flag: "-timeout", Type: OptionTypeInteger},
				},
			},
		},
	}

	flags, err := BuildMediumScanFlags(cfg, map[string]any{"timeout": float64(10)})
	if err != nil {
		t.Fatalf("BuildMediumScanFlags returned error: %v", err)
	}

	want := []string{"-timeout", "10"}
	if !reflect.DeepEqual(flags, want) {
		t.Fatalf("unexpected flags: got %v want %v", flags, want)
	}
}

func TestBuildMediumScanFlags_RejectsUnknownOption(t *testing.T) {
	cfg := sampleConfig()
	_, err := BuildMediumScanFlags(cfg, map[string]any{"unknown": "x"})
	if err == nil {
		t.Fatal("expected error for unknown option")
	}
}

func TestBuildMediumScanFlags_RejectsInvalidType(t *testing.T) {
	cfg := sampleConfig()
	_, err := BuildMediumScanFlags(cfg, map[string]any{"timeout": "30"})
	if err == nil {
		t.Fatal("expected type error for timeout")
	}
}

func TestExtractMediumOptions_RejectsInvalidDefinition(t *testing.T) {
	cfg := ToolConfig{
		ScanConfig: ScanConfig{
			Medium: MediumConfig{
				Options: []OptionDefinition{{Key: "x", Flag: "-x", Type: "number"}},
			},
		},
	}

	_, err := ExtractMediumOptions(cfg)
	if err == nil {
		t.Fatal("expected invalid option definition error")
	}
}

func TestBuildMediumInvocation_UsesSchemaInputFlag(t *testing.T) {
	toolRow := db.Tool{
		ToolName:    "subfinder",
		ImageRef:    pgtype.Text{String: "projectdiscovery/subfinder:v2.13.0", Valid: true},
		InputSchema: []byte(`{"type":"object","fields":[{"key":"domain","type":"string","required":true}]}`),
	}

	plan, err := buildMediumInvocation(toolRow, "example.com", []string{"-timeout", "30"})
	if err != nil {
		t.Fatalf("buildMediumInvocation returned error: %v", err)
	}

	want := []string{"-d", "example.com", "-timeout", "30"}
	if !reflect.DeepEqual(plan.Args, want) {
		t.Fatalf("unexpected args: got %v want %v", plan.Args, want)
	}
}

func TestBuildMediumInvocation_AllowsSubfinderThreadFlag(t *testing.T) {
	toolRow := db.Tool{
		ToolName:    "subfinder",
		ImageRef:    pgtype.Text{String: "projectdiscovery/subfinder:v2.13.0", Valid: true},
		InputSchema: []byte(`{"type":"object","fields":[{"key":"domain","type":"string","required":true,"flag":"-d"}]}`),
		ScanConfig:  []byte(`{"medium":{"options":[{"flag":"-t","key":"threads","type":"integer"}]}}`),
	}

	plan, err := buildMediumInvocation(toolRow, "example.com", []string{"-t", "25"})
	if err != nil {
		t.Fatalf("buildMediumInvocation returned error: %v", err)
	}

	want := []string{"-d", "example.com", "-t", "25"}
	if !reflect.DeepEqual(plan.Args, want) {
		t.Fatalf("unexpected args: got %v want %v", plan.Args, want)
	}
}

func TestBuildMediumInvocation_FallsBackWhenSchemaMissing(t *testing.T) {
	toolRow := db.Tool{
		ToolName: "subfinder",
		ImageRef: pgtype.Text{String: "projectdiscovery/subfinder:v2.13.0", Valid: true},
	}

	plan, err := buildMediumInvocation(toolRow, "example.com", nil)
	if err != nil {
		t.Fatalf("buildMediumInvocation returned error: %v", err)
	}

	want := []string{"-d", "example.com"}
	if !reflect.DeepEqual(plan.Args, want) {
		t.Fatalf("unexpected args: got %v want %v", plan.Args, want)
	}
}

func TestBuildMediumInvocation_PreservesPositionalTargetBeforeBooleanFlags(t *testing.T) {
	toolRow := db.Tool{
		ToolName:    "customtool",
		ImageRef:    pgtype.Text{String: "example/customtool:latest", Valid: true},
		InputSchema: []byte(`{"type":"object","fields":[{"key":"query","type":"string","required":true}]}`),
		ScanConfig:  []byte(`{"medium":{"options":[{"flag":"-silent","key":"silent","type":"boolean"}]}}`),
	}

	plan, err := buildMediumInvocation(toolRow, "example.com", []string{"-silent"})
	if err != nil {
		t.Fatalf("buildMediumInvocation returned error: %v", err)
	}

	want := []string{"example.com", "-silent"}
	if !reflect.DeepEqual(plan.Args, want) {
		t.Fatalf("unexpected args: got %v want %v", plan.Args, want)
	}
}

func TestNormalizeSubmittedStepsForRequest_LegacyFallback(t *testing.T) {
	req := &mediumspb.MediumScanSubmitRequest{
		ToolName:              "subfinder",
		RuntimeTimeoutSeconds: 1800,
		ToolOptions: map[string]*mediumspb.MediumOptionValue{
			"silent": {Value: &mediumspb.MediumOptionValue_BoolValue{BoolValue: true}},
		},
	}

	steps, err := normalizeSubmittedStepsForRequest(req)
	if err != nil {
		t.Fatalf("normalizeSubmittedStepsForRequest returned error: %v", err)
	}
	if len(steps) != 1 {
		t.Fatalf("unexpected step count: got %d want 1", len(steps))
	}
	if steps[0].ToolName != "subfinder" {
		t.Fatalf("unexpected tool name: got %q", steps[0].ToolName)
	}
	if steps[0].RuntimeTimeoutSeconds != 1800 {
		t.Fatalf("unexpected runtime timeout: got %d want 1800", steps[0].RuntimeTimeoutSeconds)
	}
}

func TestNormalizeSubmittedStepsForRequest_UsesExplicitSteps(t *testing.T) {
	req := &mediumspb.MediumScanSubmitRequest{
		Steps: []*mediumspb.MediumScanStepRequest{
			{ToolName: "subfinder", RuntimeTimeoutSeconds: 1200},
			{ToolName: "httpx"},
		},
	}

	steps, err := normalizeSubmittedStepsForRequest(req)
	if err != nil {
		t.Fatalf("normalizeSubmittedStepsForRequest returned error: %v", err)
	}
	if len(steps) != 2 {
		t.Fatalf("unexpected step count: got %d want 2", len(steps))
	}
	if steps[1].ToolName != "httpx" {
		t.Fatalf("unexpected second tool name: got %q", steps[1].ToolName)
	}
	if steps[0].RuntimeTimeoutSeconds != 1200 {
		t.Fatalf("unexpected first runtime timeout: got %d want 1200", steps[0].RuntimeTimeoutSeconds)
	}
}

func TestNormalizeSubmittedStepsForRequest_RejectsNegativeRuntimeTimeout(t *testing.T) {
	req := &mediumspb.MediumScanSubmitRequest{
		ToolName:              "subfinder",
		RuntimeTimeoutSeconds: -1,
	}

	_, err := normalizeSubmittedStepsForRequest(req)
	if err == nil {
		t.Fatal("expected negative runtime timeout to be rejected")
	}
}

func TestResolveExecutionTimeout_PrefersStepRequest(t *testing.T) {
	srv := &mediumScanServer{
		executionTimeout:    15 * time.Minute,
		maxExecutionTimeout: 2 * time.Hour,
	}
	cfg := ToolConfig{
		ScanConfig: ScanConfig{
			Medium: MediumConfig{
				DefaultRuntimeTimeoutSeconds: 1800,
			},
		},
	}

	got := srv.resolveExecutionTimeout(2400, 1200, cfg)
	if got != 40*time.Minute {
		t.Fatalf("unexpected timeout: got %s want %s", got, 40*time.Minute)
	}
}

func TestResolveExecutionTimeout_FallsBackToToolConfig(t *testing.T) {
	srv := &mediumScanServer{
		executionTimeout:    15 * time.Minute,
		maxExecutionTimeout: 2 * time.Hour,
	}
	cfg := ToolConfig{
		ScanConfig: ScanConfig{
			Medium: MediumConfig{
				DefaultRuntimeTimeoutSeconds: 1800,
			},
		},
	}

	got := srv.resolveExecutionTimeout(0, 0, cfg)
	if got != 30*time.Minute {
		t.Fatalf("unexpected timeout: got %s want %s", got, 30*time.Minute)
	}
}

func TestResolveExecutionTimeout_ClampsToServerMaximum(t *testing.T) {
	srv := &mediumScanServer{
		executionTimeout:    15 * time.Minute,
		maxExecutionTimeout: 45 * time.Minute,
	}

	got := srv.resolveExecutionTimeout(7200, 0, ToolConfig{})
	if got != 45*time.Minute {
		t.Fatalf("unexpected timeout: got %s want %s", got, 45*time.Minute)
	}
}

func TestBuildMediumInvocationForStep_AppliesPipedInput(t *testing.T) {
	toolRow := db.Tool{
		ToolName:    "httpx",
		ImageRef:    pgtype.Text{String: "projectdiscovery/httpx:latest", Valid: true},
		InputSchema: []byte(`{"type":"object","fields":[{"key":"target","type":"string","required":true}]}`),
		ScanConfig:  []byte(`{"medium":{"options":[{"flag":"-silent","key":"silent","type":"boolean"}]}}`),
	}

	prepared, err := buildMediumInvocationForStep(toolRow, "example.com", []string{"-silent"}, []string{"api.example.com", "www.example.com"}, "job-1", "step-2")
	if err != nil {
		t.Fatalf("buildMediumInvocationForStep returned error: %v", err)
	}

	want := []string{"-target", "api.example.com", "-silent"}
	if !reflect.DeepEqual(prepared.Plan.Args, want) {
		t.Fatalf("unexpected args: got %v want %v", prepared.Plan.Args, want)
	}
}

func TestBuildMediumInvocationForStep_PreparesListFilePipelineInput(t *testing.T) {
	toolRow := db.Tool{
		ToolName: "naabu",
		ImageRef: pgtype.Text{String: "projectdiscovery/naabu:latest", Valid: true},
		InputSchema: []byte(`{
			"type":"object",
			"fields":[{"key":"host","type":"string","required":true}],
			"pipeline_input":{"multi_mode":"list_file","list_flag":"-list"}
		}`),
		ScanConfig: []byte(`{"medium":{"options":[{"flag":"-silent","key":"silent","type":"boolean"}]}}`),
	}

	prepared, err := buildMediumInvocationForStep(toolRow, "example.com", []string{"-silent"}, []string{"api.example.com", "www.example.com"}, "job-1", "step-2")
	if err != nil {
		t.Fatalf("buildMediumInvocationForStep returned error: %v", err)
	}

	wantArgs := []string{"-silent", "-list", "/tmp/medium-scan-inputs/job-1_step-2.txt"}
	if !reflect.DeepEqual(prepared.Plan.Args, wantArgs) {
		t.Fatalf("unexpected args: got %v want %v", prepared.Plan.Args, wantArgs)
	}
	if len(prepared.Files) != 1 {
		t.Fatalf("unexpected file count: got %d want 1", len(prepared.Files))
	}
}
