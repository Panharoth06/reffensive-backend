package advancedscan

import (
	"strings"
	"testing"

	advancedpb "go-server/gen/advanced"
	db "go-server/internal/database/sqlc"

	"github.com/jackc/pgx/v5/pgtype"
)

func TestBuildAdvancedInvocation_AllowsValidAdvancedRequest(t *testing.T) {
	toolRow := db.Tool{
		ToolName:    "subfinder",
		ImageRef:    pgtype.Text{String: "projectdiscovery/subfinder:latest", Valid: true},
		InputSchema: []byte(`{"type":"object","fields":[{"key":"domain","type":"string","required":true,"flag":"-d"}]}`),
		ScanConfig:  []byte(`{"medium":{"options":[{"flag":"-timeout","key":"timeout","type":"integer"}]},"advanced":{"options":[{"flag":"-silent","key":"silent","type":"boolean"}]}}`),
	}

	req := &advancedpb.SubmitScanRequest{
		ToolArgs: map[string]string{
			"domain":  "example.com",
			"timeout": "20",
		},
		CustomFlags: []*advancedpb.CustomFlag{
			{Normalized: "-silent"},
		},
	}

	plan, err := BuildAdvancedInvocation(toolRow, req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	got := joinArgs(plan.Args)
	want := "-d example.com -timeout 20 -silent"
	if got != want {
		t.Fatalf("unexpected args:\nwant: %s\ngot:  %s", want, got)
	}
}

func TestBuildAdvancedInvocation_NormalizesCommandToLowercase(t *testing.T) {
	toolRow := db.Tool{
		ToolName:    "Subfinder",
		ImageRef:    pgtype.Text{String: "projectdiscovery/subfinder:latest", Valid: true},
		InputSchema: []byte(`{"type":"object","fields":[{"key":"domain","type":"string","required":true,"flag":"-d"}]}`),
		ScanConfig:  []byte(`{"medium":{"options":[]},"advanced":{"options":[]}}`),
	}

	req := &advancedpb.SubmitScanRequest{
		ToolArgs: map[string]string{
			"domain": "example.com",
		},
	}

	plan, err := BuildAdvancedInvocation(toolRow, req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if plan.Command != "subfinder" {
		t.Fatalf("unexpected command: got %q want %q", plan.Command, "subfinder")
	}
}

func TestBuildAdvancedInvocation_AllowsRawCustomFlagsWithoutAdvancedOptionMetadata(t *testing.T) {
	toolRow := db.Tool{
		ToolName:    "naabu",
		ImageRef:    pgtype.Text{String: "projectdiscovery/naabu:v2.5.0", Valid: true},
		InputSchema: []byte(`{"type":"object","fields":[{"key":"host","type":"string","required":true,"flag":"-host"}]}`),
		ScanConfig:  []byte(`{"medium":{"options":[{"flag":"-rate","key":"rate","type":"integer"}]},"advanced":{"options":[]}}`),
	}

	req := &advancedpb.SubmitScanRequest{
		ToolArgs: map[string]string{
			"host": "scanme.nmap.org",
			"rate": "500",
		},
		CustomFlags: []*advancedpb.CustomFlag{
			{Normalized: "-scan-type", Value: "connect"},
		},
	}

	plan, err := BuildAdvancedInvocation(toolRow, req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	got := joinArgs(plan.Args)
	want := "-host scanme.nmap.org -rate 500 -scan-type connect"
	if got != want {
		t.Fatalf("unexpected args:\nwant: %s\ngot:  %s", want, got)
	}
}

func TestBuildAdvancedInvocation_DeniedFlagRejected(t *testing.T) {
	toolRow := db.Tool{
		ToolName:      "subfinder",
		ImageRef:      pgtype.Text{String: "projectdiscovery/subfinder:latest", Valid: true},
		InputSchema:   []byte(`{"type":"object","fields":[{"key":"domain","type":"string","required":true,"flag":"-d"}]}`),
		ScanConfig:    []byte(`{"medium":{"options":[]},"advanced":{"options":[]}}`),
		DeniedOptions: []string{"-silent"},
	}

	req := &advancedpb.SubmitScanRequest{
		ToolArgs: map[string]string{
			"domain": "example.com",
		},
		CustomFlags: []*advancedpb.CustomFlag{
			{Normalized: "-silent"},
		},
	}

	_, err := BuildAdvancedInvocation(toolRow, req)
	if err == nil {
		t.Fatalf("expected denied flag error, got nil")
	}
}

func TestBuildAdvancedInvocation_MissingRequiredInputRejected(t *testing.T) {
	toolRow := db.Tool{
		ToolName:    "subfinder",
		ImageRef:    pgtype.Text{String: "projectdiscovery/subfinder:latest", Valid: true},
		InputSchema: []byte(`{"type":"object","fields":[{"key":"domain","type":"string","required":true,"flag":"-d"}]}`),
		ScanConfig:  []byte(`{"medium":{"options":[]},"advanced":{"options":[]}}`),
	}

	req := &advancedpb.SubmitScanRequest{
		ToolArgs: map[string]string{},
	}

	_, err := BuildAdvancedInvocation(toolRow, req)
	if err == nil {
		t.Fatalf("expected missing input error, got nil")
	}
}

func TestBuildAdvancedInvocation_FillsMissingRequiredInputFromTarget(t *testing.T) {
	toolRow := db.Tool{
		ToolName:    "subfinder",
		ImageRef:    pgtype.Text{String: "projectdiscovery/subfinder:latest", Valid: true},
		InputSchema: []byte(`{"type":"object","fields":[{"key":"domain","type":"string","required":true,"flag":"-d"}]}`),
		ScanConfig:  []byte(`{"medium":{"options":[]},"advanced":{"options":[]}}`),
	}

	req := &advancedpb.SubmitScanRequest{
		ToolArgs:    map[string]string{},
		TargetValue: "example.com",
	}

	plan, err := BuildAdvancedInvocation(toolRow, req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	got := joinArgs(plan.Args)
	want := "-d example.com"
	if got != want {
		t.Fatalf("unexpected args:\nwant: %s\ngot:  %s", want, got)
	}
}

func TestBuildAdvancedInvocation_DoesNotOverrideProvidedInputWhenTargetExists(t *testing.T) {
	toolRow := db.Tool{
		ToolName:    "subfinder",
		ImageRef:    pgtype.Text{String: "projectdiscovery/subfinder:latest", Valid: true},
		InputSchema: []byte(`{"type":"object","fields":[{"key":"domain","type":"string","required":true,"flag":"-d"}]}`),
		ScanConfig:  []byte(`{"medium":{"options":[]},"advanced":{"options":[]}}`),
	}

	req := &advancedpb.SubmitScanRequest{
		ToolArgs: map[string]string{
			"domain": "already-set.example",
		},
		TargetValue: "example.com",
	}

	plan, err := BuildAdvancedInvocation(toolRow, req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	got := joinArgs(plan.Args)
	want := "-d already-set.example"
	if got != want {
		t.Fatalf("unexpected args:\nwant: %s\ngot:  %s", want, got)
	}
}

func TestBuildAdvancedInvocation_FillsOptionalTargetLikeInputFromTarget(t *testing.T) {
	toolRow := db.Tool{
		ToolName:    "subfinder",
		ImageRef:    pgtype.Text{String: "projectdiscovery/subfinder:latest", Valid: true},
		InputSchema: []byte(`{"type":"object","fields":[{"key":"domain","type":"string","required":false,"flag":"-d"}]}`),
		ScanConfig:  []byte(`{"medium":{"options":[]},"advanced":{"options":[]}}`),
	}

	req := &advancedpb.SubmitScanRequest{
		ToolArgs:    map[string]string{},
		TargetValue: "example.com",
	}

	plan, err := BuildAdvancedInvocation(toolRow, req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	got := joinArgs(plan.Args)
	want := "-d example.com"
	if got != want {
		t.Fatalf("unexpected args:\nwant: %s\ngot:  %s", want, got)
	}
}

func TestBuildAdvancedInvocation_DoesNotInjectTargetIntoNonTargetField(t *testing.T) {
	toolRow := db.Tool{
		ToolName:    "nmap",
		ImageRef:    pgtype.Text{String: "instrumentisto/nmap:7.98", Valid: true},
		InputSchema: []byte(`{"type":"object","fields":[{"key":"target","type":"string","required":true},{"key":"ports","type":"string","required":true,"flag":"-p"}]}`),
		ScanConfig:  []byte(`{"medium":{"options":[]},"advanced":{"options":[]}}`),
	}

	req := &advancedpb.SubmitScanRequest{
		ToolArgs: map[string]string{
			"target": "nmap.org",
		},
		TargetValue: "nmap.org",
	}

	_, err := BuildAdvancedInvocation(toolRow, req)
	if err == nil {
		t.Fatal("expected missing required input error for ports, got nil")
	}
	if !strings.Contains(err.Error(), `missing required input "ports"`) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBuildAdvancedInvocation_UsesInputSchemaFlagForAnyTool(t *testing.T) {
	toolRow := db.Tool{
		ToolName:    "custom-enumerator",
		ImageRef:    pgtype.Text{String: "example/custom-enumerator:latest", Valid: true},
		InputSchema: []byte(`{"type":"object","fields":[{"key":"target","type":"string","required":true,"flag":"--input"}]}`),
		ScanConfig:  []byte(`{"medium":{"options":[]},"advanced":{"options":[]}}`),
	}

	req := &advancedpb.SubmitScanRequest{
		ToolArgs: map[string]string{
			"target": "example.com",
		},
	}

	plan, err := BuildAdvancedInvocation(toolRow, req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	got := joinArgs(plan.Args)
	want := "--input example.com"
	if got != want {
		t.Fatalf("unexpected args:\nwant: %s\ngot:  %s", want, got)
	}
}

func TestBuildAdvancedInvocation_AppendsPositionalInputWhenFlagMissing(t *testing.T) {
	toolRow := db.Tool{
		ToolName:    "custom-positional",
		ImageRef:    pgtype.Text{String: "example/custom-positional:latest", Valid: true},
		InputSchema: []byte(`{"type":"object","fields":[{"key":"target","type":"string","required":true}]}`),
		ScanConfig:  []byte(`{"medium":{"options":[{"flag":"--mode","key":"mode","type":"string"}]},"advanced":{"options":[]}}`),
	}

	req := &advancedpb.SubmitScanRequest{
		ToolArgs: map[string]string{
			"target": "example.com",
			"mode":   "fast",
		},
	}

	plan, err := BuildAdvancedInvocation(toolRow, req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	got := joinArgs(plan.Args)
	want := "example.com --mode fast"
	if got != want {
		t.Fatalf("unexpected args:\nwant: %s\ngot:  %s", want, got)
	}
}

func TestBuildAdvancedInvocation_PlacesRawCustomFlagsBeforePositionalInputs(t *testing.T) {
	toolRow := db.Tool{
		ToolName:    "subfinder",
		ImageRef:    pgtype.Text{String: "projectdiscovery/subfinder:latest", Valid: true},
		InputSchema: []byte(`{"type":"object","fields":[{"key":"domain","type":"string","required":true}]}`),
		ScanConfig:  []byte(`{"medium":{"options":[]},"advanced":{"options":[]}}`),
	}

	req := &advancedpb.SubmitScanRequest{
		ToolArgs: map[string]string{
			"domain": "scanme.nmap.org",
		},
		CustomFlags: []*advancedpb.CustomFlag{
			{Normalized: "-d"},
		},
	}

	plan, err := BuildAdvancedInvocation(toolRow, req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	got := joinArgs(plan.Args)
	want := "-d scanme.nmap.org"
	if got != want {
		t.Fatalf("unexpected args:\nwant: %s\ngot:  %s", want, got)
	}
}

func TestBuildAdvancedInvocation_UsesNaabuHostFallbackFlag(t *testing.T) {
	toolRow := db.Tool{
		ToolName:    "naabu",
		ImageRef:    pgtype.Text{String: "projectdiscovery/naabu:v2.5.0", Valid: true},
		InputSchema: []byte(`{"type":"object","fields":[{"key":"host","type":"string","required":true}]}`),
		ScanConfig:  []byte(`{"medium":{"options":[]},"advanced":{"options":[]}}`),
	}

	req := &advancedpb.SubmitScanRequest{
		ToolArgs: map[string]string{
			"host": "scanme.nmap.org",
		},
	}

	plan, err := BuildAdvancedInvocation(toolRow, req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	got := joinArgs(plan.Args)
	want := "-host scanme.nmap.org"
	if got != want {
		t.Fatalf("unexpected args:\nwant: %s\ngot:  %s", want, got)
	}
}

func TestBuildAdvancedInvocation_AllowsRequiredInputViaListTransport(t *testing.T) {
	toolRow := db.Tool{
		ToolName:    "naabu",
		ImageRef:    pgtype.Text{String: "projectdiscovery/naabu:v2.5.0", Valid: true},
		InputSchema: []byte(`{"type":"object","fields":[{"key":"host","type":"string","required":true,"flag":"-host"}],"pipeline_input":{"multi_mode":"list_file","list_flag":"-list","target_field":"host"}}`),
		ScanConfig:  []byte(`{"medium":{"options":[]},"advanced":{"options":[]}}`),
	}

	req := &advancedpb.SubmitScanRequest{
		CustomFlags: []*advancedpb.CustomFlag{
			{Normalized: "-list", Value: "/tmp/advanced-scan-inputs/example.txt"},
		},
	}

	plan, err := BuildAdvancedInvocation(toolRow, req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	got := joinArgs(plan.Args)
	want := "-list /tmp/advanced-scan-inputs/example.txt"
	if got != want {
		t.Fatalf("unexpected args:\nwant: %s\ngot:  %s", want, got)
	}
}

func TestBuildAdvancedInvocation_AllowsRequiredInputViaSystemListTransport(t *testing.T) {
	toolRow := db.Tool{
		ToolName:      "naabu",
		ImageRef:      pgtype.Text{String: "projectdiscovery/naabu:v2.5.0", Valid: true},
		InputSchema:   []byte(`{"type":"object","fields":[{"key":"host","type":"string","required":true,"flag":"-host"}],"pipeline_input":{"multi_mode":"list_file","list_flag":"-list","target_field":"host"}}`),
		ScanConfig:    []byte(`{"medium":{"options":[]},"advanced":{"options":[]}}`),
		DeniedOptions: []string{"-list"},
	}

	plan, err := buildAdvancedInvocation(toolRow, &advancedpb.SubmitScanRequest{
		ToolArgs: map[string]string{},
	}, []string{"-list", "/tmp/advanced-scan-inputs/job_step.txt"})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	got := joinArgs(plan.Args)
	if got != "" {
		t.Fatalf("expected no user args before system injection, got %q", got)
	}
}

func joinArgs(args []string) string {
	out := ""
	for i, a := range args {
		if i > 0 {
			out += " "
		}
		out += a
	}
	return out
}

func TestGlobalDeniedSet_BlocksInteractiveFlags(t *testing.T) {
	toolRow := db.Tool{
		ToolName:    "subfinder",
		ImageRef:    pgtype.Text{String: "projectdiscovery/subfinder:latest", Valid: true},
		InputSchema: []byte(`{"type":"object","fields":[{"key":"domain","type":"string","required":true,"flag":"-d"}]}`),
		ScanConfig:  []byte(`{"medium":{"options":[]},"advanced":{"options":[]}}`),
	}

	for _, flag := range []string{"-it", "--interactive", "--tty"} {
		req := &advancedpb.SubmitScanRequest{
			ToolArgs:    map[string]string{"domain": "example.com"},
			CustomFlags: []*advancedpb.CustomFlag{{Normalized: flag}},
		}
		_, err := BuildAdvancedInvocation(toolRow, req)
		if err == nil {
			t.Errorf("expected error for globally denied flag %q, got nil", flag)
		}
	}
}

func TestBuildAdvancedInvocation_AllowsToolDeclaredShortOptionT(t *testing.T) {
	toolRow := db.Tool{
		ToolName:    "subfinder",
		ImageRef:    pgtype.Text{String: "projectdiscovery/subfinder:latest", Valid: true},
		InputSchema: []byte(`{"type":"object","fields":[{"key":"domain","type":"string","required":true,"flag":"-d"}]}`),
		ScanConfig:  []byte(`{"medium":{"options":[{"flag":"-t","key":"threads","type":"integer"}]},"advanced":{"options":[]}}`),
	}

	req := &advancedpb.SubmitScanRequest{
		ToolArgs: map[string]string{
			"domain":  "example.com",
			"threads": "25",
		},
	}

	plan, err := BuildAdvancedInvocation(toolRow, req)
	if err != nil {
		t.Fatalf("expected declared short option -t to be allowed, got error: %v", err)
	}

	want := "-d example.com -t 25"
	if got := joinArgs(plan.Args); got != want {
		t.Fatalf("unexpected args:\nwant: %s\ngot:  %s", want, got)
	}
}

func TestGlobalDeniedSet_BlocksOutputRedirectionFlags(t *testing.T) {
	toolRow := db.Tool{
		ToolName:    "subfinder",
		ImageRef:    pgtype.Text{String: "projectdiscovery/subfinder:latest", Valid: true},
		InputSchema: []byte(`{"type":"object","fields":[{"key":"domain","type":"string","required":true,"flag":"-d"}]}`),
		ScanConfig:  []byte(`{"medium":{"options":[]},"advanced":{"options":[]}}`),
	}

	for _, flag := range []string{"--output", "-o", "--log", "--logfile", "--log-file"} {
		req := &advancedpb.SubmitScanRequest{
			ToolArgs:    map[string]string{"domain": "example.com"},
			CustomFlags: []*advancedpb.CustomFlag{{Normalized: flag}},
		}
		_, err := BuildAdvancedInvocation(toolRow, req)
		if err == nil {
			t.Errorf("expected error for globally denied flag %q, got nil", flag)
		}
	}
}

func TestGlobalDeniedSet_AllowsUppercaseShortFlagWhenLowercaseVariantIsDenied(t *testing.T) {
	toolRow := db.Tool{
		ToolName:    "nmap",
		ImageRef:    pgtype.Text{String: "instrumentisto/nmap:7.98", Valid: true},
		InputSchema: []byte(`{"type":"object","fields":[{"key":"target","type":"string","required":true}]}`),
		ScanConfig:  []byte(`{"medium":{"options":[]},"advanced":{"options":[]}}`),
	}

	req := &advancedpb.SubmitScanRequest{
		ToolArgs: map[string]string{"target": "scanme.nmap.org"},
		CustomFlags: []*advancedpb.CustomFlag{
			{Normalized: "-O"},
		},
	}

	plan, err := BuildAdvancedInvocation(toolRow, req)
	if err != nil {
		t.Fatalf("expected -O to be allowed, got error: %v", err)
	}
	got := joinArgs(plan.Args)
	want := "-O scanme.nmap.org"
	if got != want {
		t.Fatalf("unexpected args:\nwant: %s\ngot:  %s", want, got)
	}
}

func TestGlobalDeniedSet_BlocksDebugProxyFlags(t *testing.T) {
	toolRow := db.Tool{
		ToolName:    "subfinder",
		ImageRef:    pgtype.Text{String: "projectdiscovery/subfinder:latest", Valid: true},
		InputSchema: []byte(`{"type":"object","fields":[{"key":"domain","type":"string","required":true,"flag":"-d"}]}`),
		ScanConfig:  []byte(`{"medium":{"options":[]},"advanced":{"options":[]}}`),
	}

	for _, flag := range []string{"--debug", "--trace", "--proxy", "--upstream-proxy", "--eval", "--execute", "--run", "-e"} {
		req := &advancedpb.SubmitScanRequest{
			ToolArgs:    map[string]string{"domain": "example.com"},
			CustomFlags: []*advancedpb.CustomFlag{{Normalized: flag}},
		}
		_, err := BuildAdvancedInvocation(toolRow, req)
		if err == nil {
			t.Errorf("expected error for globally denied flag %q, got nil", flag)
		}
	}
}

func TestGlobalDeniedSet_RejectsViaInputSchemaFlag(t *testing.T) {
	// If a tool's input_schema maps a field to a globally denied flag, it should be blocked.
	toolRow := db.Tool{
		ToolName:    "custom-tool",
		ImageRef:    pgtype.Text{String: "example/custom:latest", Valid: true},
		InputSchema: []byte(`{"type":"object","fields":[{"key":"target","type":"string","required":true,"flag":"-o"}]}`),
		ScanConfig:  []byte(`{"medium":{"options":[]},"advanced":{"options":[]}}`),
	}

	req := &advancedpb.SubmitScanRequest{
		ToolArgs: map[string]string{"target": "example.com"},
	}
	_, err := BuildAdvancedInvocation(toolRow, req)
	if err == nil {
		t.Fatal("expected error for globally denied input flag -o, got nil")
	}
}

func TestGlobalDeniedSet_RejectsViaScanConfigOption(t *testing.T) {
	// If a tool's scan_config references a globally denied flag, it should be blocked.
	toolRow := db.Tool{
		ToolName:    "custom-tool",
		ImageRef:    pgtype.Text{String: "example/custom:latest", Valid: true},
		InputSchema: []byte(`{"type":"object","fields":[{"key":"target","type":"string","required":true,"flag":"-d"}]}`),
		ScanConfig:  []byte(`{"medium":{"options":[]},"advanced":{"options":[{"flag":"--debug","key":"debug","type":"boolean"}]}}`),
	}

	req := &advancedpb.SubmitScanRequest{
		ToolArgs: map[string]string{"domain": "example.com", "debug": "true"},
	}
	_, err := BuildAdvancedInvocation(toolRow, req)
	if err == nil {
		t.Fatal("expected error for globally denied scan_config option --debug, got nil")
	}
}

func TestGlobalDeniedSet_ErrorMessageIndicatesGlobalDeny(t *testing.T) {
	toolRow := db.Tool{
		ToolName:    "subfinder",
		ImageRef:    pgtype.Text{String: "projectdiscovery/subfinder:latest", Valid: true},
		InputSchema: []byte(`{"type":"object","fields":[{"key":"domain","type":"string","required":true,"flag":"-d"}]}`),
		ScanConfig:  []byte(`{"medium":{"options":[]},"advanced":{"options":[]}}`),
	}

	req := &advancedpb.SubmitScanRequest{
		ToolArgs:    map[string]string{"domain": "example.com"},
		CustomFlags: []*advancedpb.CustomFlag{{Normalized: "--proxy"}},
	}
	_, err := BuildAdvancedInvocation(toolRow, req)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "globally denied") {
		t.Errorf("expected error to contain 'globally denied', got: %v", err)
	}
}
