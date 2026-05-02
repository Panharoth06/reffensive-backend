package advancedscan

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	dockerrunner "go-server/docker"
	db "go-server/internal/database/sqlc"
)

func TestParseFindingsFromOutput_NmapXML(t *testing.T) {
	t.Parallel()

	raw := `
<nmaprun>
  <host>
    <hostnames>
      <hostname name="scanme.nmap.org"></hostname>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"></state>
        <service name="http" product="Apache httpd" version="2.4.7"></service>
      </port>
      <port protocol="tcp" portid="443">
        <state state="closed"></state>
      </port>
    </ports>
  </host>
</nmaprun>`

	parserCfg, _ := json.Marshal(ParserConfig{
		Type:              "xml",
		DefaultSeverity:   "SEVERITY_INFO",
		FingerprintFields: []string{"host", "port", "service"},
	})

	toolRow := db.Tool{
		ToolName:     "nmap",
		ParserConfig: parserCfg,
	}

	parsed := parseFindingsFromOutput(toolRow, raw, nil)
	if parsed.ParseMethod != "xml" {
		t.Fatalf("expected xml parse method, got %q", parsed.ParseMethod)
	}
	if len(parsed.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(parsed.Findings))
	}
	if parsed.Findings[0].Host != "scanme.nmap.org" {
		t.Fatalf("unexpected host: %q", parsed.Findings[0].Host)
	}
	if parsed.Findings[0].Port != 80 {
		t.Fatalf("unexpected port: %d", parsed.Findings[0].Port)
	}
}

func TestParseFindingsFromOutput_NucleiJSONL(t *testing.T) {
	t.Parallel()

	raw := `{"template-id":"cve-2024-1234","name":"SQL Injection","severity":"high","matched-at":"https://x.com/login","description":"SQLi detected"}`
	lines := []string{raw}

	parserCfg, _ := json.Marshal(ParserConfig{
		Type: "jsonl",
		FieldMappings: FieldMappings{
			Title:       []string{"template-id", "name"},
			Severity:    "severity",
			Host:        []string{"matched-at", "host"},
			Description: []string{"description"},
		},
		DefaultSeverity:   "SEVERITY_MEDIUM",
		FingerprintFields: []string{"template-id", "matched-at", "name"},
		InterestingRule: &InterestingRule{
			Field:     "template-id",
			Condition: "neq",
			Value:     "",
		},
	})

	toolRow := db.Tool{
		ToolName:     "nuclei",
		ParserConfig: parserCfg,
	}

	parsed := parseFindingsFromOutput(toolRow, raw, lines)
	if parsed.ParseMethod != "jsonl" {
		t.Fatalf("expected jsonl parse method, got %q", parsed.ParseMethod)
	}
	if len(parsed.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(parsed.Findings))
	}
	if parsed.Findings[0].Title != "cve-2024-1234" {
		t.Fatalf("expected title cve-2024-1234, got %q", parsed.Findings[0].Title)
	}
}

func TestParseFindingsFromOutput_InferredFromSchema(t *testing.T) {
	t.Parallel()

	raw := `{"host":"api.example.com","sources":["crtsh"]}`
	lines := []string{raw}

	// No parser_config — should infer from output_schema
	outputSchema, _ := json.Marshal(outputSchemaSpec{
		PipelineOutput: pipelineOutputTransportSpec{
			Mode:         "jsonl",
			ExtractField: "host",
		},
		Fields: []outputFieldSpec{
			{Key: "host", Type: "string", FindingHost: true, PipelineExtract: true},
			{Key: "sources", Type: "array"},
		},
	})

	toolRow := db.Tool{
		ToolName:     "subfinder",
		OutputSchema: outputSchema,
	}

	parsed := parseFindingsFromOutput(toolRow, raw, lines)
	if parsed.ParseMethod != "jsonl" {
		t.Fatalf("expected jsonl parse method, got %q", parsed.ParseMethod)
	}
	// Subfinder is recon — no interesting_rule means data only, no findings
	if len(parsed.Findings) != 0 {
		t.Fatalf("expected 0 findings for recon tool, got %d", len(parsed.Findings))
	}
	if len(parsed.StructuredData) != 1 {
		t.Fatalf("expected 1 data row, got %d", len(parsed.StructuredData))
	}
	if parsed.StructuredData[0]["host"] != "api.example.com" {
		t.Fatalf("unexpected data host: %v", parsed.StructuredData[0]["host"])
	}
}

func TestParseHostPort_UsesFirstTokenForDecoratedOutput(t *testing.T) {
	t.Parallel()

	host, port := parseHostPort("https://alive.example.com:8443 [200] [nginx]")
	if host != "alive.example.com" {
		t.Fatalf("unexpected host: %q", host)
	}
	if port != 8443 {
		t.Fatalf("unexpected port: %d", port)
	}
}

func TestCanonicalStepOutput_PrefersStructuredShadowContent(t *testing.T) {
	t.Parallel()

	result := &dockerrunner.ToolResult{
		Stdout:   "plain stdout",
		Duration: time.Second,
	}
	shadow := capturedShadowOutput{
		Content: []byte(`{"host":"api.example.com"}`),
	}

	got := canonicalStepOutput(result, shadow)
	if got != `{"host":"api.example.com"}` {
		t.Fatalf("unexpected canonical output: %q", got)
	}
}

func TestFindingsForPersistence_SynthesizesStructuredRowsWithoutInterestingRule(t *testing.T) {
	t.Parallel()

	outputSchema, _ := json.Marshal(outputSchemaSpec{
		PipelineOutput: pipelineOutputTransportSpec{
			Mode:         "jsonl",
			ExtractField: "host",
		},
		Fields: []outputFieldSpec{
			{Key: "host", Type: "string", FindingHost: true, PipelineExtract: true},
			{Key: "sources", Type: "array"},
		},
	})

	toolRow := db.Tool{
		ToolName:     "subfinder",
		OutputSchema: outputSchema,
	}

	parsed := &ParsedDataResult{
		ToolName:    "subfinder",
		ParseMethod: "jsonl",
		LineCount:   1,
		StructuredData: []map[string]any{
			{
				"host":    "api.example.com",
				"sources": []any{"crtsh"},
			},
		},
	}

	findings := findingsForPersistence(toolRow, parsed, []string{`{"host":"api.example.com","sources":["crtsh"]}`})
	if len(findings) != 1 {
		t.Fatalf("expected 1 synthesized finding, got %d", len(findings))
	}
	if findings[0].Host != "api.example.com" {
		t.Fatalf("unexpected host: %q", findings[0].Host)
	}
	if findings[0].Title != "api.example.com" {
		t.Fatalf("unexpected title: %q", findings[0].Title)
	}
	if findings[0].Severity != db.SeverityLevelInfo {
		t.Fatalf("unexpected severity: %q", findings[0].Severity)
	}
	if findings[0].Fingerprint == "" {
		t.Fatal("expected synthesized fingerprint")
	}
}

func TestFindingsForPersistence_PrefersParsedFindingsWhenPresent(t *testing.T) {
	t.Parallel()

	toolRow := db.Tool{ToolName: "nuclei"}
	expected := parsedFinding{
		Severity:    db.SeverityLevelHigh,
		Title:       "SQL Injection",
		Host:        "https://target.example.com",
		Fingerprint: "abc123",
	}
	parsed := &ParsedDataResult{
		ToolName:      "nuclei",
		ParseMethod:   "jsonl",
		LineCount:     1,
		FindingsCount: 1,
		StructuredData: []map[string]any{
			{"host": "https://target.example.com"},
		},
		Findings: []parsedFinding{expected},
	}

	findings := findingsForPersistence(toolRow, parsed, []string{`{"host":"https://target.example.com"}`})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if !reflect.DeepEqual(findings[0], expected) {
		t.Fatalf("unexpected finding: %#v", findings[0])
	}
}
