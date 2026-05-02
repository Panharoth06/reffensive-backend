package advancedscan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	dockerrunner "go-server/docker"
	advancedpb "go-server/gen/advanced"
	db "go-server/internal/database/sqlc"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

func (s *advancedScanServer) writeShadowArtifact(
	shadowCfg *advancedpb.ShadowOutputConfig,
	jobID string,
	stepID string,
	toolName string,
	plan *InvocationPlan,
	result *dockerrunner.ToolResult,
	shadow capturedShadowOutput,
	runErr error,
) (string, error) {
	dir := s.artifactRoot
	filename := fmt.Sprintf("%s_%s_%d.json", jobID, stepID, time.Now().UTC().Unix())
	if shadowCfg != nil {
		if stringsTrim(shadowCfg.GetDefaultPath()) != "" {
			dir = shadowCfg.GetDefaultPath()
		}
		if stringsTrim(shadowCfg.GetFilename()) != "" {
			filename = shadowCfg.GetFilename()
		}
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}

	path := filepath.Join(dir, filename)
	artifact := map[string]any{
		"job_id":     jobID,
		"step_id":    stepID,
		"tool_name":  toolName,
		"image_ref":  plan.ImageRef,
		"command":    plan.Command,
		"args":       plan.Args,
		"created_at": time.Now().UTC().Format(time.RFC3339Nano),
	}
	if result != nil {
		artifact["exit_code"] = result.ExitCode
		artifact["stdout"] = result.Stdout
		artifact["stderr"] = result.Stderr
		artifact["duration_ms"] = result.Duration.Milliseconds()
	}
	if len(shadow.Content) > 0 || shadow.HostPath != "" {
		artifact["shadow_output"] = map[string]any{
			"format":               shadow.Format,
			"parser":               shadow.Parser,
			"transport":            shadow.Transport,
			"host_path":            shadow.HostPath,
			"container_path":       shadow.ContainerPath,
			"used_stdout_fallback": shadow.UsedStdoutFallback,
			"content":              string(shadow.Content),
		}
	}
	if runErr != nil {
		artifact["error"] = runErr.Error()
	}

	b, err := json.MarshalIndent(artifact, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		return "", err
	}
	return path, nil
}

// parsedFinding is the internal finding shape before DB insertion.
type parsedFinding struct {
	Severity    db.SeverityLevel
	Title       string
	Host        string
	Port        int32
	Description string
	Metadata    map[string]string
	Fingerprint string
}

// ParserConfig is read from tool JSON at runtime. It defines how to parse
// a tool's output into structured findings without any hardcoded tool logic.
type ParserConfig struct {
	ToolName          string           `json:"-"`    // injected at parse time
	Type              string           `json:"type"` // "jsonl", "json_array", "xml", "lines"
	FieldMappings     FieldMappings    `json:"field_mappings"`
	DefaultSeverity   string           `json:"default_severity"`
	FingerprintFields []string         `json:"fingerprint_fields"`
	InterestingRule   *InterestingRule `json:"interesting_rule,omitempty"`
	DeclaredFields    map[string]bool  `json:"-"` // keys from output_schema.fields; unknown fields go to _extra
}

type FieldMappings struct {
	Title       []string `json:"title,omitempty"`
	Severity    string   `json:"severity,omitempty"`
	Host        []string `json:"host,omitempty"`
	Description []string `json:"description,omitempty"`
	Metadata    []string `json:"metadata,omitempty"`
}

type InterestingRule struct {
	Field     string `json:"field"`
	Condition string `json:"condition"` // "gte", "lte", "eq", "in", "neq"
	Value     any    `json:"value"`
}

// ParsedDataResult holds both structured data rows and extracted findings.
type ParsedDataResult struct {
	ToolName       string
	ParseMethod    string
	LineCount      int
	FindingsCount  int
	StructuredData []map[string]any
	Findings       []parsedFinding
}

func (s *advancedScanServer) persistStepResult(
	spec chainStepSpec,
	stepStatus advancedpb.StepStatus,
	startedAt time.Time,
	finishedAt time.Time,
	plan *InvocationPlan,
	result *dockerrunner.ToolResult,
	shadow capturedShadowOutput,
	runErr error,
) (int32, error) {
	rawPayload := map[string]any{
		"job_id":     spec.JobID,
		"step_id":    spec.StepID,
		"tool_name":  spec.ToolRow.ToolName,
		"image_ref":  plan.ImageRef,
		"command":    plan.Command,
		"args":       plan.Args,
		"created_at": finishedAt.Format(time.RFC3339Nano),
	}
	if result != nil {
		rawPayload["exit_code"] = result.ExitCode
		rawPayload["stdout"] = result.Stdout
		rawPayload["stderr"] = result.Stderr
		rawPayload["duration_ms"] = result.Duration.Milliseconds()
	}
	rawForParsing := canonicalStepOutput(result, shadow)
	if len(shadow.Content) > 0 {
		rawPayload["shadow_output"] = map[string]any{
			"format":               shadow.Format,
			"parser":               shadow.Parser,
			"transport":            shadow.Transport,
			"host_path":            shadow.HostPath,
			"container_path":       shadow.ContainerPath,
			"used_stdout_fallback": shadow.UsedStdoutFallback,
			"content":              string(shadow.Content),
		}
	}
	if runErr != nil {
		rawPayload["error"] = runErr.Error()
	}
	rawData, err := json.Marshal(rawPayload)
	if err != nil {
		return 0, err
	}

	lines := extractPipeLines(rawForParsing)
	parsed := parseFindingsFromOutput(spec.ToolRow, rawForParsing, lines)
	findings := findingsForPersistence(spec.ToolRow, parsed, lines)

	parsedPayload := map[string]any{
		"tool_name":      parsed.ToolName,
		"parse_method":   parsed.ParseMethod,
		"line_count":     parsed.LineCount,
		"findings_count": len(findings),
		"data":           parsed.StructuredData,
	}
	parsedData, err := json.Marshal(parsedPayload)
	if err != nil {
		return 0, err
	}

	severity := db.NullSeverityLevel{Valid: false}
	if len(findings) > 0 {
		highest := highestSeverity(findings)
		severity = db.NullSeverityLevel{
			SeverityLevel: highest,
			Valid:         true,
		}
	}
	startedTS := pgtype.Timestamptz{Time: startedAt, Valid: true}
	finishedTS := pgtype.Timestamptz{Time: finishedAt, Valid: true}
	resultRow, err := s.queries.CreateScanResult(context.Background(), db.CreateScanResultParams{
		StepID:     spec.StepUUID,
		JobID:      spec.JobUUID,
		ProjectID:  spec.ProjectUUID,
		TargetID:   spec.TargetUUID,
		ToolID:     spec.ToolRow.ToolID,
		RawData:    rawData,
		ParsedData: parsedData,
		Severity:   severity,
		Status: db.NullScanStepStatus{
			ScanStepStatus: protoStepStatusToDB(stepStatus),
			Valid:          true,
		},
		StartedAt:  startedTS,
		FinishedAt: finishedTS,
	})
	if err != nil {
		return 0, err
	}

	var upserted int32
	for _, f := range findings {
		hostText := pgtype.Text{}
		if f.Host != "" {
			hostText = pgtype.Text{String: f.Host, Valid: true}
		}
		port := pgtype.Int4{}
		if f.Port > 0 {
			port = pgtype.Int4{Int32: f.Port, Valid: true}
		}
		title := pgtype.Text{}
		if f.Title != "" {
			title = pgtype.Text{String: f.Title, Valid: true}
		}
		fp := pgtype.Text{String: f.Fingerprint, Valid: true}
		if _, err := s.queries.UpsertFinding(context.Background(), db.UpsertFindingParams{
			ProjectID: spec.ProjectUUID,
			JobID:     spec.JobUUID,
			StepID:    spec.StepUUID,
			ToolID:    spec.ToolRow.ToolID,
			Severity: db.NullSeverityLevel{
				SeverityLevel: f.Severity,
				Valid:         true,
			},
			Title:       title,
			Host:        hostText,
			Port:        port,
			Fingerprint: fp,
			RawResultID: pgtype.UUID{Bytes: resultRow.ResultID, Valid: true},
		}); err != nil {
			return upserted, err
		}
		upserted++
	}

	return upserted, nil
}

// persistJSONLShadow is the streaming counterpart of persistStepResult for
// ClassStdoutJSONL tools. Instead of reading from a capturedShadowOutput, it
// works from the []string of raw JSONL lines accumulated during streaming.
func (s *advancedScanServer) persistJSONLShadow(
	ctx context.Context,
	spec chainStepSpec,
	stepStatus advancedpb.StepStatus,
	startedAt time.Time,
	finishedAt time.Time,
	plan *InvocationPlan,
	shadowRows []string, // raw JSONL lines from the fan-out, one per tool result
	exitCode int,
	runErr error,
) (int32, error) {
	// Rebuild the canonical raw output string for the raw_data column.
	rawForParsing := strings.Join(shadowRows, "\n")

	rawPayload := map[string]any{
		"job_id":     spec.JobID,
		"step_id":    spec.StepID,
		"tool_name":  spec.ToolRow.ToolName,
		"image_ref":  plan.ImageRef,
		"command":    plan.Command,
		"args":       plan.Args,
		"exit_code":  exitCode,
		"created_at": finishedAt.Format(time.RFC3339Nano),
		// No "stdout" key — raw JSONL is captured via shadow_rows.
		"shadow_output": map[string]any{
			"transport": "stdout",
			"format":    "jsonl",
			"parser":    "jsonl",
			"row_count": len(shadowRows),
			"content":   rawForParsing,
		},
	}
	if runErr != nil {
		rawPayload["error"] = runErr.Error()
	}
	rawData, err := json.Marshal(rawPayload)
	if err != nil {
		return 0, err
	}

	lines := extractPipeLines(rawForParsing)
	parsed := parseFindingsFromOutput(spec.ToolRow, rawForParsing, lines)
	findings := findingsForPersistence(spec.ToolRow, parsed, lines)

	parsedPayload := map[string]any{
		"tool_name":      parsed.ToolName,
		"parse_method":   parsed.ParseMethod,
		"line_count":     parsed.LineCount,
		"findings_count": len(findings),
		"data":           parsed.StructuredData,
	}
	parsedData, err := json.Marshal(parsedPayload)
	if err != nil {
		return 0, err
	}

	severity := db.NullSeverityLevel{Valid: false}
	if len(findings) > 0 {
		highest := highestSeverity(findings)
		severity = db.NullSeverityLevel{SeverityLevel: highest, Valid: true}
	}
	startedTS := pgtype.Timestamptz{Time: startedAt, Valid: true}
	finishedTS := pgtype.Timestamptz{Time: finishedAt, Valid: true}

	resultRow, err := s.queries.CreateScanResult(ctx, db.CreateScanResultParams{
		StepID:     spec.StepUUID,
		JobID:      spec.JobUUID,
		ProjectID:  spec.ProjectUUID,
		TargetID:   spec.TargetUUID,
		ToolID:     spec.ToolRow.ToolID,
		RawData:    rawData,
		ParsedData: parsedData,
		Severity:   severity,
		Status: db.NullScanStepStatus{
			ScanStepStatus: protoStepStatusToDB(stepStatus),
			Valid:          true,
		},
		StartedAt:  startedTS,
		FinishedAt: finishedTS,
	})
	if err != nil {
		return 0, err
	}

	var upserted int32
	for _, f := range findings {
		hostText := pgtype.Text{}
		if f.Host != "" {
			hostText = pgtype.Text{String: f.Host, Valid: true}
		}
		port := pgtype.Int4{}
		if f.Port > 0 {
			port = pgtype.Int4{Int32: f.Port, Valid: true}
		}
		title := pgtype.Text{}
		if f.Title != "" {
			title = pgtype.Text{String: f.Title, Valid: true}
		}
		fp := pgtype.Text{String: f.Fingerprint, Valid: true}
		if _, err := s.queries.UpsertFinding(ctx, db.UpsertFindingParams{
			ProjectID: spec.ProjectUUID,
			JobID:     spec.JobUUID,
			StepID:    spec.StepUUID,
			ToolID:    spec.ToolRow.ToolID,
			Severity: db.NullSeverityLevel{
				SeverityLevel: f.Severity,
				Valid:         true,
			},
			Title:       title,
			Host:        hostText,
			Port:        port,
			Fingerprint: fp,
			RawResultID: pgtype.UUID{Bytes: resultRow.ResultID, Valid: true},
		}); err != nil {
			return upserted, err
		}
		upserted++
	}

	return upserted, nil
}

// highestSeverity returns the most severe finding level from a slice.
func highestSeverity(findings []parsedFinding) db.SeverityLevel {
	order := map[db.SeverityLevel]int{
		db.SeverityLevelInfo:     0,
		db.SeverityLevelLow:      1,
		db.SeverityLevelMedium:   2,
		db.SeverityLevelHigh:     3,
		db.SeverityLevelCritical: 4,
	}
	highest := db.SeverityLevelInfo
	for _, f := range findings {
		if order[f.Severity] > order[highest] {
			highest = f.Severity
		}
	}
	return highest
}

func findingsForPersistence(toolRow db.Tool, parsed *ParsedDataResult, lines []string) []parsedFinding {
	if parsed != nil && len(parsed.Findings) > 0 {
		return parsed.Findings
	}

	if parsed != nil && len(parsed.StructuredData) > 0 {
		if derived := synthesizeFindingsFromStructuredData(toolRow, parsed.StructuredData); len(derived) > 0 {
			return derived
		}
	}

	if len(lines) == 0 {
		return nil
	}
	cfg := inferParserConfig(toolRow)
	cfg.ToolName = toolRow.ToolName
	cfg.Type = "lines"
	cfg.DefaultSeverity = "SEVERITY_INFO"
	cfg.FingerprintFields = []string{"_line"}
	_, findings := parseLines(lines, cfg)
	return findings
}

func synthesizeFindingsFromStructuredData(toolRow db.Tool, rows []map[string]any) []parsedFinding {
	if len(rows) == 0 {
		return nil
	}

	cfg := inferParserConfig(toolRow)
	cfg.ToolName = toolRow.ToolName
	findings := make([]parsedFinding, 0, len(rows))

	for _, row := range rows {
		if len(row) == 0 {
			continue
		}

		host := resolveFirst(row, cfg.FieldMappings.Host)
		if host == "" {
			host = resolveFirst(row, []string{"host", "host_port", "url", "input", "matched-at", "domain", "ip", "name"})
		}
		host, port := normalizeStructuredHostPort(host, row)

		title := resolveFirst(row, cfg.FieldMappings.Title)
		if title == "" {
			title = resolveFirst(row, []string{"title", "name", "template-id", "url", "input", "host_port", "host", "_line"})
		}
		if title == "" {
			if compact, err := json.Marshal(row); err == nil {
				title = string(compact)
			}
		}
		title = truncate(title, 500)
		if title == "" {
			continue
		}

		severity := db.SeverityLevelInfo
		if cfg.FieldMappings.Severity != "" {
			if raw, ok := row[cfg.FieldMappings.Severity]; ok {
				severity = normalizeSeverity(fmt.Sprint(raw))
			}
		}

		fpParts := []string{cfg.ToolName}
		for _, field := range cfg.FingerprintFields {
			if value := getString(row, field); value != "" {
				fpParts = append(fpParts, value)
			}
		}
		if len(fpParts) == 1 {
			fpParts = append(fpParts, title)
			if host != "" {
				fpParts = append(fpParts, host)
			}
			if port > 0 {
				fpParts = append(fpParts, strconv.Itoa(int(port)))
			}
		}
		sum := sha256.Sum256([]byte(strings.Join(fpParts, "|")))

		findings = append(findings, parsedFinding{
			Severity:    severity,
			Title:       title,
			Host:        host,
			Port:        port,
			Fingerprint: hex.EncodeToString(sum[:]),
		})
	}

	return findings
}

func normalizeStructuredHostPort(host string, row map[string]any) (string, int32) {
	if port := int32FromAny(row["port"]); port > 0 {
		if parsedHost, _, ok := parseSingleHostPortCandidate(host); ok {
			return parsedHost, port
		}
		return host, port
	}

	if parsedHost, parsedPort, ok := parseSingleHostPortCandidate(host); ok {
		return parsedHost, parsedPort
	}

	for _, key := range []string{"url", "input", "matched-at", "host_port"} {
		value := getString(row, key)
		if parsedHost, parsedPort, ok := parseSingleHostPortCandidate(value); ok {
			return parsedHost, parsedPort
		}
	}

	return host, 0
}

func int32FromAny(v any) int32 {
	switch value := v.(type) {
	case int:
		return int32(value)
	case int32:
		return value
	case int64:
		return int32(value)
	case float64:
		return int32(value)
	case json.Number:
		i, err := value.Int64()
		if err != nil {
			return 0
		}
		return int32(i)
	case string:
		n, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil {
			return 0
		}
		return int32(n)
	default:
		return 0
	}
}

// parseFindingsFromOutput parses tool output using the tool's parser_config.
// Falls back to inferred config from output_schema, then to naive line parsing.
func parseFindingsFromOutput(toolRow db.Tool, rawOutput string, lines []string) *ParsedDataResult {
	var cfg ParserConfig

	if len(toolRow.ParserConfig) > 0 {
		if err := json.Unmarshal(toolRow.ParserConfig, &cfg); err == nil {
			cfg.ToolName = toolRow.ToolName
			// Still extract declared fields from output_schema for row filtering.
			cfg.DeclaredFields = extractDeclaredFields(toolRow.OutputSchema)
			return parseWithConfig(rawOutput, lines, cfg)
		}
	}

	cfg = inferParserConfig(toolRow)
	return parseWithConfig(rawOutput, lines, cfg)
}

// inferParserConfig builds a parser config from output_schema when parser_config is missing.
func inferParserConfig(toolRow db.Tool) ParserConfig {
	outputSchema, err := parseOutputSchema(toolRow.OutputSchema)
	if err != nil {
		return ParserConfig{
			ToolName:          toolRow.ToolName,
			Type:              "lines",
			DefaultSeverity:   "SEVERITY_INFO",
			FingerprintFields: []string{"_line"},
		}
	}

	mode := strings.ToLower(stringsTrim(outputSchema.PipelineOutput.Mode))
	extractField := stringsTrim(outputSchema.PipelineOutput.ExtractField)

	cfg := ParserConfig{
		ToolName:        toolRow.ToolName,
		Type:            mode,
		DefaultSeverity: "SEVERITY_INFO",
		DeclaredFields:  make(map[string]bool),
	}
	if extractField != "" {
		cfg.FingerprintFields = []string{extractField}
	} else {
		cfg.FingerprintFields = []string{"_line"}
	}

	var hostFields []string
	for _, f := range outputSchema.Fields {
		if f.FindingHost {
			hostFields = append(hostFields, f.Key)
		}
		if f.FindingTitle {
			cfg.FieldMappings.Title = append(cfg.FieldMappings.Title, f.Key)
		}
		if f.FindingSeverity {
			cfg.FieldMappings.Severity = f.Key
		}
		if f.Key != "" {
			cfg.DeclaredFields[f.Key] = true
		}
	}
	if len(hostFields) > 0 {
		cfg.FieldMappings.Host = hostFields
	}
	if cfg.Type == "" {
		cfg.Type = "lines"
	}
	return cfg
}

// extractDeclaredFields reads output_schema and returns a set of declared field keys.
func extractDeclaredFields(outputSchemaJSON []byte) map[string]bool {
	out := make(map[string]bool)
	schema, err := parseOutputSchema(outputSchemaJSON)
	if err != nil {
		return out
	}
	for _, f := range schema.Fields {
		if f.Key != "" {
			out[f.Key] = true
		}
	}
	return out
}

// filterToDeclaredFields copies only declared keys into a new row.
// Unknown fields are bundled into _extra as a JSON object.
func filterToDeclaredFields(obj map[string]any, declared map[string]bool) map[string]any {
	if len(declared) == 0 {
		return obj // no schema declared; keep all fields
	}

	row := make(map[string]any, len(declared)+1)
	var extra map[string]any

	for key, val := range obj {
		if declared[key] {
			row[key] = val
		} else {
			if extra == nil {
				extra = make(map[string]any)
			}
			extra[key] = val
		}
	}

	if len(extra) > 0 {
		row["_extra"] = extra
	}
	return row
}

// parseWithConfig runs the generic parser based on parser_config.type.
func parseWithConfig(rawOutput string, lines []string, cfg ParserConfig) *ParsedDataResult {
	findings := make([]parsedFinding, 0)
	var structuredData []map[string]any

	switch cfg.Type {
	case "jsonl":
		structuredData, findings = parseJSONL(lines, cfg)
	case "json_array":
		structuredData, findings = parseJSONArray(rawOutput, cfg)
	case "xml":
		structuredData, findings = parseXML(rawOutput, cfg)
	default:
		structuredData, findings = parseLines(lines, cfg)
	}

	return &ParsedDataResult{
		ToolName:       cfg.ToolName,
		ParseMethod:    cfg.Type,
		LineCount:      len(lines),
		FindingsCount:  len(findings),
		StructuredData: structuredData,
		Findings:       findings,
	}
}

// parseJSONL parses newline-delimited JSON output.
func parseJSONL(lines []string, cfg ParserConfig) ([]map[string]any, []parsedFinding) {
	structuredData := make([]map[string]any, 0, len(lines))
	findings := make([]parsedFinding, 0, len(lines))

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || !strings.HasPrefix(trimmed, "{") {
			continue
		}
		var obj map[string]any
		if err := json.Unmarshal([]byte(trimmed), &obj); err != nil {
			continue
		}
		enrichStructuredJSONRow(obj)

		// Filter to declared schema fields; unknown fields go to _extra.
		row := filterToDeclaredFields(obj, cfg.DeclaredFields)
		structuredData = append(structuredData, row)

		// Only create findings if an interesting rule is defined.
		// Recon tools (httpx, subfinder) without interesting_rule produce data only.
		if cfg.InterestingRule != nil && matchesRule(row, *cfg.InterestingRule) {
			findings = append(findings, mapFieldsToFinding(row, cfg))
		}
	}
	return structuredData, findings
}

func enrichStructuredJSONRow(obj map[string]any) {
	hostPortValue := deriveHostPortValue(obj)
	if hostPortValue != "" {
		if _, exists := obj["host_port"]; !exists {
			obj["host_port"] = hostPortValue
		}
		if _, exists := obj["host"]; !exists {
			obj["host"] = hostPortValue
		}
	}
}

// parseJSONArray parses a JSON array output.
func parseJSONArray(rawOutput string, cfg ParserConfig) ([]map[string]any, []parsedFinding) {
	trimmed := strings.TrimSpace(rawOutput)
	if !strings.HasPrefix(trimmed, "[") {
		return nil, nil
	}
	var arr []map[string]any
	if err := json.Unmarshal([]byte(trimmed), &arr); err != nil {
		return nil, nil
	}
	if len(arr) == 0 {
		return nil, nil
	}

	findings := make([]parsedFinding, 0, len(arr))
	structuredData := make([]map[string]any, 0, len(arr))
	for _, obj := range arr {
		// Filter to declared schema fields; unknown fields go to _extra.
		row := filterToDeclaredFields(obj, cfg.DeclaredFields)
		structuredData = append(structuredData, row)

		if cfg.InterestingRule == nil || matchesRule(row, *cfg.InterestingRule) {
			findings = append(findings, mapFieldsToFinding(row, cfg))
		}
	}
	return structuredData, findings
}

// parseXML parses XML output (nmap-style).
func parseXML(rawOutput string, cfg ParserConfig) ([]map[string]any, []parsedFinding) {
	// For nmap XML, use the existing dedicated parser
	if strings.EqualFold(cfg.ToolName, "nmap") {
		return tryParseXMLToStructured(rawOutput)
	}
	return nil, nil
}

// parseLines handles plain text output line by line.
func parseLines(lines []string, cfg ParserConfig) ([]map[string]any, []parsedFinding) {
	structuredData := make([]map[string]any, 0, len(lines))
	findings := make([]parsedFinding, 0, len(lines))

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		obj := map[string]any{"_line": trimmed}

		// For line-mode tools, there is no output_schema to filter against.
		// If declared fields exist but don't include "_line", we still keep it.
		row := filterToDeclaredFields(obj, cfg.DeclaredFields)
		structuredData = append(structuredData, row)

		host, port := parseHostPort(trimmed)
		fpParts := []string{cfg.ToolName}
		for _, field := range cfg.FingerprintFields {
			if field == "_line" {
				fpParts = append(fpParts, trimmed)
			}
		}
		if len(fpParts) < 2 {
			fpParts = append(fpParts, trimmed)
		}
		sum := sha256.Sum256([]byte(strings.Join(fpParts, "|")))

		findings = append(findings, parsedFinding{
			Severity:    normalizeSeverity(cfg.DefaultSeverity),
			Title:       truncate(trimmed, 500),
			Host:        host,
			Port:        port,
			Fingerprint: hex.EncodeToString(sum[:]),
		})
	}
	return structuredData, findings
}

// mapFieldsToFinding builds a parsedFinding from a JSON object using field_mappings.
func mapFieldsToFinding(obj map[string]any, cfg ParserConfig) parsedFinding {
	title := resolveFirst(obj, cfg.FieldMappings.Title)
	if title == "" {
		title = resolveFirst(obj, cfg.FieldMappings.Host)
	}
	title = truncate(title, 500)

	host := resolveFirst(obj, cfg.FieldMappings.Host)

	severity := normalizeSeverity(cfg.DefaultSeverity)
	if cfg.FieldMappings.Severity != "" {
		if raw, ok := obj[cfg.FieldMappings.Severity]; ok {
			severity = normalizeSeverity(fmt.Sprint(raw))
		}
	}

	metadata := make(map[string]string)
	for _, key := range cfg.FieldMappings.Metadata {
		if v, ok := obj[key]; ok {
			metadata[key] = fmt.Sprint(v)
		}
	}

	fpParts := []string{cfg.ToolName}
	for _, field := range cfg.FingerprintFields {
		fpParts = append(fpParts, getString(obj, field))
	}
	sum := sha256.Sum256([]byte(strings.Join(fpParts, "|")))

	return parsedFinding{
		Severity:    severity,
		Title:       title,
		Host:        host,
		Fingerprint: hex.EncodeToString(sum[:]),
		Metadata:    metadata,
	}
}

// matchesRule checks if a JSON object matches an interesting rule.
func matchesRule(obj map[string]any, rule InterestingRule) bool {
	raw, ok := obj[rule.Field]
	if !ok {
		return false
	}
	switch rule.Condition {
	case "eq":
		return fmt.Sprint(raw) == fmt.Sprint(rule.Value)
	case "neq":
		return fmt.Sprint(raw) != fmt.Sprint(rule.Value)
	case "gte":
		num, err := toFloat(raw)
		return err == nil && num >= toFloatSafe(rule.Value)
	case "lte":
		num, err := toFloat(raw)
		return err == nil && num <= toFloatSafe(rule.Value)
	case "in":
		if arr, ok := rule.Value.([]any); ok {
			strVal := fmt.Sprint(raw)
			for _, item := range arr {
				if fmt.Sprint(item) == strVal {
					return true
				}
			}
		}
		return false
	}
	return false
}

// Helpers

func resolveFirst(obj map[string]any, keys []string) string {
	for _, key := range keys {
		if v, ok := obj[key]; ok && v != nil {
			s := strings.TrimSpace(fmt.Sprint(v))
			if s != "" && s != "<nil>" {
				return s
			}
		}
	}
	return ""
}

func getString(obj map[string]any, key string) string {
	if v, ok := obj[key]; ok && v != nil {
		return fmt.Sprint(v)
	}
	return ""
}

func truncate(s string, max int) string {
	if len(s) > max {
		return s[:max]
	}
	return s
}

func normalizeSeverity(raw string) db.SeverityLevel {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "critical", "crit":
		return db.SeverityLevelCritical
	case "high", "h":
		return db.SeverityLevelHigh
	case "medium", "med", "moderate":
		return db.SeverityLevelMedium
	case "low", "l":
		return db.SeverityLevelLow
	default:
		return db.SeverityLevelInfo
	}
}

func toFloat(v any) (float64, error) {
	switch n := v.(type) {
	case float64:
		return n, nil
	case int:
		return float64(n), nil
	case int64:
		return float64(n), nil
	case string:
		return strconv.ParseFloat(n, 64)
	default:
		return 0, fmt.Errorf("cannot convert to float")
	}
}

func toFloatSafe(v any) float64 {
	f, _ := toFloat(v)
	return f
}

// tryParseXMLToStructured parses nmap XML into structured data + findings.
func tryParseXMLToStructured(rawOutput string) ([]map[string]any, []parsedFinding) {
	var run nmapRun
	if err := xml.Unmarshal([]byte(rawOutput), &run); err != nil {
		return nil, nil
	}
	if len(run.Hosts) == 0 {
		return nil, nil
	}

	structuredData := make([]map[string]any, 0)
	findings := make([]parsedFinding, 0)

	for _, host := range run.Hosts {
		hostValue := ""
		for _, hostname := range host.Hostnames {
			if stringsTrim(hostname.Name) != "" {
				hostValue = hostname.Name
				break
			}
		}
		if hostValue == "" {
			for _, address := range host.Addresses {
				if stringsTrim(address.Addr) != "" {
					hostValue = address.Addr
					break
				}
			}
		}
		for _, port := range host.Ports {
			if !strings.EqualFold(stringsTrim(port.State.State), "open") {
				continue
			}
			serviceName := ""
			if port.Service != nil {
				serviceName = port.Service.Name
			}

			obj := map[string]any{
				"host":    hostValue,
				"port":    port.PortID,
				"state":   port.State.State,
				"service": serviceName,
			}
			structuredData = append(structuredData, obj)

			title := fmt.Sprintf("Open port %d", port.PortID)
			if port.Service != nil {
				parts := make([]string, 0, 3)
				if stringsTrim(port.Service.Name) != "" {
					parts = append(parts, port.Service.Name)
				}
				if stringsTrim(port.Service.Product) != "" {
					parts = append(parts, port.Service.Product)
				}
				if stringsTrim(port.Service.Version) != "" {
					parts = append(parts, port.Service.Version)
				}
				if len(parts) > 0 {
					title = fmt.Sprintf("%s on port %d", strings.Join(parts, " "), port.PortID)
				}
			}
			fpSource := fmt.Sprintf("nmap|%s|%d|%s", hostValue, port.PortID, title)
			sum := sha256.Sum256([]byte(fpSource))

			findings = append(findings, parsedFinding{
				Severity:    db.SeverityLevelInfo,
				Title:       title,
				Host:        hostValue,
				Port:        port.PortID,
				Fingerprint: hex.EncodeToString(sum[:]),
			})
		}
	}
	if len(findings) == 0 {
		return nil, nil
	}
	return structuredData, findings
}

// nmap XML structs

type nmapRun struct {
	Hosts []nmapHost `xml:"host"`
}

type nmapHost struct {
	Addresses []nmapAddress `xml:"address"`
	Hostnames []nmapName    `xml:"hostnames>hostname"`
	Ports     []nmapPort    `xml:"ports>port"`
}

type nmapAddress struct {
	Addr string `xml:"addr,attr"`
	Type string `xml:"addrtype,attr"`
}

type nmapName struct {
	Name string `xml:"name,attr"`
}

type nmapPort struct {
	PortID  int32            `xml:"portid,attr"`
	State   nmapPortState    `xml:"state"`
	Service *nmapPortService `xml:"service"`
}

type nmapPortState struct {
	State string `xml:"state,attr"`
}

type nmapPortService struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr"`
	Version string `xml:"version,attr"`
}

func parseHostPort(line string) (string, int32) {
	trimmed := stringsTrim(line)
	if trimmed == "" {
		return "", 0
	}

	if host, port, ok := parseSingleHostPortCandidate(trimmed); ok {
		return host, port
	}

	fields := strings.Fields(trimmed)
	if len(fields) > 1 {
		if host, port, ok := parseSingleHostPortCandidate(strings.Trim(fields[0], `"'`)); ok {
			return host, port
		}
		return strings.Trim(fields[0], `"'`), 0
	}

	return trimmed, 0
}

func parseSingleHostPortCandidate(candidate string) (string, int32, bool) {
	candidate = stringsTrim(candidate)
	if candidate == "" {
		return "", 0, false
	}
	if strings.ContainsAny(candidate, " \t") {
		return "", 0, false
	}

	if u, err := url.Parse(candidate); err == nil && u.Host != "" {
		host := u.Hostname()
		portText := u.Port()
		if portText == "" {
			return host, 0, true
		}
		port, err := strconv.Atoi(portText)
		if err != nil {
			return host, 0, true
		}
		return host, int32(port), true
	}

	host, portText, err := net.SplitHostPort(candidate)
	if err != nil {
		if candidate != "" {
			return candidate, 0, true
		}
		return "", 0, false
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return host, 0, true
	}
	return host, int32(port), true
}

func (s *advancedScanServer) syncStepTerminalStatusToDB(stepUUID uuid.UUID, status advancedpb.StepStatus) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := s.queries.FinishScanStep(ctx, db.FinishScanStepParams{
		StepID: stepUUID,
		Status: db.NullScanStepStatus{
			ScanStepStatus: protoStepStatusToDB(status),
			Valid:          true,
		},
	})
	return err
}

func (s *advancedScanServer) syncJobStatusToDB(jobID string) {
	jobUUID, err := uuid.Parse(jobID)
	if err != nil {
		return
	}
	s.mu.RLock()
	job, ok := s.jobs[jobID]
	if !ok {
		s.mu.RUnlock()
		return
	}
	status := job.Status
	s.mu.RUnlock()

	dbStatus := db.NullScanJobStatus{
		ScanJobStatus: protoJobStatusToDB(status),
		Valid:         true,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if isTerminalJobStatus(status) {
		_, _ = s.queries.FinishScanJob(ctx, db.FinishScanJobParams{
			JobID:  jobUUID,
			Status: dbStatus,
		})
		return
	}
	_, _ = s.queries.UpdateScanJobStatus(ctx, db.UpdateScanJobStatusParams{
		JobID:  jobUUID,
		Status: dbStatus,
	})
}

func requestExecutionModeToDB(mode advancedpb.ExecutionMode) db.ExecutionMode {
	switch mode {
	case advancedpb.ExecutionMode_EXECUTION_MODE_CICD:
		return db.ExecutionModeCicd
	case advancedpb.ExecutionMode_EXECUTION_MODE_CLI:
		return db.ExecutionModeCli
	case advancedpb.ExecutionMode_EXECUTION_MODE_WEB:
		return db.ExecutionModeWeb
	default:
		return db.ExecutionModeWeb
	}
}

func protoStepStatusToDB(status advancedpb.StepStatus) db.ScanStepStatus {
	switch status {
	case advancedpb.StepStatus_STEP_STATUS_COMPLETED:
		return db.ScanStepStatusCompleted
	case advancedpb.StepStatus_STEP_STATUS_SKIPPED:
		return db.ScanStepStatusSkipped
	case advancedpb.StepStatus_STEP_STATUS_RUNNING:
		return db.ScanStepStatusRunning
	case advancedpb.StepStatus_STEP_STATUS_QUEUED, advancedpb.StepStatus_STEP_STATUS_PENDING:
		return db.ScanStepStatusPending
	default:
		return db.ScanStepStatusFailed
	}
}

func protoJobStatusToDB(status advancedpb.JobStatus) db.ScanJobStatus {
	switch status {
	case advancedpb.JobStatus_JOB_STATUS_COMPLETED:
		return db.ScanJobStatusCompleted
	case advancedpb.JobStatus_JOB_STATUS_RUNNING:
		return db.ScanJobStatusRunning
	case advancedpb.JobStatus_JOB_STATUS_PENDING:
		return db.ScanJobStatusPending
	default:
		return db.ScanJobStatusFailed
	}
}

func isTerminalJobStatus(status advancedpb.JobStatus) bool {
	switch status {
	case advancedpb.JobStatus_JOB_STATUS_COMPLETED,
		advancedpb.JobStatus_JOB_STATUS_FAILED,
		advancedpb.JobStatus_JOB_STATUS_CANCELLED,
		advancedpb.JobStatus_JOB_STATUS_PARTIAL:
		return true
	default:
		return false
	}
}

func protoSeverityToDB(severity advancedpb.Severity) db.NullSeverityLevel {
	switch severity {
	case advancedpb.Severity_SEVERITY_INFO:
		return db.NullSeverityLevel{SeverityLevel: db.SeverityLevelInfo, Valid: true}
	case advancedpb.Severity_SEVERITY_LOW:
		return db.NullSeverityLevel{SeverityLevel: db.SeverityLevelLow, Valid: true}
	case advancedpb.Severity_SEVERITY_MEDIUM:
		return db.NullSeverityLevel{SeverityLevel: db.SeverityLevelMedium, Valid: true}
	case advancedpb.Severity_SEVERITY_HIGH:
		return db.NullSeverityLevel{SeverityLevel: db.SeverityLevelHigh, Valid: true}
	case advancedpb.Severity_SEVERITY_CRITICAL:
		return db.NullSeverityLevel{SeverityLevel: db.SeverityLevelCritical, Valid: true}
	default:
		return db.NullSeverityLevel{Valid: false}
	}
}

func dbSeverityToProto(severity db.NullSeverityLevel) advancedpb.Severity {
	if !severity.Valid {
		return advancedpb.Severity_SEVERITY_UNSPECIFIED
	}
	switch severity.SeverityLevel {
	case db.SeverityLevelInfo:
		return advancedpb.Severity_SEVERITY_INFO
	case db.SeverityLevelLow:
		return advancedpb.Severity_SEVERITY_LOW
	case db.SeverityLevelMedium:
		return advancedpb.Severity_SEVERITY_MEDIUM
	case db.SeverityLevelHigh:
		return advancedpb.Severity_SEVERITY_HIGH
	case db.SeverityLevelCritical:
		return advancedpb.Severity_SEVERITY_CRITICAL
	default:
		return advancedpb.Severity_SEVERITY_UNSPECIFIED
	}
}

func buildStepKey(order int, toolName string) string {
	base := strings.ToLower(stringsTrim(toolName))
	if base == "" {
		base = "step"
	}
	var b strings.Builder
	lastDash := false
	for _, r := range base {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			b.WriteByte('-')
			lastDash = true
		}
	}
	clean := strings.Trim(b.String(), "-")
	if clean == "" {
		clean = "step"
	}
	if len(clean) > 40 {
		clean = clean[:40]
	}
	return fmt.Sprintf("%02d_%s", order, clean)
}
