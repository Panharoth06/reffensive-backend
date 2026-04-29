package advancedscan

import (
	dockerrunner "go-server/docker"
	db "go-server/internal/database/sqlc"
	"time"
)

// ToolOutputClass describes how a tool emits structured output.
type ToolOutputClass int

const (
	ToolOutputClassStdoutJSONL ToolOutputClass = ToolOutputClass(ClassStdoutJSONL)
	ToolOutputClassFileOnly    ToolOutputClass = ToolOutputClass(ClassFileOnly)
)

// PreparedShadowOutput contains the runtime wiring needed before container start.
type PreparedShadowOutput struct {
	Enabled          bool
	Format           string
	Parser           string
	Transport        string
	ContainerPath    string
	HostPath         string
	Volumes          []string
	AddedArgs        []string
	FallbackToStdout bool
	ParseTimeout     time.Duration
}

// CapturedShadowOutput is the structured payload collected after execution.
type CapturedShadowOutput struct {
	Format             string
	Parser             string
	Transport          string
	HostPath           string
	ContainerPath      string
	Content            []byte
	UsedStdoutFallback bool
}

// ParsedFinding is the cross-package view of a parsed finding.
type ParsedFinding struct {
	Severity    db.SeverityLevel
	Title       string
	Host        string
	Port        int32
	Description string
	Metadata    map[string]string
	Fingerprint string
}

// ParsedOutput is the cross-package view of structured parsing results.
type ParsedOutput struct {
	ToolName       string
	ParseMethod    string
	LineCount      int
	FindingsCount  int
	StructuredData []map[string]any
	Findings       []ParsedFinding
}

func ResolveToolOutputClass(toolRow db.Tool) ToolOutputClass {
	return ToolOutputClass(resolveOutputClass(toolRow))
}

func PrepareShadowOutput(toolRow db.Tool, jobID string, stepID string) (PreparedShadowOutput, error) {
	prepared, err := prepareShadowOutput(toolRow, jobID, stepID)
	if err != nil {
		return PreparedShadowOutput{}, err
	}
	return PreparedShadowOutput{
		Enabled:          prepared.Enabled,
		Format:           prepared.Format,
		Parser:           prepared.Parser,
		Transport:        prepared.Transport,
		ContainerPath:    prepared.ContainerPath,
		HostPath:         prepared.HostPath,
		Volumes:          append([]string(nil), prepared.Volumes...),
		AddedArgs:        append([]string(nil), prepared.AddedArgs...),
		FallbackToStdout: prepared.FallbackToStdout,
		ParseTimeout:     prepared.ParseTimeout,
	}, nil
}

func CaptureShadowOutput(prepared PreparedShadowOutput, stdout string) (CapturedShadowOutput, error) {
	captured, err := captureShadowOutput(preparedShadowOutput{
		Enabled:          prepared.Enabled,
		Format:           prepared.Format,
		Parser:           prepared.Parser,
		Transport:        prepared.Transport,
		ContainerPath:    prepared.ContainerPath,
		HostPath:         prepared.HostPath,
		Volumes:          append([]string(nil), prepared.Volumes...),
		AddedArgs:        append([]string(nil), prepared.AddedArgs...),
		FallbackToStdout: prepared.FallbackToStdout,
		ParseTimeout:     prepared.ParseTimeout,
	}, stdout)
	if err != nil {
		return CapturedShadowOutput{}, err
	}
	return CapturedShadowOutput{
		Format:             captured.Format,
		Parser:             captured.Parser,
		Transport:          captured.Transport,
		HostPath:           captured.HostPath,
		ContainerPath:      captured.ContainerPath,
		Content:            append([]byte(nil), captured.Content...),
		UsedStdoutFallback: captured.UsedStdoutFallback,
	}, nil
}

func CanonicalStepOutput(result *dockerrunner.ToolResult, shadow CapturedShadowOutput) string {
	return canonicalStepOutput(result, capturedShadowOutput{
		Format:             shadow.Format,
		Parser:             shadow.Parser,
		Transport:          shadow.Transport,
		HostPath:           shadow.HostPath,
		ContainerPath:      shadow.ContainerPath,
		Content:            shadow.Content,
		UsedStdoutFallback: shadow.UsedStdoutFallback,
	})
}

func ExtractPipelineOutputs(toolRow db.Tool, rawOutput string) []string {
	return extractPipelineOutputs(toolRow, rawOutput)
}

func FormatStructuredLogLine(jsonLine string, toolRow db.Tool) string {
	return formatSSELine(jsonLine, toolRow)
}

func ParseToolOutput(toolRow db.Tool, rawOutput string, lines []string) *ParsedOutput {
	parsed := parseFindingsFromOutput(toolRow, rawOutput, lines)
	if parsed == nil {
		return nil
	}

	findings := make([]ParsedFinding, 0, len(parsed.Findings))
	for _, finding := range parsed.Findings {
		findings = append(findings, ParsedFinding{
			Severity:    finding.Severity,
			Title:       finding.Title,
			Host:        finding.Host,
			Port:        finding.Port,
			Description: finding.Description,
			Metadata:    finding.Metadata,
			Fingerprint: finding.Fingerprint,
		})
	}

	return &ParsedOutput{
		ToolName:       parsed.ToolName,
		ParseMethod:    parsed.ParseMethod,
		LineCount:      parsed.LineCount,
		FindingsCount:  parsed.FindingsCount,
		StructuredData: parsed.StructuredData,
		Findings:       findings,
	}
}

func HighestSeverity(findings []ParsedFinding) db.SeverityLevel {
	internal := make([]parsedFinding, 0, len(findings))
	for _, finding := range findings {
		internal = append(internal, parsedFinding{
			Severity:    finding.Severity,
			Title:       finding.Title,
			Host:        finding.Host,
			Port:        finding.Port,
			Description: finding.Description,
			Metadata:    finding.Metadata,
			Fingerprint: finding.Fingerprint,
		})
	}
	return highestSeverity(internal)
}
