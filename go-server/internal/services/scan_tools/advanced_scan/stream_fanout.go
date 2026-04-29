package advancedscan

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	dockerrunner "go-server/docker"
	advancedpb "go-server/gen/advanced"
	db "go-server/internal/database/sqlc"
)

// toolOutputClass describes how a tool delivers its structured output.
type toolOutputClass int

const (
	// ClassStdoutJSONL — tool emits JSONL on stdout (subfinder, httpx, nuclei, katana …).
	// shadow_output_config.formats[preferred].transport == "stdout"
	// Fan-out happens in Go: SSE gets the extracted field, DB gets raw JSONL, pipe gets extracted field.
	ClassStdoutJSONL toolOutputClass = iota

	// ClassFileOnly — tool writes structured output to a file flag (-oX, -oJ …) and emits
	// human log lines on stdout.
	// shadow_output_config.formats[preferred].transport == "file"
	// Stdout is streamed to SSE as-is; shadow file is read after container exits.
	ClassFileOnly
)

// resolveOutputClass reads shadow_output_config to decide the output class.
func resolveOutputClass(toolRow db.Tool) toolOutputClass {
	cfg, err := parseShadowOutputConfig(toolRow.ShadowOutputConfig)
	if err != nil || stringsTrim(cfg.PreferredFormat) == "" {
		return ClassFileOnly
	}
	format, ok := cfg.Formats[cfg.PreferredFormat]
	if !ok {
		return ClassFileOnly
	}
	if strings.ToLower(stringsTrim(format.Transport)) == "stdout" {
		return ClassStdoutJSONL
	}
	return ClassFileOnly
}

// stdoutJSONLResult is returned by runStdoutJSONLStep.
type stdoutJSONLResult struct {
	ExitCode   int
	ShadowRows []string // raw JSONL lines collected during streaming
	PipeLines  []string // extracted pipeline values (deduplicated)
	Duration   time.Duration
}

// runStdoutJSONLStep handles ClassStdoutJSONL tools.
//
// One stdout read → three simultaneous fan-out targets:
//   - SSE:       human-readable extracted value (e.g. "api.example.com")
//   - shadowBuf: raw JSONL line for DB persistence
//   - pipeLines: extracted value for the next step's input
//
// stderr lines are forwarded to SSE as LOG_SOURCE_STDERR in real time.
func (s *advancedScanServer) runStdoutJSONLStep(
	ctx context.Context,
	spec chainStepSpec,
	plan *InvocationPlan,
	prepared preparedShadowOutput,
	timeout time.Duration,
	memoryLimit int64,
	cpuQuota int64,
	useGVisor bool,
	networkMode string,
	privileged bool,
	runtimeCapabilities []string,
	pipelineFiles []dockerrunner.ContainerFile,
) (*stdoutJSONLResult, error) {
	stepID := spec.StepID
	toolName := spec.ToolRow.ToolName

	// Resolve the JSON field to extract for SSE + pipe (from output_schema.pipeline_output.extract_field).
	extractField := resolveExtractField(spec.ToolRow)

	// Deduplication state for pipe lines.
	seenPipe := make(map[string]struct{})

	var (
		shadowRows []string
		pipeLines  []string
	)

	startTime := time.Now()

	exitCode, err := s.runner.RunStreamed(ctx, dockerrunner.ToolConfig{
		Image:           plan.ImageRef,
		Command:         plan.Command,
		Args:            plan.Args,
		Files:           pipelineFiles,
		Volumes:         prepared.Volumes,
		ImagePullPolicy: imagePullPolicyFromSource(spec.ToolRow.ImageSource.String),
		Timeout:         timeout,
		UseGVisor:       useGVisor,
		NetworkMode:     networkMode,
		Privileged:      privileged,
		CapAdd:          runtimeCapabilities,
		MemoryLimit:     memoryLimit,
		CPUQuota:        cpuQuota,
	}, dockerrunner.StreamedCallbacks{
		OnStdoutLine: func(line string) {
			line = strings.TrimSpace(line)
			if line == "" || !strings.HasPrefix(line, "{") {
				// Non-JSON stdout line: emit to SSE as a system log so the user sees it.
				s.publishLog(stepID, toolName, advancedpb.LogSource_LOG_SOURCE_STDOUT, line)

				// Some tools (or tool presets) still emit plain text on stdout even when
				// configured as ClassStdoutJSONL. Capture lines that look like real
				// results (hosts/URLs) so they are persisted and queryable later.
				if captured := capturePlainStdoutResultLine(line); captured != "" {
					shadowRows = append(shadowRows, captured)
					if _, dup := seenPipe[captured]; !dup {
						seenPipe[captured] = struct{}{}
						pipeLines = append(pipeLines, captured)
					}
				}
				return
			}

			// Extract the pipeline field for pipe passthrough.
			extracted := extractJSONLineField(line, extractField)

			// --- Fan-out ---

			// 1. SSE: terminal-formatted line so the user sees exactly what a real
			//    terminal would show — primary value followed by [field] brackets for
			//    every non-empty secondary field that was actually returned by the tool.
			//    e.g. "https://apply.cadt.edu.kh [200] [Bootstrap:5,jQuery:3.6]"
			sseValue := formatSSELine(line, spec.ToolRow)
			if sseValue == "" {
				sseValue = extracted
			}
			if sseValue == "" {
				sseValue = line // last-resort: raw JSON
			}
			s.publishLog(stepID, toolName, advancedpb.LogSource_LOG_SOURCE_STDOUT, sseValue)

			// 2. Shadow buffer: accumulate raw JSONL for DB.
			shadowRows = append(shadowRows, line)

			// 3. Pipe: deduplicated extracted values for the next step.
			if extracted != "" {
				if _, dup := seenPipe[extracted]; !dup {
					seenPipe[extracted] = struct{}{}
					pipeLines = append(pipeLines, extracted)
				}
			}
		},
		OnStderrLine: func(line string) {
			s.publishLog(stepID, toolName, advancedpb.LogSource_LOG_SOURCE_STDERR, line)
		},
	})

	duration := time.Since(startTime)

	return &stdoutJSONLResult{
		ExitCode:   exitCode,
		ShadowRows: shadowRows,
		PipeLines:  pipeLines,
		Duration:   duration,
	}, err
}

func capturePlainStdoutResultLine(line string) string {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return ""
	}

	// Use the first token to avoid persisting decoration like "[200] [nginx]".
	fields := strings.Fields(trimmed)
	if len(fields) == 0 {
		return ""
	}
	token := strings.Trim(fields[0], `"'`)
	if token == "" {
		return ""
	}

	if strings.HasPrefix(token, "[") {
		// Allow bracketed IPv6 like "[2001:db8::1]" (and ignore non-IP tags like "[INF]").
		closeIdx := strings.Index(token, "]")
		if closeIdx > 1 {
			inner := token[1:closeIdx]
			if ip := net.ParseIP(inner); ip != nil {
				return inner
			}
		}
		// Skip common progress prefixes like "[INF]".
		return ""
	}

	if u, err := url.Parse(token); err == nil && u.Host != "" {
		return token
	}

	// Strip bracketed formatting.
	hostLike := strings.Trim(token, "[]")
	if ip := net.ParseIP(hostLike); ip != nil {
		return hostLike
	}

	// Basic hostname heuristic: must contain a dot (e.g. "api.example.com").
	if strings.Contains(hostLike, ".") && !strings.ContainsAny(hostLike, " \t\r\n") {
		return hostLike
	}

	return ""
}

// fileOnlyResult is returned by runFileOnlyStep.
type fileOnlyResult struct {
	DockerResult *dockerrunner.ToolResult
	Shadow       capturedShadowOutput
}

// runFileOnlyStep handles ClassFileOnly tools (nmap, masscan, gobuster -oX …).
//
// Stdout is piped to SSE as raw human log lines.
// After the container exits, the shadow file (bind-mounted) is read and parsed.
func (s *advancedScanServer) runFileOnlyStep(
	ctx context.Context,
	spec chainStepSpec,
	plan *InvocationPlan,
	prepared preparedShadowOutput,
	timeout time.Duration,
	memoryLimit int64,
	cpuQuota int64,
	useGVisor bool,
	networkMode string,
	privileged bool,
	runtimeCapabilities []string,
	pipelineFiles []dockerrunner.ContainerFile,
) (*fileOnlyResult, error) {
	stepID := spec.StepID
	toolName := spec.ToolRow.ToolName

	result, runErr := s.runner.Run(ctx, dockerrunner.ToolConfig{
		Image:           plan.ImageRef,
		Command:         plan.Command,
		Args:            plan.Args,
		Files:           pipelineFiles,
		Volumes:         prepared.Volumes,
		ImagePullPolicy: imagePullPolicyFromSource(spec.ToolRow.ImageSource.String),
		Timeout:         timeout,
		UseGVisor:       useGVisor,
		NetworkMode:     networkMode,
		Privileged:      privileged,
		CapAdd:          runtimeCapabilities,
		MemoryLimit:     memoryLimit,
		CPUQuota:        cpuQuota,
		OnLog: func(source, line string) {
			switch source {
			case "stderr":
				s.publishLog(stepID, toolName, advancedpb.LogSource_LOG_SOURCE_STDERR, line)
			default:
				s.publishLog(stepID, toolName, advancedpb.LogSource_LOG_SOURCE_STDOUT, line)
			}
		},
	})

	// Capture shadow file output (reads from bind-mounted host path after exit).
	capturedShadow, captureErr := captureShadowOutput(prepared, "")
	if result != nil {
		capturedShadow, captureErr = captureShadowOutput(prepared, result.Stdout)
	}
	if captureErr != nil {
		s.publishLog(stepID, toolName, advancedpb.LogSource_LOG_SOURCE_SYSTEM,
			fmt.Sprintf("failed to capture shadow output: %v", captureErr))
	}

	return &fileOnlyResult{
		DockerResult: result,
		Shadow:       capturedShadow,
	}, runErr
}

// resolveExtractField returns the JSON field key to pull from each JSONL line
// for SSE display and pipeline output. Reads output_schema.pipeline_output.extract_field.
func resolveExtractField(toolRow db.Tool) string {
	schema, err := parseOutputSchema(toolRow.OutputSchema)
	if err != nil {
		return ""
	}
	return stringsTrim(schema.PipelineOutput.ExtractField)
}

// extractJSONLineField attempts to get a string value from a raw JSONL line.
// Falls back to common aliases (url, input, host) when the exact field is missing.
func extractJSONLineField(line, field string) string {
	var obj map[string]any
	if err := json.Unmarshal([]byte(line), &obj); err != nil {
		return ""
	}
	// Try the declared extract_field first.
	if field != "" {
		if v := extractJSONField(obj, field); v != "" {
			return v
		}
	}
	// Fallback aliases used by common recon tools.
	for _, alias := range []string{"host", "url", "input", "ip", "domain"} {
		if v := extractJSONField(obj, alias); v != "" {
			return v
		}
	}
	return ""
}

// formatSSELine builds a terminal-style display string from a raw JSONL line.
//
// It reads output_schema.fields in declaration order:
//   - The primary field (pipeline_extract:true or finding_host:true) is shown first, without brackets.
//   - Every other field that has a non-empty value in the JSON is appended as [value].
//   - The "input" passthrough field is always skipped (it is the feed-in, not a result).
//
// Only fields whose values are actually present in the JSON are included, so
// unused tool options (e.g. -title when not requested) are silently omitted.
//
// Examples:
//
//	httpx  -sc -td → "https://apply.cadt.edu.kh [200] [Bootstrap:5,jQuery:3.6]"
//	subfinder      → "api.cadt.edu.kh [certspotter,bevigil]"
//	nuclei         → "https://x.com [high] [CVE-2021-1234] [SQL Injection]"
func formatSSELine(jsonLine string, toolRow db.Tool) string {
	var obj map[string]any
	if err := json.Unmarshal([]byte(jsonLine), &obj); err != nil {
		return ""
	}

	schema, err := parseOutputSchema(toolRow.OutputSchema)
	if err != nil || len(schema.Fields) == 0 {
		// No schema — just return the extracted primary value.
		return extractJSONLineField(jsonLine, "")
	}

	var primary string
	var brackets []string

	for _, field := range schema.Fields {
		// Skip the passthrough input field — it is the caller's input, not a result.
		if field.Key == "input" {
			continue
		}

		val := jsonDisplayValue(obj, field.Key)
		if val == "" {
			continue
		}

		if field.PipelineExtract || field.FindingHost {
			// Primary field: first one wins.
			if primary == "" {
				primary = val
			}
		} else {
			brackets = append(brackets, "["+val+"]")
		}
	}

	// Fall back to alias-based extraction if schema produced nothing.
	if primary == "" {
		primary = extractJSONLineField(jsonLine, "")
	}
	if primary == "" {
		return ""
	}
	if len(brackets) == 0 {
		return primary
	}
	return primary + " " + strings.Join(brackets, " ")
}

// jsonDisplayValue converts a JSON object value to a human-readable string
// suitable for bracket display in the terminal-style SSE line.
//
//   - Arrays   → comma-joined (e.g. ["Bootstrap","jQuery"] → "Bootstrap,jQuery")
//   - Floats that are whole numbers → formatted as integers (200.0 → "200")
//   - Boolean false → empty string (field was not triggered, hide it)
//   - nil / "<nil>" → empty string
func jsonDisplayValue(obj map[string]any, key string) string {
	v, ok := obj[key]
	if !ok || v == nil {
		return ""
	}
	switch val := v.(type) {
	case []any:
		parts := make([]string, 0, len(val))
		for _, item := range val {
			s := strings.TrimSpace(fmt.Sprint(item))
			if s != "" && s != "<nil>" {
				parts = append(parts, s)
			}
		}
		if len(parts) == 0 {
			return ""
		}
		return strings.Join(parts, ",")
	case float64:
		// JSON numbers are float64; render integers without a decimal point.
		if val == float64(int64(val)) {
			return strconv.FormatInt(int64(val), 10)
		}
		return strconv.FormatFloat(val, 'f', -1, 64)
	case bool:
		// Boolean false means the field wasn't triggered — omit it.
		if !val {
			return ""
		}
		return "true"
	default:
		s := strings.TrimSpace(fmt.Sprint(val))
		if s == "<nil>" {
			return ""
		}
		return s
	}
}
