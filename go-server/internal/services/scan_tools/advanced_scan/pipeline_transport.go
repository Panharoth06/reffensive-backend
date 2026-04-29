package advancedscan

import (
	"encoding/json"
	"fmt"
	"strings"

	dockerrunner "go-server/docker"
	db "go-server/internal/database/sqlc"
)

type preparedPipelineInput struct {
	ToolArgs       map[string]string
	RawCustomFlags []string
	InjectedArgs   []string
	Files          []dockerrunner.ContainerFile
	Note           string
}

// canonicalStepOutput keeps parsing and inter-step piping aligned by favoring
// the structured shadow output whenever the tool emitted one.
func canonicalStepOutput(result *dockerrunner.ToolResult, shadow capturedShadowOutput) string {
	if len(shadow.Content) > 0 {
		return string(shadow.Content)
	}
	if result == nil {
		return ""
	}
	return result.Stdout
}

func preparePipelineInput(
	toolRow db.Tool,
	toolArgs map[string]string,
	rawCustomFlags []string,
	pipedLines []string,
	jobID string,
	stepID string,
) (preparedPipelineInput, error) {
	prepared := preparedPipelineInput{
		ToolArgs:       cloneStringMap(toolArgs),
		RawCustomFlags: append([]string(nil), rawCustomFlags...),
	}

	lines := normalizePipelineLines(pipedLines)
	if len(lines) == 0 {
		return prepared, nil
	}

	inputSchema, err := parseInputSchema(toolRow.InputSchema)
	if err != nil {
		return preparedPipelineInput{}, fmt.Errorf("parse input_schema: %w", err)
	}

	switch strings.ToLower(stringsTrim(inputSchema.PipelineInput.MultiMode)) {
	case "list_file":
		listFlag := stringsTrim(inputSchema.PipelineInput.ListFlag)
		if listFlag == "" {
			return preparedPipelineInput{}, fmt.Errorf("pipeline_input.list_flag is required for multi_mode=list_file")
		}

		containerPath := fmt.Sprintf("/tmp/advanced-scan-inputs/%s_%s.txt", jobID, stepID)
		fileBody := []byte(strings.Join(lines, "\n") + "\n")
		prepared.InjectedArgs = append(prepared.InjectedArgs, listFlag, containerPath)
		prepared.Files = append(prepared.Files, dockerrunner.ContainerFile{
			Path:    containerPath,
			Content: fileBody,
			Mode:    0o644,
		})
		prepared.Note = fmt.Sprintf("prepared %d piped inputs via %s", len(lines), listFlag)
		return prepared, nil
	default:
		appliedArgs, err := ApplyPipeInputs(toolRow, prepared.ToolArgs, lines)
		if err != nil {
			return preparedPipelineInput{}, err
		}
		prepared.ToolArgs = appliedArgs
		prepared.Note = fmt.Sprintf("applied first piped input from %d upstream lines", len(lines))
		return prepared, nil
	}
}

func extractPipelineOutputs(toolRow db.Tool, stdout string) []string {
	lines := extractRawLines(stdout)

	outputSchema, err := parseOutputSchema(toolRow.OutputSchema)
	if err != nil {
		return dedupeLines(lines)
	}

	pipelineCfg := outputSchema.PipelineOutput
	extractField := stringsTrim(pipelineCfg.ExtractField)
	mode := strings.ToLower(stringsTrim(pipelineCfg.Mode))

	// JSONL mode: extract specified field, or fallback to common aliases
	if mode == "jsonl" {
		extracted := extractJSONLField(lines, extractField)
		if len(extracted) > 0 {
			if pipelineCfg.Dedupe == nil || *pipelineCfg.Dedupe {
				return dedupeStrings(extracted)
			}
			return extracted
		}
		// No extract_field or field missing in data: try common aliases
		extracted = extractJSONLField(lines, "")
		if len(extracted) > 0 {
			if pipelineCfg.Dedupe == nil || *pipelineCfg.Dedupe {
				return dedupeStrings(extracted)
			}
			return extracted
		}
	}

	// Fallback: raw lines
	if pipelineCfg.Dedupe == nil || *pipelineCfg.Dedupe {
		return dedupeLines(lines)
	}
	return lines
}

// extractJSONLField pulls a specific field from each JSON line.
// Falls back to common aliases if the exact field is missing.
func extractJSONLField(lines []string, field string) []string {
	extracted := make([]string, 0, len(lines))
	for _, line := range lines {
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var obj map[string]any
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			continue
		}
		val := extractJSONField(obj, field)
		if val == "" {
			// Try common aliases for host/url extraction
			for _, fallback := range []string{"url", "input", "host"} {
				if val = extractJSONField(obj, fallback); val != "" {
					break
				}
			}
		}
		if val != "" {
			extracted = append(extracted, val)
		}
	}
	return extracted
}

// extractJSONField safely reads a string value from a JSON object.
func extractJSONField(obj map[string]any, key string) string {
	if key == "host_port" {
		return deriveHostPortValue(obj)
	}
	raw, ok := obj[key]
	if !ok || raw == nil {
		return ""
	}
	s := stringsTrim(fmt.Sprint(raw))
	if s == "" || s == "<nil>" {
		return ""
	}
	return s
}

func deriveHostPortValue(obj map[string]any) string {
	hostValue := stringsTrim(fmt.Sprint(firstNonNilValue(obj, "host_port", "host", "ip", "input", "url")))
	if hostValue == "" || hostValue == "<nil>" {
		return ""
	}

	if portValue := stringsTrim(fmt.Sprint(firstNonNilValue(obj, "port"))); portValue != "" && portValue != "<nil>" {
		if !strings.Contains(hostValue, ":") {
			return fmt.Sprintf("%s:%s", hostValue, portValue)
		}
	}
	return hostValue
}

func firstNonNilValue(obj map[string]any, keys ...string) any {
	for _, key := range keys {
		value, ok := obj[key]
		if !ok || value == nil {
			continue
		}
		return value
	}
	return nil
}

func extractRawLines(stdout string) []string {
	out := make([]string, 0)
	for _, line := range strings.Split(stdout, "\n") {
		trimmed := stringsTrim(strings.TrimRight(line, "\r"))
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func dedupeLines(lines []string) []string {
	if len(lines) == 0 {
		return nil
	}
	out := make([]string, 0, len(lines))
	seen := make(map[string]struct{}, len(lines))
	for _, line := range lines {
		if _, ok := seen[line]; !ok {
			seen[line] = struct{}{}
			out = append(out, line)
		}
	}
	return out
}

func dedupeStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if _, ok := seen[value]; !ok {
			seen[value] = struct{}{}
			out = append(out, value)
		}
	}
	return out
}

func normalizePipelineLines(lines []string) []string {
	cleaned := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := stringsTrim(strings.TrimRight(line, "\r"))
		if trimmed == "" {
			continue
		}
		cleaned = append(cleaned, trimmed)
	}
	return dedupeStrings(cleaned)
}
