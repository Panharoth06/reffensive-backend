package advancedscan

import (
	"context"
	"fmt"
	"strings"

	advancedpb "go-server/gen/advanced"
	db "go-server/internal/database/sqlc"
)

type parsedCommandResult struct {
	Steps              []submittedStepInput
	DerivedTargetValue string
}

func (s *advancedScanServer) normalizeSubmittedStepsForRequest(ctx context.Context, req *advancedpb.SubmitScanRequest) ([]submittedStepInput, string, error) {
	command := stringsTrim(req.GetCommand())
	if command == "" {
		return nil, "", fmt.Errorf("command is required")
	}

	if len(req.GetTools()) > 0 || stringsTrim(req.GetToolName()) != "" || stringsTrim(req.GetToolId()) != "" || len(req.GetToolArgs()) > 0 || len(req.GetCustomFlags()) > 0 {
		return nil, "", fmt.Errorf("command cannot be combined with tools, tool_name, tool_id, tool_args, or custom_flags")
	}

	parsed, err := parseUnixCommandToSubmittedSteps(command, func(toolName string) (db.Tool, error) {
		return s.resolveTool(ctx, &advancedpb.SubmitScanRequest{ToolName: toolName})
	})
	if err != nil {
		return nil, "", err
	}
	return parsed.Steps, parsed.DerivedTargetValue, nil
}

func parseUnixCommandToSubmittedSteps(raw string, resolve func(toolName string) (db.Tool, error)) (parsedCommandResult, error) {
	segments, err := splitUnixCommandPipeline(raw)
	if err != nil {
		return parsedCommandResult{}, err
	}

	steps := make([]submittedStepInput, 0, len(segments))
	derivedTarget := ""
	for idx, tokens := range segments {
		toolName := stringsTrim(tokens[0])
		toolRow, err := resolve(toolName)
		if err != nil {
			return parsedCommandResult{}, fmt.Errorf("resolve tool %q: %w", toolName, err)
		}

		step, err := parseCommandStepTokens(tokens, toolRow)
		if err != nil {
			return parsedCommandResult{}, fmt.Errorf("parse command step %d (%s): %w", idx+1, toolName, err)
		}
		if idx == 0 {
			derivedTarget = deriveTargetValueFromStep(toolRow, step.ToolArgs)
		}
		steps = append(steps, step)
	}

	return parsedCommandResult{
		Steps:              steps,
		DerivedTargetValue: derivedTarget,
	}, nil
}

func splitUnixCommandPipeline(raw string) ([][]string, error) {
	command := stringsTrim(raw)
	if command == "" {
		return nil, fmt.Errorf("command is required")
	}

	var segments [][]string
	var current []string
	var buf strings.Builder
	tokenStarted := false
	inSingle := false
	inDouble := false
	escaping := false

	flushToken := func() {
		if !tokenStarted {
			return
		}
		current = append(current, buf.String())
		buf.Reset()
		tokenStarted = false
	}

	flushSegment := func() error {
		flushToken()
		if len(current) == 0 {
			return fmt.Errorf("command contains an empty pipeline segment")
		}
		segments = append(segments, current)
		current = nil
		return nil
	}

	for _, r := range command {
		switch {
		case escaping:
			buf.WriteRune(r)
			tokenStarted = true
			escaping = false
		case inSingle:
			if r == '\'' {
				inSingle = false
			} else {
				buf.WriteRune(r)
			}
			tokenStarted = true
		case inDouble:
			switch r {
			case '"':
				inDouble = false
			case '\\':
				escaping = true
			default:
				buf.WriteRune(r)
			}
			tokenStarted = true
		default:
			switch r {
			case '\\':
				escaping = true
				tokenStarted = true
			case '\'':
				inSingle = true
				tokenStarted = true
			case '"':
				inDouble = true
				tokenStarted = true
			case '|':
				if err := flushSegment(); err != nil {
					return nil, err
				}
			case ' ', '\t', '\r', '\n':
				flushToken()
			default:
				buf.WriteRune(r)
				tokenStarted = true
			}
		}
	}

	if escaping || inSingle || inDouble {
		return nil, fmt.Errorf("command contains an unterminated escape or quote")
	}
	if err := flushSegment(); err != nil {
		return nil, err
	}

	return segments, nil
}

func parseCommandStepTokens(tokens []string, toolRow db.Tool) (submittedStepInput, error) {
	if len(tokens) == 0 {
		return submittedStepInput{}, fmt.Errorf("step is empty")
	}

	inputSchema, err := parseInputSchema(toolRow.InputSchema)
	if err != nil {
		return submittedStepInput{}, fmt.Errorf("parse input_schema: %w", err)
	}
	scanConfig, err := parseScanConfig(toolRow.ScanConfig)
	if err != nil {
		return submittedStepInput{}, fmt.Errorf("parse scan_config: %w", err)
	}

	inputFlagIndex := buildInputFlagIndex(inputSchema)
	positionalFields := positionalInputFields(inputSchema)
	// Declared scan_config options are convenience mappings for common typed
	// flags. Any other flag stays raw and is validated later by the denylist.
	_, optionByFlag := buildOptionIndex(scanConfig)

	step := submittedStepInput{
		ToolName:       stringsTrim(tokens[0]),
		ToolArgs:       make(map[string]string),
		RawCustomFlags: make([]string, 0, len(tokens)),
	}

	positionals := make([]string, 0, len(positionalFields))
	for i := 1; i < len(tokens); i++ {
		token := tokens[i]
		if token == "" {
			continue
		}

		flagToken := token
		flagValue := ""
		if idx := strings.Index(token, "="); idx >= 0 {
			flagToken = token[:idx]
			flagValue = token[idx+1:]
		}

		if strings.HasPrefix(flagToken, "-") {
			normFlag := normalizeFlag(flagToken)
			if field, ok := inputFlagIndex[normFlag]; ok {
				value := flagValue
				if value == "" {
					if i+1 >= len(tokens) {
						return submittedStepInput{}, fmt.Errorf("input flag %q requires a value", token)
					}
					i++
					value = tokens[i]
				}
				step.ToolArgs[field.Key] = value
				continue
			}

			if spec, ok := optionByFlag[normFlag]; ok {
				value := flagValue
				if value == "" {
					if isBooleanOptionType(spec) {
						if i+1 < len(tokens) && isBoolLiteral(tokens[i+1]) {
							i++
							step.ToolArgs[spec.Key] = tokens[i]
						} else {
							step.ToolArgs[spec.Key] = "true"
						}
						continue
					}
					if i+1 >= len(tokens) {
						return submittedStepInput{}, fmt.Errorf("option flag %q requires a value", token)
					}
					i++
					value = tokens[i]
				}
				step.ToolArgs[spec.Key] = value
				continue
			}

			step.RawCustomFlags = append(step.RawCustomFlags, token)
			if flagValue == "" && i+1 < len(tokens) && !strings.HasPrefix(tokens[i+1], "-") {
				i++
				step.RawCustomFlags = append(step.RawCustomFlags, tokens[i])
			}
			continue
		}

		positionals = append(positionals, token)
	}

	if len(positionals) > len(positionalFields) {
		return submittedStepInput{}, fmt.Errorf("too many positional arguments for tool %q", toolRow.ToolName)
	}
	for idx, field := range positionalFields {
		if idx >= len(positionals) {
			break
		}
		step.ToolArgs[field.Key] = positionals[idx]
	}

	return step, nil
}

func buildInputFlagIndex(schema inputSchemaSpec) map[string]inputFieldSpec {
	out := make(map[string]inputFieldSpec, len(schema.Fields))
	for _, field := range schema.Fields {
		normFlag := normalizeFlag(field.Flag)
		if normFlag == "" {
			continue
		}
		out[normFlag] = field
	}
	return out
}

func positionalInputFields(schema inputSchemaSpec) []inputFieldSpec {
	out := make([]inputFieldSpec, 0, len(schema.Fields))
	for _, field := range schema.Fields {
		if stringsTrim(field.Key) == "" || stringsTrim(field.Flag) != "" {
			continue
		}
		out = append(out, field)
	}
	return out
}

func deriveTargetValueFromStep(toolRow db.Tool, toolArgs map[string]string) string {
	inputSchema, err := parseInputSchema(toolRow.InputSchema)
	if err != nil {
		return ""
	}

	inputByKey, inputOrder := buildInputIndex(inputSchema)
	for _, preferred := range preferredTargetInputKeys {
		for _, key := range inputOrder {
			field, ok := inputByKey[key]
			if !ok || !strings.EqualFold(field.Key, preferred) {
				continue
			}
			if value := stringsTrim(toolArgs[field.Key]); value != "" {
				return value
			}
		}
	}
	for _, key := range inputOrder {
		if value := stringsTrim(toolArgs[key]); value != "" {
			return value
		}
	}
	return ""
}

func isBooleanOptionType(spec optionSpec) bool {
	switch strings.ToLower(stringsTrim(spec.Type)) {
	case "bool", "boolean":
		return true
	default:
		return false
	}
}

func isBoolLiteral(raw string) bool {
	switch strings.ToLower(stringsTrim(raw)) {
	case "1", "0", "true", "false", "yes", "no", "on", "off":
		return true
	default:
		return false
	}
}
