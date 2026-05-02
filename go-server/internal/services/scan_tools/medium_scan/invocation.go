package mediumscan

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	dockerrunner "go-server/docker"
	advancedpb "go-server/gen/advanced"
	mediumspb "go-server/gen/mediumscan"
	db "go-server/internal/database/sqlc"
	advancedscan "go-server/internal/services/scan_tools/advanced_scan"
)

type inputFieldSpec struct {
	Key      string `json:"key"`
	Type     string `json:"type"`
	Required bool   `json:"required"`
	Flag     string `json:"flag"`
}

type inputSchemaSpec struct {
	Type          string                     `json:"type"`
	Fields        []inputFieldSpec           `json:"fields"`
	PipelineInput pipelineInputTransportSpec `json:"pipeline_input"`
}

type invocationPlan struct {
	ImageRef string
	Command  string
	Args     []string
}

type pipelineInputTransportSpec struct {
	MultiMode   string `json:"multi_mode"`
	ListFlag    string `json:"list_flag"`
	TargetField string `json:"target_field"`
}

type preparedInvocation struct {
	Plan  *invocationPlan
	Files []dockerrunner.ContainerFile
	Note  string
}

func buildMediumInvocation(toolRow db.Tool, targetValue string, flags []string) (*invocationPlan, error) {
	prepared, err := buildMediumInvocationForStep(toolRow, targetValue, flags, nil, "", "")
	if err != nil {
		return nil, err
	}
	return prepared.Plan, nil
}

func buildMediumInvocationForStep(toolRow db.Tool, targetValue string, flags, pipedLines []string, jobID, stepID string) (*preparedInvocation, error) {
	if stringsTrim(toolRow.ToolName) == "" {
		return nil, fmt.Errorf("tool configuration is missing tool_name")
	}
	if stringsTrim(toolRow.ImageRef.String) == "" {
		return nil, fmt.Errorf("tool %q is missing image_ref", toolRow.ToolName)
	}
	targetValue = stringsTrim(targetValue)
	if targetValue == "" {
		return nil, fmt.Errorf("target_value is required")
	}

	schema, err := parseInputSchema(toolRow.InputSchema)
	if err != nil {
		return nil, fmt.Errorf("invalid input_schema for tool %q: %w", toolRow.ToolName, err)
	}
	field := inferPrimaryInputField(toolRow.ToolName, schema, targetValue)
	if stringsTrim(field.Flag) == "" {
		field.Flag = inferInputFlag(toolRow.ToolName, field.Key)
	}

	// Advanced invocation building depends on input_schema metadata to inject the
	// target value. Medium historically tolerated missing schema by inferring the
	// primary input field and common input flags, so preserve that behavior by
	// synthesizing or augmenting schema metadata before delegating to advanced
	// invocation building.
	invocationTool := toolRow
	invocationSchema := schema
	schemaChanged := false
	if len(invocationSchema.Fields) == 0 {
		invocationSchema = inputSchemaSpec{
			Type:   "object",
			Fields: []inputFieldSpec{field},
		}
		schemaChanged = true
	} else if stringsTrim(field.Key) != "" {
		foundField := false
		for i := range invocationSchema.Fields {
			if !strings.EqualFold(invocationSchema.Fields[i].Key, field.Key) {
				continue
			}
			foundField = true
			if stringsTrim(invocationSchema.Fields[i].Flag) == "" && stringsTrim(field.Flag) != "" {
				invocationSchema.Fields[i].Flag = field.Flag
				schemaChanged = true
			}
			break
		}
		if !foundField {
			invocationSchema.Fields = append(invocationSchema.Fields, field)
			schemaChanged = true
		}
	}

	rawCustomFlags, err := mediumFlagsToRawCustomFlags(flags)
	if err != nil {
		return nil, err
	}
	toolArgs := map[string]string{}
	injectedArgs := make([]string, 0, 2)
	files := make([]dockerrunner.ContainerFile, 0, 1)
	note := ""
	targetForPlan := targetValue
	listFileInputUsed := false
	if len(pipedLines) > 0 {
		lines := normalizePipelineLines(pipedLines)
		if len(lines) > 0 {
			switch strings.ToLower(stringsTrim(invocationSchema.PipelineInput.MultiMode)) {
			case "list_file":
				listFlag := stringsTrim(invocationSchema.PipelineInput.ListFlag)
				if listFlag == "" {
					return nil, fmt.Errorf("pipeline_input.list_flag is required for multi_mode=list_file")
				}
				containerPath := fmt.Sprintf("/tmp/medium-scan-inputs/%s_%s.txt", jobID, stepID)
				injectedArgs = append(injectedArgs, listFlag, containerPath)
				files = append(files, dockerrunner.ContainerFile{
					Path:    containerPath,
					Content: []byte(strings.Join(lines, "\n") + "\n"),
					Mode:    0o644,
				})
				note = fmt.Sprintf("prepared %d piped inputs via %s", len(lines), listFlag)
				targetForPlan = ""
				listFileInputUsed = true
			default:
				appliedArgs, pipeErr := advancedscan.ApplyPipeInputs(invocationTool, toolArgs, lines)
				if pipeErr != nil {
					return nil, fmt.Errorf("failed to apply piped inputs: %w", pipeErr)
				}
				toolArgs = appliedArgs
				note = fmt.Sprintf("applied first piped input from %d upstream lines", len(lines))
				targetForPlan = ""
			}
		}
	}
	if listFileInputUsed {
		targetFieldKey := stringsTrim(invocationSchema.PipelineInput.TargetField)
		if targetFieldKey == "" {
			targetFieldKey = field.Key
		}
		for i := range invocationSchema.Fields {
			if !strings.EqualFold(stringsTrim(invocationSchema.Fields[i].Key), targetFieldKey) {
				continue
			}
			if invocationSchema.Fields[i].Required {
				invocationSchema.Fields[i].Required = false
				schemaChanged = true
			}
		}
	}
	if schemaChanged {
		b, marshalErr := json.Marshal(invocationSchema)
		if marshalErr != nil {
			return nil, fmt.Errorf("failed to synthesize input_schema for tool %q: %w", toolRow.ToolName, marshalErr)
		}
		invocationTool.InputSchema = b
	}

	customFlags, err := advancedscan.ParseCustomFlagsFromRaw(rawCustomFlags)
	if err != nil {
		return nil, fmt.Errorf("invalid medium flags for tool %q: %w", toolRow.ToolName, err)
	}

	plan, err := advancedscan.BuildAdvancedInvocation(invocationTool, &advancedpb.SubmitScanRequest{
		ToolArgs:    toolArgs,
		TargetValue: targetForPlan,
		CustomFlags: customFlags,
	})
	if err != nil {
		return nil, err
	}
	if len(injectedArgs) > 0 {
		plan.Args = append(plan.Args, injectedArgs...)
	}

	return &preparedInvocation{
		Plan: &invocationPlan{
			ImageRef: plan.ImageRef,
			Command:  plan.Command,
			Args:     append([]string(nil), plan.Args...),
		},
		Files: files,
		Note:  note,
	}, nil
}

func mediumFlagsToRawCustomFlags(flags []string) ([]string, error) {
	raw := make([]string, 0, len(flags))
	for i := 0; i < len(flags); i++ {
		flag := stringsTrim(flags[i])
		if flag == "" {
			continue
		}
		if !strings.HasPrefix(flag, "-") {
			return nil, fmt.Errorf("unexpected medium flag token %q", flag)
		}

		value := "true"
		if i+1 < len(flags) && !strings.HasPrefix(stringsTrim(flags[i+1]), "-") {
			i++
			value = stringsTrim(flags[i])
		}
		raw = append(raw, fmt.Sprintf("%s=%s", flag, value))
	}
	return raw, nil
}

func decodeMediumToolConfig(raw []byte) (ToolConfig, error) {
	if len(raw) == 0 {
		return ToolConfig{}, nil
	}
	var cfg ScanConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return ToolConfig{}, err
	}
	return ToolConfig{ScanConfig: cfg}, nil
}

func decodeMediumOptionValues(values map[string]*mediumspb.MediumOptionValue) (map[string]any, error) {
	out := make(map[string]any, len(values))
	for key, value := range values {
		if value == nil {
			return nil, fmt.Errorf("tool_options[%q] is required", key)
		}
		switch v := value.GetValue().(type) {
		case *mediumspb.MediumOptionValue_IntValue:
			out[key] = v.IntValue
		case *mediumspb.MediumOptionValue_StrValue:
			out[key] = v.StrValue
		case *mediumspb.MediumOptionValue_BoolValue:
			out[key] = v.BoolValue
		default:
			return nil, fmt.Errorf("tool_options[%q] has unsupported type", key)
		}
	}
	return out, nil
}

func parseInputSchema(raw []byte) (inputSchemaSpec, error) {
	if len(raw) == 0 {
		return inputSchemaSpec{}, nil
	}
	var out inputSchemaSpec
	if err := json.Unmarshal(raw, &out); err != nil {
		return inputSchemaSpec{}, err
	}
	return out, nil
}

func inferPrimaryInputField(toolName string, schema inputSchemaSpec, targetValue string) inputFieldSpec {
	targetType := inferTargetType(targetValue)
	preferredKeys := preferredInputKeysForTargetType(targetType)

	for _, key := range preferredKeys {
		for _, field := range schema.Fields {
			if strings.EqualFold(stringsTrim(field.Key), key) {
				return field
			}
		}
	}
	for _, field := range schema.Fields {
		if field.Required && stringsTrim(field.Key) != "" {
			return field
		}
	}
	key := defaultInputKeyForTool(toolName, targetType)
	return inputFieldSpec{
		Key:      key,
		Type:     "string",
		Required: true,
		Flag:     inferInputFlag(toolName, key),
	}
}

func buildInputArgs(toolName string, field inputFieldSpec, value string) ([]string, error) {
	flag := stringsTrim(field.Flag)
	if flag == "" {
		flag = inferInputFlag(toolName, field.Key)
	}
	if flag == "" {
		return []string{value}, nil
	}
	if !safeFlagPattern.MatchString(flag) {
		return nil, fmt.Errorf("invalid input flag %q", flag)
	}
	return []string{flag, value}, nil
}

func inferInputFlag(toolName, key string) string {
	normalizedTool := strings.ToLower(stringsTrim(toolName))
	normalizedKey := strings.ToLower(stringsTrim(key))

	toolSpecific := map[string]map[string]string{
		"subfinder": {"domain": "-d"},
		"naabu":     {"host": "-host", "ports": "-p"},
	}
	if byKey, ok := toolSpecific[normalizedTool]; ok {
		if flag, exists := byKey[normalizedKey]; exists {
			return flag
		}
	}
	generic := map[string]string{
		"domain":   "-d",
		"host":     "-host",
		"hostname": "-host",
		"ip":       "-host",
		"cidr":     "-host",
		"url":      "-u",
		"ports":    "-p",
		"target":   "-target",
	}
	return generic[normalizedKey]
}

func defaultInputKeyForTool(toolName, targetType string) string {
	switch strings.ToLower(stringsTrim(toolName)) {
	case "subfinder":
		return "domain"
	case "httpx":
		if targetType == "url" {
			return "url"
		}
		return "target"
	case "naabu":
		return "host"
	}
	keys := preferredInputKeysForTargetType(targetType)
	if len(keys) == 0 {
		return ""
	}
	return keys[0]
}

func preferredInputKeysForTargetType(targetType string) []string {
	switch targetType {
	case "url":
		return []string{"url", "target", "domain", "host"}
	case "ip":
		return []string{"ip", "host", "target", "domain"}
	case "cidr":
		return []string{"cidr", "network", "target", "domain"}
	default:
		return []string{"domain", "host", "target", "url"}
	}
}

var safeFlagPattern = regexp.MustCompile(`^--?[A-Za-z0-9][A-Za-z0-9._-]*$`)

func dedupeStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}

	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
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
