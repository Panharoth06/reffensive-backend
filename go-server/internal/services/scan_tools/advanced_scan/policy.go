package advancedscan

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	advancedpb "go-server/gen/advanced"
	db "go-server/internal/database/sqlc"
)

var safeFlagPattern = regexp.MustCompile(`^--?[A-Za-z0-9][A-Za-z0-9._-]*$`)
var preferredTargetInputKeys = []string{"target", "host", "hostname", "domain", "url", "ip", "cidr"}
var toolSpecificInputFlagFallbacks = map[string]map[string]string{
	"naabu": {
		"host": "-host",
	},
}

// globalDeniedOptions is a baseline set of flags that are rejected for every tool.
// Per-tool DeniedOptions are merged on top of this set at runtime.
var globalDeniedOptions = []string{
	// Interactive / TTY modes break automation and can hang the pipeline.
	"-it",
	"--interactive",
	"--tty",
	// Shell / code execution vectors (argument smuggling risk).
	"--eval",
	"--execute",
	"--run",
	"-e",
	// Output redirection that bypasses result capture.
	"--output",
	"-o",
	"--log",
	"--logfile",
	"--log-file",
	// Verbose / debug modes that could leak internals.
	"--debug",
	"--trace",
	// Network / proxy overrides that could reach unintended targets.
	"--proxy",
	"--upstream-proxy",
}

var globalDeniedSet = buildGlobalDeniedSet()

func buildGlobalDeniedSet() map[string]struct{} {
	out := make(map[string]struct{}, len(globalDeniedOptions))
	for _, flag := range globalDeniedOptions {
		if norm := normalizeFlag(flag); norm != "" {
			out[norm] = struct{}{}
		}
	}
	return out
}

func isDeniedFlag(norm string) bool {
	_, global := globalDeniedSet[norm]
	return global
}

type inputFieldSpec struct {
	Key      string `json:"key"`
	Type     string `json:"type"`
	Required bool   `json:"required"`
	Flag     string `json:"flag"`
}

type pipelineInputTransportSpec struct {
	MultiMode   string `json:"multi_mode"`
	ListFlag    string `json:"list_flag"`
	TargetField string `json:"target_field"`
}

type inputSchemaSpec struct {
	Type          string                     `json:"type"`
	Fields        []inputFieldSpec           `json:"fields"`
	PipelineInput pipelineInputTransportSpec `json:"pipeline_input"`
}

type outputFieldSpec struct {
	Key                string `json:"key"`
	Type               string `json:"type"`
	Label              string `json:"label"`
	Description        string `json:"description"`
	FindingTitle       bool   `json:"finding_title"`
	FindingSeverity    bool   `json:"finding_severity"`
	FindingHost        bool   `json:"finding_host"`
	FindingDescription bool   `json:"finding_description"`
	PipelineExtract    bool   `json:"pipeline_extract"`
}

type pipelineOutputTransportSpec struct {
	Mode         string `json:"mode"`
	Entity       string `json:"entity"`
	ExtractField string `json:"extract_field"`
	Dedupe       *bool  `json:"dedupe"`
}

type outputSchemaSpec struct {
	Type           string                      `json:"type"`
	PipelineOutput pipelineOutputTransportSpec `json:"pipeline_output"`
	Fields         []outputFieldSpec           `json:"fields"`
}

type shadowOutputFormatSpec struct {
	Transport     string   `json:"transport"`
	EnableFlags   []string `json:"enable_flags"`
	PathFlag      string   `json:"path_flag"`
	Parser        string   `json:"parser"`
	PathMode      string   `json:"path_mode"`
	FileExtension string   `json:"file_extension"`
}

type shadowOutputConfigSpec struct {
	PreferredFormat     string                            `json:"preferred_format"`
	Formats             map[string]shadowOutputFormatSpec `json:"formats"`
	DefaultPath         string                            `json:"default_path"`
	FilenameTemplate    string                            `json:"filename_template"`
	ParseTimeoutSeconds int32                             `json:"parse_timeout_seconds"`
	FallbackToStdout    bool                              `json:"fallback_to_stdout"`
	IsStreaming         bool                              `json:"is_streaming"`
	JsonFlag            string                            `json:"json_flag"`
	FileFlag            string                            `json:"file_flag"`
	AlternativeFormats  []string                          `json:"alternative_formats"`
}

type optionSpec struct {
	Flag string `json:"flag"`
	Key  string `json:"key"`
	Type string `json:"type"`
	Enum []any  `json:"enum"`
}

type scanModeConfig struct {
	Options []optionSpec `json:"options"`
}

type toolRuntimeConfig struct {
	UseGVisor   *bool    `json:"use_gvisor"`
	NetworkMode string   `json:"network_mode"`
	Privileged  *bool    `json:"privileged"`
	CapAdd      []string `json:"cap_add"`
}

type toolScanConfig struct {
	Medium   scanModeConfig    `json:"medium"`
	Advanced scanModeConfig    `json:"advanced"`
	Runtime  toolRuntimeConfig `json:"runtime"`
}

// InvocationPlan is a validated command plan for advanced mode.
// It is argv-safe (no shell interpolation).
type InvocationPlan struct {
	ImageRef string
	Command  string
	Args     []string
}

// ParseCustomFlagsFromRaw converts frontend-friendly raw flag strings
// into structured gRPC custom flags.
func ParseCustomFlagsFromRaw(rawFlags []string) ([]*advancedpb.CustomFlag, error) {
	out := make([]*advancedpb.CustomFlag, 0, len(rawFlags))
	for _, raw := range rawFlags {
		flag := strings.TrimSpace(raw)
		if flag == "" {
			return nil, fmt.Errorf("custom flag cannot be empty")
		}
		if !strings.HasPrefix(flag, "-") {
			return nil, fmt.Errorf("invalid custom flag %q", raw)
		}
		normalized := flag
		value := ""
		if idx := strings.Index(flag, "="); idx >= 0 {
			normalized = strings.TrimSpace(flag[:idx])
			value = strings.TrimSpace(flag[idx+1:])
		}
		if !safeFlagPattern.MatchString(normalized) {
			return nil, fmt.Errorf("invalid custom flag %q", raw)
		}
		out = append(out, &advancedpb.CustomFlag{
			Raw:        flag,
			Normalized: normalized,
			Value:      value,
		})
	}
	return out, nil
}

// ApplyPipeInputs injects previous step output into missing required inputs.
// Current strategy is intentionally simple: use the first non-empty piped line.
func ApplyPipeInputs(toolRow db.Tool, toolArgs map[string]string, pipedLines []string) (map[string]string, error) {
	clone := make(map[string]string, len(toolArgs))
	for k, v := range toolArgs {
		clone[k] = v
	}

	if len(pipedLines) == 0 {
		return clone, nil
	}

	first := ""
	for _, l := range pipedLines {
		l = strings.TrimSpace(l)
		if l != "" {
			first = l
			break
		}
	}
	if first == "" {
		return clone, nil
	}

	schema, err := parseInputSchema(toolRow.InputSchema)
	if err != nil {
		return nil, fmt.Errorf("parse input_schema: %w", err)
	}

	for _, field := range schema.Fields {
		if !field.Required {
			continue
		}
		if strings.TrimSpace(clone[field.Key]) != "" {
			continue
		}
		clone[field.Key] = first
		// Fill only the first required missing field to avoid surprising overrides.
		break
	}

	return clone, nil
}

func BuildAdvancedInvocation(toolRow db.Tool, req *advancedpb.SubmitScanRequest) (*InvocationPlan, error) {
	return buildAdvancedInvocation(toolRow, req, nil)
}

func BuildAdvancedInvocationWithSystemArgs(toolRow db.Tool, req *advancedpb.SubmitScanRequest, systemArgs []string) (*InvocationPlan, error) {
	return buildAdvancedInvocation(toolRow, req, systemArgs)
}

func buildAdvancedInvocation(toolRow db.Tool, req *advancedpb.SubmitScanRequest, systemArgs []string) (*InvocationPlan, error) {
	if strings.TrimSpace(toolRow.ToolName) == "" {
		return nil, fmt.Errorf("tool configuration is missing tool_name")
	}
	if strings.TrimSpace(toolRow.ImageRef.String) == "" {
		return nil, fmt.Errorf("tool %q is missing image_ref", toolRow.ToolName)
	}

	inputSchema, err := parseInputSchema(toolRow.InputSchema)
	if err != nil {
		return nil, fmt.Errorf("invalid input_schema for tool %q: %w", toolRow.ToolName, err)
	}

	scanConfig, err := parseScanConfig(toolRow.ScanConfig)
	if err != nil {
		return nil, fmt.Errorf("invalid scan_config for tool %q: %w", toolRow.ToolName, err)
	}

	denied := make(map[string]struct{}, len(toolRow.DeniedOptions))
	for _, flag := range toolRow.DeniedOptions {
		norm := normalizeFlag(flag)
		if norm != "" {
			denied[norm] = struct{}{}
		}
	}

	isBlocked := func(norm string) (string, bool) {
		if isDeniedFlag(norm) {
			return "globally denied", true
		}
		if _, blocked := denied[norm]; blocked {
			return fmt.Sprintf("denied for tool %q", toolRow.ToolName), true
		}
		return "", false
	}

	// scan_config options are optional structured hints. In advanced command mode
	// users can still pass most flags as raw custom_flags; only denied flags are
	// hard blocked.
	optionByKey, optionByFlag := buildOptionIndex(scanConfig)
	inputByKey, inputOrder := buildInputIndex(inputSchema)
	toolArgs := injectTargetValueIntoToolArgs(cloneStringMap(req.ToolArgs), inputSchema, req.GetTargetValue())

	if err := validateRequiredInputs(toolArgs, req.CustomFlags, systemArgs, inputSchema); err != nil {
		return nil, err
	}

	flaggedInputArgs := make([]string, 0, len(toolArgs)*2)
	positionalInputArgs := make([]string, 0, len(toolArgs))

	for _, key := range inputOrder {
		val, ok := toolArgs[key]
		if !ok || strings.TrimSpace(val) == "" {
			continue
		}
		if err := validateValueSanity(val); err != nil {
			return nil, fmt.Errorf("invalid value for input %q: %w", key, err)
		}
		if field, exists := inputByKey[key]; exists {
			if fieldFlag := resolveInputFieldFlag(toolRow.ToolName, field); fieldFlag != "" {
				normFlag := normalizeFlag(fieldFlag)
				if reason, blocked := isBlocked(normFlag); blocked {
					return nil, fmt.Errorf("flag %q is %s", fieldFlag, reason)
				}
				flaggedInputArgs = append(flaggedInputArgs, fieldFlag, val)
				continue
			}
		}
		positionalInputArgs = append(positionalInputArgs, val)
	}

	toolArgKeys := make([]string, 0, len(toolArgs))
	for k := range toolArgs {
		toolArgKeys = append(toolArgKeys, k)
	}
	sort.Strings(toolArgKeys)

	optionArgs := make([]string, 0, len(toolArgKeys)*2)
	for _, key := range toolArgKeys {
		if _, isInput := inputByKey[key]; isInput {
			continue
		}

		val := toolArgs[key]
		spec, ok := optionByKey[key]
		if !ok {
			return nil, fmt.Errorf("unknown tool_args key %q; structured tool_args only support declared options, use custom_flags for raw advanced flags", key)
		}

		normFlag := normalizeFlag(spec.Flag)
		if reason, blocked := isBlocked(normFlag); blocked {
			return nil, fmt.Errorf("flag %q is %s", spec.Flag, reason)
		}

		parsed, shouldAppend, err := coerceOptionValue(spec, val)
		if err != nil {
			return nil, fmt.Errorf("invalid value for %q: %w", key, err)
		}
		if !shouldAppend {
			continue
		}
		optionArgs = append(optionArgs, spec.Flag)
		if parsed != "" {
			optionArgs = append(optionArgs, parsed)
		}
	}

	customArgs := make([]string, 0, len(req.CustomFlags)*2)
	for _, cf := range req.CustomFlags {
		flag := strings.TrimSpace(cf.Normalized)
		value := strings.TrimSpace(cf.Value)
		if flag == "" {
			return nil, fmt.Errorf("custom_flags.normalized must be set for %q", cf.Raw)
		}

		if strings.Contains(flag, "=") && value == "" {
			flagParts := strings.SplitN(flag, "=", 2)
			flag = flagParts[0]
			value = flagParts[1]
		}

		if !safeFlagPattern.MatchString(flag) {
			return nil, fmt.Errorf("invalid custom flag %q", flag)
		}
		if err := validateValueSanity(value); err != nil {
			return nil, fmt.Errorf("invalid custom flag value for %q: %w", flag, err)
		}

		normFlag := normalizeFlag(flag)
		if reason, blocked := isBlocked(normFlag); blocked {
			return nil, fmt.Errorf("flag %q is %s", flag, reason)
		}

		if spec, known := optionByFlag[normFlag]; known {
			parsed, shouldAppend, err := coerceOptionValue(spec, value)
			if err != nil {
				return nil, fmt.Errorf("invalid custom flag value for %q: %w", flag, err)
			}
			if !shouldAppend {
				continue
			}
			customArgs = append(customArgs, flag)
			if parsed != "" {
				customArgs = append(customArgs, parsed)
			}
			continue
		}

		customArgs = append(customArgs, flag)
		if value != "" {
			customArgs = append(customArgs, value)
		}
	}

	// Preserve the legacy "inputs then options then custom flags" order by default.
	// If a tool models its target positionally but the user supplied a bare raw flag
	// such as `-d`, emit that raw flag before the positional input so the final argv
	// still represents `-d example.com`.
	moveCustomBeforePositional := len(optionArgs) == 0 && len(positionalInputArgs) > 0 && hasBareCustomFlag(req.CustomFlags)

	args := make([]string, 0, len(flaggedInputArgs)+len(optionArgs)+len(customArgs)+len(positionalInputArgs))
	args = append(args, flaggedInputArgs...)
	if moveCustomBeforePositional {
		args = append(args, customArgs...)
		args = append(args, positionalInputArgs...)
	} else {
		args = append(args, positionalInputArgs...)
		args = append(args, optionArgs...)
		args = append(args, customArgs...)
	}

	return &InvocationPlan{
		ImageRef: toolRow.ImageRef.String,
		Command:  canonicalToolName(toolRow.ToolName),
		Args:     args,
	}, nil
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

func parseScanConfig(raw []byte) (toolScanConfig, error) {
	if len(raw) == 0 {
		return toolScanConfig{}, nil
	}
	var out toolScanConfig
	if err := json.Unmarshal(raw, &out); err != nil {
		return toolScanConfig{}, err
	}
	return out, nil
}

func parseOutputSchema(raw []byte) (outputSchemaSpec, error) {
	if len(raw) == 0 {
		return outputSchemaSpec{}, nil
	}
	var out outputSchemaSpec
	if err := json.Unmarshal(raw, &out); err != nil {
		return outputSchemaSpec{}, err
	}
	return out, nil
}

func parseShadowOutputConfig(raw []byte) (shadowOutputConfigSpec, error) {
	if len(raw) == 0 {
		return shadowOutputConfigSpec{}, nil
	}
	var out shadowOutputConfigSpec
	if err := json.Unmarshal(raw, &out); err != nil {
		return shadowOutputConfigSpec{}, err
	}
	return normalizeShadowOutputConfig(out), nil
}

func normalizeShadowOutputConfig(cfg shadowOutputConfigSpec) shadowOutputConfigSpec {
	if cfg.Formats == nil {
		cfg.Formats = make(map[string]shadowOutputFormatSpec)
	}
	if cfg.ParseTimeoutSeconds <= 0 {
		cfg.ParseTimeoutSeconds = 30
	}
	if stringsTrim(cfg.DefaultPath) == "" {
		cfg.DefaultPath = "/tmp/shadow"
	}

	preferred := stringsTrim(cfg.PreferredFormat)
	if preferred == "" {
		switch {
		case stringsTrim(cfg.FileFlag) != "" && stringsTrim(cfg.JsonFlag) != "":
			preferred = "json"
			cfg.Formats[preferred] = shadowOutputFormatSpec{
				Transport:     "file",
				EnableFlags:   []string{cfg.JsonFlag},
				PathFlag:      cfg.FileFlag,
				Parser:        "json",
				PathMode:      "file",
				FileExtension: ".json",
			}
		case stringsTrim(cfg.FileFlag) != "":
			preferred = "raw"
			cfg.Formats[preferred] = shadowOutputFormatSpec{
				Transport: "file",
				PathFlag:  cfg.FileFlag,
				Parser:    "raw",
				PathMode:  "file",
			}
		case stringsTrim(cfg.JsonFlag) != "":
			preferred = "json"
			cfg.Formats[preferred] = shadowOutputFormatSpec{
				Transport:   "stdout",
				EnableFlags: []string{cfg.JsonFlag},
				Parser:      "json",
			}
		}
	}

	cfg.PreferredFormat = preferred
	for key, spec := range cfg.Formats {
		if stringsTrim(spec.Transport) == "" {
			spec.Transport = "stdout"
		}
		if stringsTrim(spec.Parser) == "" {
			spec.Parser = "raw"
		}
		if stringsTrim(spec.PathMode) == "" {
			spec.PathMode = "file"
		}
		if spec.EnableFlags == nil {
			spec.EnableFlags = []string{}
		}
		cfg.Formats[key] = spec
	}

	return cfg
}

func buildOptionIndex(cfg toolScanConfig) (map[string]optionSpec, map[string]optionSpec) {
	byKey := make(map[string]optionSpec)
	byFlag := make(map[string]optionSpec)

	merge := func(options []optionSpec) {
		for _, opt := range options {
			if strings.TrimSpace(opt.Key) != "" {
				byKey[opt.Key] = opt
			}
			norm := normalizeFlag(opt.Flag)
			if norm != "" {
				byFlag[norm] = opt
			}
		}
	}

	merge(cfg.Medium.Options)
	merge(cfg.Advanced.Options)
	return byKey, byFlag
}

func buildInputIndex(schema inputSchemaSpec) (map[string]inputFieldSpec, []string) {
	byKey := make(map[string]inputFieldSpec, len(schema.Fields))
	order := make([]string, 0, len(schema.Fields))
	for _, f := range schema.Fields {
		if strings.TrimSpace(f.Key) == "" {
			continue
		}
		byKey[f.Key] = f
		order = append(order, f.Key)
	}
	return byKey, order
}

func injectTargetValueIntoToolArgs(toolArgs map[string]string, schema inputSchemaSpec, targetValue string) map[string]string {
	target := strings.TrimSpace(targetValue)
	if target == "" {
		return toolArgs
	}

	targetFieldName := stringsTrim(schema.PipelineInput.TargetField)

	// First pass: fill missing required input.
	missingRequired := make([]inputFieldSpec, 0, len(schema.Fields))
	for _, field := range schema.Fields {
		key := strings.TrimSpace(field.Key)
		if key == "" || !field.Required {
			continue
		}
		if strings.TrimSpace(toolArgs[key]) != "" {
			continue
		}
		missingRequired = append(missingRequired, field)
	}

	if len(missingRequired) > 0 {
		targetCandidates := filterTargetCandidates(missingRequired, targetFieldName, len(schema.Fields) == 1)
		if len(targetCandidates) == 1 {
			toolArgs[targetCandidates[0].Key] = target
			return toolArgs
		}

		// Prefer common target-like keys when there are multiple choices.
		for _, preferred := range preferredTargetInputKeys {
			for _, field := range targetCandidates {
				if strings.EqualFold(field.Key, preferred) {
					toolArgs[field.Key] = target
					return toolArgs
				}
			}
		}
		for _, field := range targetCandidates {
			if strings.EqualFold(field.Key, targetFieldName) {
				toolArgs[field.Key] = target
				return toolArgs
			}
		}
	}

	// Second pass: some tool definitions mark target fields as optional.
	missingAny := make([]inputFieldSpec, 0, len(schema.Fields))
	for _, field := range schema.Fields {
		key := strings.TrimSpace(field.Key)
		if key == "" {
			continue
		}
		if strings.TrimSpace(toolArgs[key]) != "" {
			continue
		}
		missingAny = append(missingAny, field)
	}
	targetCandidates := filterTargetCandidates(missingAny, targetFieldName, len(schema.Fields) == 1)
	if len(targetCandidates) == 1 {
		toolArgs[targetCandidates[0].Key] = target
		return toolArgs
	}
	for _, preferred := range preferredTargetInputKeys {
		for _, field := range targetCandidates {
			if strings.EqualFold(field.Key, preferred) {
				toolArgs[field.Key] = target
				return toolArgs
			}
		}
	}
	for _, field := range targetCandidates {
		if strings.EqualFold(field.Key, targetFieldName) {
			toolArgs[field.Key] = target
			return toolArgs
		}
	}

	return toolArgs
}

func filterTargetCandidates(fields []inputFieldSpec, explicitTargetField string, allowFallback bool) []inputFieldSpec {
	candidates := make([]inputFieldSpec, 0, len(fields))
	for _, field := range fields {
		if isTargetLikeField(field.Key, explicitTargetField) {
			candidates = append(candidates, field)
		}
	}
	if len(candidates) > 0 {
		return candidates
	}
	if allowFallback {
		return fields
	}
	return nil
}

func isTargetLikeField(key string, explicitTargetField string) bool {
	trimmed := stringsTrim(key)
	if trimmed == "" {
		return false
	}
	if strings.EqualFold(trimmed, explicitTargetField) {
		return true
	}
	for _, preferred := range preferredTargetInputKeys {
		if strings.EqualFold(trimmed, preferred) {
			return true
		}
	}
	return false
}

func resolveInputFieldFlag(toolName string, field inputFieldSpec) string {
	if flag := strings.TrimSpace(field.Flag); flag != "" {
		return flag
	}

	perTool, ok := toolSpecificInputFlagFallbacks[strings.ToLower(strings.TrimSpace(toolName))]
	if !ok {
		return ""
	}
	return strings.TrimSpace(perTool[strings.ToLower(strings.TrimSpace(field.Key))])
}

func validateRequiredInputs(toolArgs map[string]string, customFlags []*advancedpb.CustomFlag, systemArgs []string, schema inputSchemaSpec) error {
	pipelineListFlag := normalizeFlag(schema.PipelineInput.ListFlag)
	pipelineTargetField := stringsTrim(schema.PipelineInput.TargetField)
	hasListTransport := strings.EqualFold(stringsTrim(schema.PipelineInput.MultiMode), "list_file") &&
		pipelineListFlag != "" &&
		(hasCustomFlag(customFlags, pipelineListFlag) || hasSystemFlag(systemArgs, pipelineListFlag))

	for _, field := range schema.Fields {
		if !field.Required {
			continue
		}
		if hasListTransport && (pipelineTargetField == "" || strings.EqualFold(field.Key, pipelineTargetField)) {
			continue
		}
		val := strings.TrimSpace(toolArgs[field.Key])
		if val == "" {
			return fmt.Errorf("missing required input %q", field.Key)
		}
	}
	return nil
}

func hasSystemFlag(args []string, normalizedFlag string) bool {
	for _, arg := range args {
		if normalizeFlag(arg) == normalizedFlag {
			return true
		}
	}
	return false
}

func coerceOptionValue(spec optionSpec, raw string) (string, bool, error) {
	value := strings.TrimSpace(raw)

	switch strings.ToLower(strings.TrimSpace(spec.Type)) {
	case "", "string":
		if err := validateEnum(spec.Enum, value); err != nil {
			return "", false, err
		}
		if value == "" {
			return "", false, fmt.Errorf("value is required")
		}
		return value, true, nil
	case "integer", "int":
		if value == "" {
			return "", false, fmt.Errorf("integer value is required")
		}
		if _, err := strconv.Atoi(value); err != nil {
			return "", false, fmt.Errorf("expected integer")
		}
		if err := validateEnum(spec.Enum, value); err != nil {
			return "", false, err
		}
		return value, true, nil
	case "number", "float", "double":
		if value == "" {
			return "", false, fmt.Errorf("number value is required")
		}
		if _, err := strconv.ParseFloat(value, 64); err != nil {
			return "", false, fmt.Errorf("expected number")
		}
		if err := validateEnum(spec.Enum, value); err != nil {
			return "", false, err
		}
		return value, true, nil
	case "boolean", "bool":
		if value == "" {
			return "", true, nil
		}
		b, err := parseBool(value)
		if err != nil {
			return "", false, err
		}
		if !b {
			return "", false, nil
		}
		return "", true, nil
	default:
		if value == "" {
			return "", false, fmt.Errorf("value is required")
		}
		if err := validateEnum(spec.Enum, value); err != nil {
			return "", false, err
		}
		return value, true, nil
	}
}

func validateEnum(enumValues []any, value string) error {
	if len(enumValues) == 0 {
		return nil
	}
	for _, enumVal := range enumValues {
		if fmt.Sprint(enumVal) == value {
			return nil
		}
	}
	return fmt.Errorf("value %q is not in allowed enum", value)
}

func validateValueSanity(value string) error {
	if strings.ContainsRune(value, '\x00') {
		return fmt.Errorf("contains null byte")
	}
	if strings.ContainsAny(value, "\r\n") {
		return fmt.Errorf("contains newline")
	}
	return nil
}

func normalizeFlag(flag string) string {
	trimmed := strings.TrimSpace(flag)
	if i := strings.Index(trimmed, "="); i >= 0 {
		trimmed = trimmed[:i]
	}
	if strings.HasPrefix(trimmed, "--") {
		return strings.ToLower(trimmed)
	}
	return trimmed
}

func parseBool(v string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true, nil
	case "0", "false", "no", "off":
		return false, nil
	default:
		return false, fmt.Errorf("expected boolean")
	}
}

func hasBareCustomFlag(flags []*advancedpb.CustomFlag) bool {
	for _, flag := range flags {
		if flag == nil {
			continue
		}
		if strings.TrimSpace(flag.Value) != "" {
			continue
		}
		if strings.Contains(strings.TrimSpace(flag.Normalized), "=") {
			continue
		}
		return true
	}
	return false
}

func hasCustomFlag(flags []*advancedpb.CustomFlag, normalizedFlag string) bool {
	if normalizedFlag == "" {
		return false
	}
	for _, flag := range flags {
		if flag == nil {
			continue
		}
		if normalizeFlag(flag.Normalized) == normalizedFlag {
			return true
		}
	}
	return false
}
