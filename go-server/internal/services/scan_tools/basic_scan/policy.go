package basicscan

import (
	"fmt"
	"regexp"
	"strings"
)

var sensitiveNamePattern = regexp.MustCompile(`(?i)(token|password|passwd|secret|api[-_]?key|authorization|bearer|cookie|session|private[-_]?key|client[-_]?secret)`)
var sensitiveAssignmentPattern = regexp.MustCompile(`(?i)(token|password|passwd|secret|api[-_]?key|authorization|bearer|cookie|session|private[-_]?key|client[-_]?secret)\s*=`)

func parseCustomFlags(rawFlags []string) ([]string, error) {
	return normalizeRawFlags(rawFlags)
}

func normalizeToolArgs(toolArgs map[string]string) (map[string]string, error) {
	if err := validateToolArgs(toolArgs); err != nil {
		return nil, err
	}
	out := make(map[string]string, len(toolArgs))
	for key, value := range toolArgs {
		out[stringsTrim(key)] = stringsTrim(value)
	}
	return out, nil
}

func validateToolArgs(toolArgs map[string]string) error {
	for key, value := range toolArgs {
		trimmedKey := stringsTrim(key)
		if trimmedKey == "" {
			return fmt.Errorf("tool_args key cannot be empty")
		}
		if sensitiveNamePattern.MatchString(trimmedKey) {
			return fmt.Errorf("tool_args key %q is not allowed for security reasons", key)
		}
		if strings.ContainsRune(value, '\x00') {
			return fmt.Errorf("invalid value for tool_args %q: contains null byte", key)
		}
		if strings.ContainsAny(value, "\r\n") {
			return fmt.Errorf("invalid value for tool_args %q: contains newline", key)
		}
		if sensitiveAssignmentPattern.MatchString(value) {
			return fmt.Errorf("invalid value for tool_args %q: contains sensitive assignment", key)
		}
	}
	return nil
}

func normalizeRawFlags(rawFlags []string) ([]string, error) {
	seen := make(map[string]struct{}, len(rawFlags))
	out := make([]string, 0, len(rawFlags))
	for _, item := range rawFlags {
		flag := stringsTrim(item)
		if flag == "" {
			continue
		}
		// Deduplicate exact raw flags while preserving order.
		if _, ok := seen[flag]; ok {
			continue
		}
		seen[flag] = struct{}{}
		out = append(out, flag)
	}
	return out, nil
}
