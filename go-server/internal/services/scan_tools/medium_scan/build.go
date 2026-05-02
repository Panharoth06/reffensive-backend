package mediumscan

import (
	"fmt"
	"strconv"
)

// BuildMediumFlags converts validated options into CLI flags in config-defined order.
func BuildMediumFlags(validated map[string]ValidatedOption, ordered []OptionDefinition) ([]string, error) {
	flags := make([]string, 0, len(validated)*2)

	for _, opt := range ordered {
		entry, ok := validated[opt.Key]
		if !ok {
			continue
		}

		switch opt.Type {
		case OptionTypeBoolean:
			value, ok := entry.Value.(bool)
			if !ok {
				return nil, fmt.Errorf("option %q expected normalized boolean value", opt.Key)
			}
			if value {
				flags = append(flags, opt.Flag)
			}
		case OptionTypeInteger:
			value, ok := entry.Value.(int64)
			if !ok {
				return nil, fmt.Errorf("option %q expected normalized integer value", opt.Key)
			}
			flags = append(flags, opt.Flag, strconv.FormatInt(value, 10))
		case OptionTypeString:
			value, ok := entry.Value.(string)
			if !ok {
				return nil, fmt.Errorf("option %q expected normalized string value", opt.Key)
			}
			flags = append(flags, opt.Flag, value)
		case OptionTypeArray:
			values, ok := entry.Value.([]string)
			if !ok {
				return nil, fmt.Errorf("option %q expected normalized array value", opt.Key)
			}
			for _, value := range values {
				flags = append(flags, opt.Flag, value)
			}
		default:
			return nil, fmt.Errorf("option %q has unsupported type %q", opt.Key, opt.Type)
		}
	}

	return flags, nil
}

// BuildMediumScanFlags is a convenience pipeline: extract -> validate -> build.
func BuildMediumScanFlags(cfg ToolConfig, userOptions map[string]any) ([]string, error) {
	allowed, err := ExtractMediumOptions(cfg)
	if err != nil {
		return nil, err
	}

	validated, err := ValidateMediumOptions(userOptions, allowed)
	if err != nil {
		return nil, err
	}

	return BuildMediumFlags(validated, allowed.Ordered)
}
