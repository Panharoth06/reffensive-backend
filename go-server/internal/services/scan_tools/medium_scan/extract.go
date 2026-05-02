package mediumscan

import "fmt"

// ExtractMediumOptions reads medium options from config and validates
// each allowed option definition.
func ExtractMediumOptions(cfg ToolConfig) (ExtractedOptions, error) {
	result := ExtractedOptions{
		ByKey:   make(map[string]OptionDefinition, len(cfg.ScanConfig.Medium.Options)),
		Ordered: make([]OptionDefinition, 0, len(cfg.ScanConfig.Medium.Options)),
	}

	for i, opt := range cfg.ScanConfig.Medium.Options {
		if opt.Key == "" {
			return ExtractedOptions{}, fmt.Errorf("medium option at index %d has empty key", i)
		}
		if opt.Flag == "" {
			return ExtractedOptions{}, fmt.Errorf("medium option %q has empty flag", opt.Key)
		}
		if !isSupportedType(opt.Type) {
			return ExtractedOptions{}, fmt.Errorf("medium option %q has unsupported type %q", opt.Key, opt.Type)
		}
		if prev, exists := result.ByKey[opt.Key]; exists {
			// Tools sometimes end up with duplicated option definitions in persisted config.
			// If the duplicates are identical, treat them as benign and keep the first.
			if prev.Flag == opt.Flag && prev.Type == opt.Type {
				continue
			}
			return ExtractedOptions{}, fmt.Errorf(
				"duplicate medium option key %q with different definitions (existing flag=%q type=%q, duplicate flag=%q type=%q)",
				opt.Key, prev.Flag, prev.Type, opt.Flag, opt.Type,
			)
		}

		result.ByKey[opt.Key] = opt
		result.Ordered = append(result.Ordered, opt)
	}

	return result, nil
}

func isSupportedType(optionType string) bool {
	switch optionType {
	case OptionTypeInteger, OptionTypeString, OptionTypeBoolean, OptionTypeArray:
		return true
	default:
		return false
	}
}
