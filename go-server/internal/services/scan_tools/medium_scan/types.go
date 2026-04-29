package mediumscan

const (
	OptionTypeInteger = "integer"
	OptionTypeString  = "string"
	OptionTypeBoolean = "boolean"
	OptionTypeArray   = "array"
)

// ToolConfig models the portion of tool configuration used by medium scan.
type ToolConfig struct {
	ScanConfig ScanConfig `json:"scan_config"`
}

// ScanConfig contains scan mode configuration sections.
type ScanConfig struct {
	Medium MediumConfig `json:"medium"`
}

// MediumConfig defines allowed options for medium scans.
type MediumConfig struct {
	Options                      []OptionDefinition `json:"options"`
	DefaultRuntimeTimeoutSeconds int32              `json:"default_runtime_timeout_seconds"`
}

// OptionDefinition declares a single user option.
type OptionDefinition struct {
	Key  string `json:"key"`
	Flag string `json:"flag"`
	Type string `json:"type"`
}

// ExtractedOptions keeps allowed options in both map form (fast validation)
// and list form (stable flag ordering from config).
type ExtractedOptions struct {
	ByKey   map[string]OptionDefinition
	Ordered []OptionDefinition
}

// ValidatedOption contains a normalized value ready for CLI generation.
type ValidatedOption struct {
	Definition OptionDefinition
	Value      any
}
