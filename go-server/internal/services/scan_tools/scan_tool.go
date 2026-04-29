package scantools

import (
	"encoding/json"
	"fmt"

	mediumscan "go-server/internal/services/scan_tools/medium_scan"
)

// BuildMediumFlags builds CLI flags for medium scan mode using typed config.
func BuildMediumFlags(cfg mediumscan.ToolConfig, userOptions map[string]any) ([]string, error) {
	return mediumscan.BuildMediumScanFlags(cfg, userOptions)
}

// BuildMediumFlagsFromJSON builds medium scan flags directly from tool JSON bytes.
func BuildMediumFlagsFromJSON(toolJSON []byte, userOptions map[string]any) ([]string, error) {
	var cfg mediumscan.ToolConfig
	if err := json.Unmarshal(toolJSON, &cfg); err != nil {
		return nil, fmt.Errorf("unmarshal tool config: %w", err)
	}

	return BuildMediumFlags(cfg, userOptions)
}
