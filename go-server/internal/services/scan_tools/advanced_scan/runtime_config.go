package advancedscan

import (
	"fmt"
	"strings"

	advancedpb "go-server/gen/advanced"
)

var allowedRuntimeCapabilities = map[string]struct{}{
	"NET_RAW": {},
}

func resolveToolRuntime(scanCfg toolScanConfig, execCfg *advancedpb.ExecutionConfig) (useGVisor bool, networkMode string, privileged bool, capAdd []string, err error) {
	useGVisor = true
	if scanCfg.Runtime.UseGVisor != nil {
		useGVisor = *scanCfg.Runtime.UseGVisor
	}

	networkMode = networkModeToDocker(execCfg)
	if stringsTrim(networkMode) == "" {
		switch strings.ToLower(stringsTrim(scanCfg.Runtime.NetworkMode)) {
		case "bridge", "host", "none":
			networkMode = strings.ToLower(stringsTrim(scanCfg.Runtime.NetworkMode))
		}
	}
	if stringsTrim(networkMode) == "" {
		networkMode = "bridge"
	}
	if networkMode == "host" {
		return false, "", false, nil, fmt.Errorf("host networking is forbidden")
	}

	if scanCfg.Runtime.Privileged != nil && *scanCfg.Runtime.Privileged {
		return false, "", false, nil, fmt.Errorf("privileged execution is forbidden")
	}

	capAdd, err = normalizeRuntimeCapabilities(scanCfg.Runtime.CapAdd)
	if err != nil {
		return false, "", false, nil, err
	}

	return useGVisor, networkMode, false, capAdd, nil
}

func normalizeRuntimeCapabilities(rawCapabilities []string) ([]string, error) {
	if len(rawCapabilities) == 0 {
		return nil, nil
	}

	normalizedCapabilities := make([]string, 0, len(rawCapabilities))
	seenCapabilities := make(map[string]struct{}, len(rawCapabilities))
	for _, rawCapability := range rawCapabilities {
		normalizedCapability := strings.ToUpper(strings.TrimSpace(rawCapability))
		normalizedCapability = strings.TrimPrefix(normalizedCapability, "CAP_")
		if normalizedCapability == "" {
			continue
		}
		if _, allowed := allowedRuntimeCapabilities[normalizedCapability]; !allowed {
			return nil, fmt.Errorf("runtime capability %q is forbidden", normalizedCapability)
		}
		if _, duplicate := seenCapabilities[normalizedCapability]; duplicate {
			continue
		}
		seenCapabilities[normalizedCapability] = struct{}{}
		normalizedCapabilities = append(normalizedCapabilities, normalizedCapability)
	}

	if len(normalizedCapabilities) == 0 {
		return nil, nil
	}
	return normalizedCapabilities, nil
}
