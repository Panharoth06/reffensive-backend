package advancedscan

import (
	"strings"

	dockerrunner "go-server/docker"
)

func imagePullPolicyFromSource(source string) dockerrunner.ImagePullPolicy {
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "custom", "local":
		return dockerrunner.ImagePullNever
	default:
		return dockerrunner.ImagePullIfMissing
	}
}
