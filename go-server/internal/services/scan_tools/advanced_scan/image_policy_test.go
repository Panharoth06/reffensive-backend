package advancedscan

import (
	"testing"

	dockerrunner "go-server/docker"
)

func TestImagePullPolicyFromSource(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		source string
		want   dockerrunner.ImagePullPolicy
	}{
		{name: "empty defaults to if missing", source: "", want: dockerrunner.ImagePullIfMissing},
		{name: "dockerhub defaults to if missing", source: "dockerhub", want: dockerrunner.ImagePullIfMissing},
		{name: "custom uses local only", source: "custom", want: dockerrunner.ImagePullNever},
		{name: "local uses local only", source: "local", want: dockerrunner.ImagePullNever},
		{name: "custom is case insensitive", source: " Custom ", want: dockerrunner.ImagePullNever},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := imagePullPolicyFromSource(tt.source); got != tt.want {
				t.Fatalf("imagePullPolicyFromSource(%q) = %q, want %q", tt.source, got, tt.want)
			}
		})
	}
}
