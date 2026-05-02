package docker

import (
	"strings"
	"testing"
)

func TestNormalizeImagePullPolicy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   ImagePullPolicy
		want ImagePullPolicy
	}{
		{name: "empty defaults to if missing", in: "", want: ImagePullIfMissing},
		{name: "if missing stays if missing", in: ImagePullIfMissing, want: ImagePullIfMissing},
		{name: "never stays never", in: ImagePullNever, want: ImagePullNever},
		{name: "unknown falls back to if missing", in: ImagePullPolicy("always"), want: ImagePullIfMissing},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := normalizeImagePullPolicy(tt.in); got != tt.want {
				t.Fatalf("normalizeImagePullPolicy(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestValidateExecutionPolicy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     ToolConfig
		wantErr string
	}{
		{
			name: "safe config",
			cfg: ToolConfig{
				UseGVisor:   true,
				NetworkMode: "bridge",
			},
		},
		{
			name: "allows regular runc runtime",
			cfg: ToolConfig{
				NetworkMode: "bridge",
			},
		},
		{
			name: "allows net raw capability",
			cfg: ToolConfig{
				NetworkMode: "bridge",
				CapAdd:      []string{"NET_RAW"},
			},
		},
		{
			name: "rejects forbidden capability",
			cfg: ToolConfig{
				NetworkMode: "bridge",
				CapAdd:      []string{"NET_ADMIN"},
			},
			wantErr: "capability \"NET_ADMIN\" is forbidden",
		},
		{
			name: "rejects host network",
			cfg: ToolConfig{
				UseGVisor:   true,
				NetworkMode: "host",
			},
			wantErr: "host network mode is forbidden",
		},
		{
			name: "rejects privileged",
			cfg: ToolConfig{
				UseGVisor:   true,
				NetworkMode: "bridge",
				Privileged:  true,
			},
			wantErr: "privileged containers are forbidden",
		},
		{
			name: "rejects docker socket mounts",
			cfg: ToolConfig{
				UseGVisor:   true,
				NetworkMode: "bridge",
				Volumes:     []string{"/var/run/docker.sock:/var/run/docker.sock"},
			},
			wantErr: "docker socket mounts are forbidden",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := validateExecutionPolicy(tt.cfg)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("validateExecutionPolicy() returned unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected validation error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}
