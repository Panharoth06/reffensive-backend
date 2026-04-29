package advancedscan

import (
	"strings"
	"testing"

	advancedpb "go-server/gen/advanced"
)

func TestResolveToolRuntime_DefaultsToBridgeAndGVisor(t *testing.T) {
	t.Parallel()

	gotGVisor, gotNetwork, gotPrivileged, gotCapabilities, err := resolveToolRuntime(toolScanConfig{}, nil)
	if err != nil {
		t.Fatalf("resolveToolRuntime() returned unexpected error: %v", err)
	}
	if !gotGVisor {
		t.Fatal("expected gVisor to stay enabled")
	}
	if gotNetwork != "bridge" {
		t.Fatalf("expected bridge network, got %q", gotNetwork)
	}
	if gotPrivileged {
		t.Fatal("expected privileged to remain false")
	}
	if len(gotCapabilities) != 0 {
		t.Fatalf("expected no capabilities, got %v", gotCapabilities)
	}
}

func TestResolveToolRuntime_RequestNetworkWins(t *testing.T) {
	t.Parallel()

	gotGVisor, gotNetwork, gotPrivileged, gotCapabilities, err := resolveToolRuntime(toolScanConfig{}, &advancedpb.ExecutionConfig{
		NetworkPolicy: &advancedpb.NetworkPolicy{
			Mode: advancedpb.NetworkMode_NETWORK_MODE_NONE,
		},
	})
	if err != nil {
		t.Fatalf("resolveToolRuntime() returned unexpected error: %v", err)
	}
	if !gotGVisor {
		t.Fatal("expected gVisor default true")
	}
	if gotNetwork != "none" {
		t.Fatalf("expected request network mode to win, got %q", gotNetwork)
	}
	if gotPrivileged {
		t.Fatal("expected privileged default false")
	}
	if len(gotCapabilities) != 0 {
		t.Fatalf("expected no capabilities, got %v", gotCapabilities)
	}
}

func TestResolveToolRuntime_RejectsUnsafeOverrides(t *testing.T) {
	t.Parallel()

	disabled := false
	privileged := true
	tests := []struct {
		name       string
		cfg        toolScanConfig
		req        *advancedpb.ExecutionConfig
		wantErr    string
		wantUseG   bool
		wantCapAdd []string
	}{
		{
			name: "tool can disable gvisor",
			cfg: toolScanConfig{
				Runtime: toolRuntimeConfig{
					UseGVisor: &disabled,
				},
			},
			wantUseG: false,
		},
		{
			name: "tool can request net raw capability",
			cfg: toolScanConfig{
				Runtime: toolRuntimeConfig{
					CapAdd: []string{"NET_RAW", "cap_net_raw"},
				},
			},
			wantUseG:   true,
			wantCapAdd: []string{"NET_RAW"},
		},
		{
			name: "tool requests forbidden capability",
			cfg: toolScanConfig{
				Runtime: toolRuntimeConfig{
					CapAdd: []string{"NET_ADMIN"},
				},
			},
			wantErr: "runtime capability \"NET_ADMIN\" is forbidden",
		},
		{
			name: "tool requests privileged",
			cfg: toolScanConfig{
				Runtime: toolRuntimeConfig{
					Privileged: &privileged,
				},
			},
			wantErr: "privileged execution is forbidden",
		},
		{
			name: "tool requests host network",
			cfg: toolScanConfig{
				Runtime: toolRuntimeConfig{
					NetworkMode: "host",
				},
			},
			wantErr: "host networking is forbidden",
		},
		{
			name: "request asks for host network",
			req: &advancedpb.ExecutionConfig{
				NetworkPolicy: &advancedpb.NetworkPolicy{
					Mode: advancedpb.NetworkMode_NETWORK_MODE_HOST,
				},
			},
			wantErr: "host networking is forbidden",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			gotUseGVisor, _, _, gotCapAdd, err := resolveToolRuntime(tt.cfg, tt.req)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
				if gotUseGVisor != tt.wantUseG {
					t.Fatalf("expected use_gvisor=%v, got %v", tt.wantUseG, gotUseGVisor)
				}
				if strings.Join(gotCapAdd, ",") != strings.Join(tt.wantCapAdd, ",") {
					t.Fatalf("expected cap_add=%v, got %v", tt.wantCapAdd, gotCapAdd)
				}
				return
			}
			if err == nil {
				t.Fatal("expected runtime policy error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}
