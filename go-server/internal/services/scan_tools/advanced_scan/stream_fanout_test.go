package advancedscan

import "testing"

func TestCapturePlainStdoutResultLine(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		line string
		want string
	}{
		{name: "empty", line: "", want: ""},
		{name: "progress", line: "[INF] starting scan", want: ""},
		{name: "hostname", line: "api.example.com", want: "api.example.com"},
		{name: "url with decoration", line: "https://a.example.com [200] [nginx]", want: "https://a.example.com"},
		{name: "ipv4", line: "192.168.1.10", want: "192.168.1.10"},
		{name: "ipv6 bracketed", line: "[2001:db8::1]", want: "2001:db8::1"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := capturePlainStdoutResultLine(tt.line); got != tt.want {
				t.Fatalf("capturePlainStdoutResultLine(%q) = %q, want %q", tt.line, got, tt.want)
			}
		})
	}
}
