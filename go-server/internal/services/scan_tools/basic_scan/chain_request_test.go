package basicscan

import (
	"testing"

	basicpb "go-server/gen/basic"
)

func TestBuildBasicSubmitRequest_MapsFields(t *testing.T) {
	req := &basicpb.SubmitScanRequest{
		ProjectId:      "project-1",
		Target:         "example.com",
		TargetId:       "target-1",
		ToolName:       "subfinder",
		IdempotencyKey: "  idem-123 ",
		ToolArgs: map[string]string{
			"domain": " example.com ",
		},
		CustomFlags: []string{" -silent ", "-silent"},
	}

	out, err := buildBasicSubmitRequest(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.GetToolName() != "subfinder" {
		t.Fatalf("unexpected tool name: %q", out.GetToolName())
	}
	if out.GetTarget() != "example.com" {
		t.Fatalf("unexpected target value: %q", out.GetTarget())
	}
	if out.GetToolArgs()["domain"] != "example.com" {
		t.Fatalf("unexpected tool arg domain: %#v", out.GetToolArgs())
	}
	if out.GetIdempotencyKey() != "idem-123" {
		t.Fatalf("unexpected idempotency key: %q", out.GetIdempotencyKey())
	}
	if len(out.GetCustomFlags()) != 1 || out.GetCustomFlags()[0] != "-silent" {
		t.Fatalf("unexpected custom flags: %#v", out.GetCustomFlags())
	}
}
