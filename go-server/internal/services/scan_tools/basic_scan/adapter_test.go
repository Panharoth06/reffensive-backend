package basicscan

import (
	"testing"

	basicpb "go-server/gen/basic"
)

func TestToAdvancedSubmitRequest_NormalizesToolNameToLowercase(t *testing.T) {
	req := &basicpb.SubmitScanRequest{
		ProjectId: "project-1",
		Target:    "example.com",
		ToolName:  "Subfinder",
	}

	out, err := toAdvancedSubmitRequest(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.GetCommand() != "subfinder" {
		t.Fatalf("unexpected command: got %q want %q", out.GetCommand(), "subfinder")
	}
}
