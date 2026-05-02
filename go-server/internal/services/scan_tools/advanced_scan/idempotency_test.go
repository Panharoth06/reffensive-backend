package advancedscan

import (
	"testing"

	advancedpb "go-server/gen/advanced"
)

func TestIdempotencyHash_IgnoresRetryFields(t *testing.T) {
	base := &advancedpb.SubmitScanRequest{
		JobId:          "11111111-1111-1111-1111-111111111111",
		StepId:         "22222222-2222-2222-2222-222222222222",
		ToolName:       "subfinder",
		ProjectId:      "33333333-3333-3333-3333-333333333333",
		TargetId:       "44444444-4444-4444-4444-444444444444",
		IdempotencyKey: "idem-1",
		ToolArgs: map[string]string{
			"domain": "example.com",
		},
	}
	retry := &advancedpb.SubmitScanRequest{
		JobId:          "",
		StepId:         "",
		ToolName:       "subfinder",
		ProjectId:      "33333333-3333-3333-3333-333333333333",
		TargetId:       "44444444-4444-4444-4444-444444444444",
		IdempotencyKey: "idem-1",
		ToolArgs: map[string]string{
			"domain": "example.com",
		},
	}

	h1, err := idempotencyHashForRequest(base)
	if err != nil {
		t.Fatalf("hash base: %v", err)
	}
	h2, err := idempotencyHashForRequest(retry)
	if err != nil {
		t.Fatalf("hash retry: %v", err)
	}
	if h1 != h2 {
		t.Fatalf("expected hashes to match for retries, got %q vs %q", h1, h2)
	}
}

func TestIdempotencyHash_ChangesWithPayload(t *testing.T) {
	a := &advancedpb.SubmitScanRequest{
		ToolName:       "subfinder",
		ProjectId:      "33333333-3333-3333-3333-333333333333",
		TargetId:       "44444444-4444-4444-4444-444444444444",
		IdempotencyKey: "idem-1",
		ToolArgs: map[string]string{
			"domain": "example.com",
		},
	}
	b := &advancedpb.SubmitScanRequest{
		ToolName:       "subfinder",
		ProjectId:      "33333333-3333-3333-3333-333333333333",
		TargetId:       "44444444-4444-4444-4444-444444444444",
		IdempotencyKey: "idem-1",
		ToolArgs: map[string]string{
			"domain": "example.org",
		},
	}

	h1, err := idempotencyHashForRequest(a)
	if err != nil {
		t.Fatalf("hash a: %v", err)
	}
	h2, err := idempotencyHashForRequest(b)
	if err != nil {
		t.Fatalf("hash b: %v", err)
	}
	if h1 == h2 {
		t.Fatalf("expected different hashes for different payloads")
	}
}
