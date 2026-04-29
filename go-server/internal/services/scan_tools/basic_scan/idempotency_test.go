package basicscan

import "testing"

func TestNormalizeIdempotencyKey_Trim(t *testing.T) {
	got := normalizeIdempotencyKey("  abc-123  ")
	if got != "abc-123" {
		t.Fatalf("expected trimmed idempotency key, got %q", got)
	}
}
