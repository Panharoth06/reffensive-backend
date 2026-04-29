package basicscan

import (
	"testing"
)

func TestValidateToolArgs_RejectsSensitiveKey(t *testing.T) {
	err := validateToolArgs(map[string]string{
		"api_key": "123",
	})
	if err == nil {
		t.Fatalf("expected sensitive key error, got nil")
	}
}

func TestValidateToolArgs_RejectsSensitiveAssignment(t *testing.T) {
	err := validateToolArgs(map[string]string{
		"domain": "example.com?token=abc",
	})
	if err == nil {
		t.Fatalf("expected sensitive assignment error, got nil")
	}
}

func TestNormalizeRawFlags_DeduplicatesAndTrims(t *testing.T) {
	out, err := normalizeRawFlags([]string{" -silent ", "-silent", "", "  ", "-all"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 2 || out[0] != "-silent" || out[1] != "-all" {
		t.Fatalf("unexpected normalized flags: %#v", out)
	}
}
