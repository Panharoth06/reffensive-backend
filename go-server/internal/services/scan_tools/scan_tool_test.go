package scantools

import (
	"reflect"
	"testing"
)

func TestBuildMediumFlagsFromJSON(t *testing.T) {
	toolJSON := []byte(`{
		"scan_config": {
			"medium": {
				"options": [
					{"flag": "-timeout", "key": "timeout", "type": "integer"},
					{"flag": "-silent", "key": "silent", "type": "boolean"}
				]
			}
		}
	}`)

	flags, err := BuildMediumFlagsFromJSON(toolJSON, map[string]any{
		"timeout": float64(60),
		"silent":  true,
	})
	if err != nil {
		t.Fatalf("BuildMediumFlagsFromJSON returned error: %v", err)
	}

	want := []string{"-timeout", "60", "-silent"}
	if !reflect.DeepEqual(flags, want) {
		t.Fatalf("unexpected flags: got %v want %v", flags, want)
	}
}
