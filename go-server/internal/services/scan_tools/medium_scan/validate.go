package mediumscan

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
)

// ValidateMediumOptions checks user options against allowed options and enforces
// type correctness.
func ValidateMediumOptions(userOptions map[string]any, allowed ExtractedOptions) (map[string]ValidatedOption, error) {
	validated := make(map[string]ValidatedOption, len(userOptions))

	for key, raw := range userOptions {
		definition, exists := allowed.ByKey[key]
		if !exists {
			return nil, fmt.Errorf("unknown medium option %q", key)
		}

		normalized, err := normalizeByType(raw, definition.Type)
		if err != nil {
			return nil, fmt.Errorf("invalid value for option %q: %w", key, err)
		}

		validated[key] = ValidatedOption{Definition: definition, Value: normalized}
	}

	return validated, nil
}

func normalizeByType(raw any, optionType string) (any, error) {
	switch optionType {
	case OptionTypeInteger:
		return normalizeInteger(raw)
	case OptionTypeString:
		value, ok := raw.(string)
		if !ok {
			return nil, fmt.Errorf("expected string")
		}
		return value, nil
	case OptionTypeBoolean:
		value, ok := raw.(bool)
		if !ok {
			return nil, fmt.Errorf("expected boolean")
		}
		return value, nil
	case OptionTypeArray:
		return normalizeArray(raw)
	default:
		return nil, fmt.Errorf("unsupported type %q", optionType)
	}
}

func normalizeInteger(raw any) (int64, error) {
	switch v := raw.(type) {
	case int:
		return int64(v), nil
	case int8:
		return int64(v), nil
	case int16:
		return int64(v), nil
	case int32:
		return int64(v), nil
	case int64:
		return v, nil
	case uint:
		if uint64(v) > math.MaxInt64 {
			return 0, fmt.Errorf("integer overflows int64")
		}
		return int64(v), nil
	case uint8:
		return int64(v), nil
	case uint16:
		return int64(v), nil
	case uint32:
		return int64(v), nil
	case uint64:
		if v > math.MaxInt64 {
			return 0, fmt.Errorf("integer overflows int64")
		}
		return int64(v), nil
	case float32:
		fv := float64(v)
		if math.Trunc(fv) != fv {
			return 0, fmt.Errorf("expected integer")
		}
		if fv > math.MaxInt64 || fv < math.MinInt64 {
			return 0, fmt.Errorf("integer out of int64 range")
		}
		return int64(fv), nil
	case float64:
		if math.Trunc(v) != v {
			return 0, fmt.Errorf("expected integer")
		}
		if v > math.MaxInt64 || v < math.MinInt64 {
			return 0, fmt.Errorf("integer out of int64 range")
		}
		return int64(v), nil
	default:
		return 0, fmt.Errorf("expected integer")
	}
}

func normalizeArray(raw any) ([]string, error) {
	switch v := raw.(type) {
	case []string:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if item == "" {
				return nil, fmt.Errorf("expected non-empty array items")
			}
			out = append(out, item)
		}
		return out, nil
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			normalized, err := normalizeArrayItem(item)
			if err != nil {
				return nil, err
			}
			out = append(out, normalized)
		}
		return out, nil
	case string:
		var decoded []any
		if err := json.Unmarshal([]byte(v), &decoded); err != nil {
			return nil, fmt.Errorf("expected JSON array string")
		}
		return normalizeArray(decoded)
	default:
		return nil, fmt.Errorf("expected array")
	}
}

func normalizeArrayItem(raw any) (string, error) {
	switch v := raw.(type) {
	case string:
		if v == "" {
			return "", fmt.Errorf("expected non-empty array items")
		}
		return v, nil
	case bool:
		return strconv.FormatBool(v), nil
	case int:
		return strconv.Itoa(v), nil
	case int8, int16, int32, int64:
		return fmt.Sprintf("%d", v), nil
	case uint, uint8, uint16, uint32, uint64:
		return fmt.Sprintf("%d", v), nil
	case float32:
		if math.Trunc(float64(v)) != float64(v) {
			return "", fmt.Errorf("array number must be an integer-compatible value")
		}
		return strconv.FormatFloat(float64(v), 'f', -1, 32), nil
	case float64:
		if math.Trunc(v) != v {
			return "", fmt.Errorf("array number must be an integer-compatible value")
		}
		return strconv.FormatFloat(v, 'f', -1, 64), nil
	default:
		return "", fmt.Errorf("expected primitive array items")
	}
}
