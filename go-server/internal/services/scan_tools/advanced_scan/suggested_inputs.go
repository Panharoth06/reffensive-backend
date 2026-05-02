package advancedscan

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	db "go-server/internal/database/sqlc"

	"github.com/google/uuid"
)

func (s *advancedScanServer) loadPipelineLinesFromStoredStep(stepUUID uuid.UUID) ([]string, error) {
	stepRow, err := s.queries.GetScanStepByID(context.Background(), stepUUID)
	if err != nil {
		return nil, fmt.Errorf("load scan step: %w", err)
	}

	toolRow, err := s.queries.GetToolByID(context.Background(), stepRow.ToolID)
	if err != nil {
		return nil, fmt.Errorf("load tool for input step: %w", err)
	}

	resultsRows, err := s.queries.ListScanResultsByStep(context.Background(), db.ListScanResultsByStepParams{
		StepID: stepRow.StepID,
		JobID:  stepRow.JobID,
	})
	if err != nil {
		return nil, fmt.Errorf("load parsed results for input step: %w", err)
	}

	lines := make([]string, 0, 32)
	for _, row := range resultsRows {
		lines = append(lines, parsedDataToJSONLines(row.ParsedData)...)
	}
	if len(lines) == 0 {
		return nil, fmt.Errorf("input step has no parsed_data available")
	}

	return extractPipelineOutputs(toolRow, strings.Join(lines, "\n")), nil
}

func parsedDataToJSONLines(raw []byte) []string {
	if len(raw) == 0 {
		return nil
	}

	var parsed any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil
	}

	switch value := parsed.(type) {
	case []any:
		out := make([]string, 0, len(value))
		for _, item := range value {
			encoded, err := json.Marshal(item)
			if err != nil {
				continue
			}
			out = append(out, string(encoded))
		}
		return out
	case map[string]any:
		encoded, err := json.Marshal(value)
		if err != nil {
			return nil
		}
		return []string{string(encoded)}
	default:
		return nil
	}
}
