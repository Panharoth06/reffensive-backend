package aisuggestion

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

type AIContextInput struct {
	JobID          string           `json:"job_id"`
	ProjectID      string           `json:"project_id"`
	Status         string           `json:"status"`
	Target         AITargetContext  `json:"target"`
	SeverityCounts map[string]int   `json:"severity_counts"`
	Findings       []AIFindingInput `json:"findings"`
	Results        []AIResultInput  `json:"results"`
}

type AITargetContext struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	Description string `json:"description"`
}

type AIFindingInput struct {
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Fingerprint string `json:"fingerprint"`
	ToolName    string `json:"tool_name"`
}

type AIResultInput struct {
	ToolName   string         `json:"tool_name"`
	Severity   string         `json:"severity"`
	ParsedData map[string]any `json:"parsed_data,omitempty"`
	RawPreview string         `json:"raw_preview"`
}

type aiContextBuilder struct {
	store suggestionResultStore
}

func BuildAIContext(ctx context.Context, jobID string) (AIContextInput, error) {
	jobUUID, err := uuid.Parse(strings.TrimSpace(jobID))
	if err != nil {
		return AIContextInput{}, fmt.Errorf("parse job id: %w", err)
	}

	store, err := getSuggestionResultStore()
	if err != nil {
		return AIContextInput{}, err
	}

	return newAIContextBuilder(store).Build(ctx, jobUUID)
}

func newAIContextBuilder(store suggestionResultStore) *aiContextBuilder {
	return &aiContextBuilder{store: store}
}

func (b *aiContextBuilder) Build(ctx context.Context, jobUUID uuid.UUID) (AIContextInput, error) {
	jobRow, err := b.store.GetQueries().GetScanJobByID(ctx, jobUUID)
	if err != nil {
		return AIContextInput{}, fmt.Errorf("load scan job: %w", err)
	}

	targetRow, err := b.store.GetQueries().GetTargetByID(ctx, jobRow.TargetID)
	if err != nil {
		return AIContextInput{}, fmt.Errorf("load target: %w", err)
	}

	findingsRows, err := b.store.GetQueries().ListFindingsByJob(ctx, jobRow.JobID)
	if err != nil {
		return AIContextInput{}, fmt.Errorf("load findings: %w", err)
	}

	resultRows, err := b.store.GetQueries().ListScanResultsByJob(ctx, jobRow.JobID)
	if err != nil {
		return AIContextInput{}, fmt.Errorf("load scan results: %w", err)
	}

	toolNames := make(map[uuid.UUID]string)
	severityCounts := make(map[string]int)
	findings := make([]AIFindingInput, 0, len(findingsRows))
	for _, row := range findingsRows {
		severity := normalizeSeverity(row.Severity)
		severityCounts[severity]++

		findings = append(findings, AIFindingInput{
			Title:       strings.TrimSpace(row.Title.String),
			Severity:    severity,
			Host:        strings.TrimSpace(row.Host.String),
			Port:        nullPortToInt(row.Port),
			Fingerprint: strings.TrimSpace(row.Fingerprint.String),
			ToolName:    b.toolName(ctx, toolNames, row.ToolID),
		})
	}

	sort.SliceStable(findings, func(i, j int) bool {
		return severityRank(findings[i].Severity) > severityRank(findings[j].Severity)
	})

	results := make([]AIResultInput, 0, len(resultRows))
	for _, row := range resultRows {
		results = append(results, AIResultInput{
			ToolName:   b.toolName(ctx, toolNames, row.ToolID),
			Severity:   normalizeSeverity(row.Severity),
			ParsedData: decodeJSONObject(row.ParsedData),
			RawPreview: truncateUTF8(string(row.RawData), 500),
		})
	}

	return AIContextInput{
		JobID:     jobRow.JobID.String(),
		ProjectID: jobRow.ProjectID.String(),
		Status:    normalizeJobStatus(jobRow.Status),
		Target: AITargetContext{
			ID:          targetRow.TargetID.String(),
			Name:        targetRow.Name,
			Type:        targetRow.Type,
			Description: strings.TrimSpace(targetRow.Description.String),
		},
		SeverityCounts: severityCounts,
		Findings:       findings,
		Results:        results,
	}, nil
}

func (b *aiContextBuilder) toolName(ctx context.Context, cache map[uuid.UUID]string, toolID uuid.UUID) string {
	if name := cache[toolID]; name != "" {
		return name
	}

	name := toolID.String()
	toolRow, err := b.store.GetQueries().GetToolByID(ctx, toolID)
	if err == nil && strings.TrimSpace(toolRow.ToolName) != "" {
		name = strings.TrimSpace(toolRow.ToolName)
	}

	cache[toolID] = name
	return name
}

func decodeJSONObject(raw []byte) map[string]any {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}

	var object map[string]any
	if err := json.Unmarshal(raw, &object); err == nil {
		return object
	}

	var value any
	if err := json.Unmarshal(raw, &value); err == nil {
		return map[string]any{"value": value}
	}

	return map[string]any{"raw": truncateUTF8(string(raw), 500)}
}

func nullPortToInt(value pgtype.Int4) int {
	if !value.Valid {
		return 0
	}
	return int(value.Int32)
}
