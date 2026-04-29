package mediumscan

import (
	"context"
	"encoding/json"
	"strings"

	mediumspb "go-server/gen/mediumscan"
	db "go-server/internal/database/sqlc"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type mediumOutputFieldSpec struct {
	Key                string `json:"key"`
	Type               string `json:"type"`
	Label              string `json:"label"`
	Description        string `json:"description"`
	FindingTitle       bool   `json:"finding_title"`
	FindingSeverity    bool   `json:"finding_severity"`
	FindingHost        bool   `json:"finding_host"`
	FindingDescription bool   `json:"finding_description"`
	PipelineExtract    bool   `json:"pipeline_extract"`
}

type mediumOutputSchemaSpec struct {
	Fields []mediumOutputFieldSpec `json:"fields"`
}

func (s *mediumScanServer) GetParsedData(ctx context.Context, req *mediumspb.GetParsedDataRequest) (*mediumspb.GetParsedDataResponse, error) {
	stepID := stringsTrim(req.GetStepId())
	if stepID == "" {
		return nil, status.Error(codes.InvalidArgument, "step_id is required")
	}
	stepUUID, err := uuid.Parse(stepID)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid step_id: %v", err)
	}

	stepRuntime, jobRuntime, err := s.requireOwnedMediumStep(ctx, stepID)
	if err != nil {
		return nil, err
	}
	jobUUID, err := uuid.Parse(jobRuntime.JobID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "invalid job_id: %v", err)
	}

	parsedRow, err := s.queries.GetParsedDataByStep(ctx, db.GetParsedDataByStepParams{
		StepID: stepUUID,
		JobID:  jobUUID,
	})
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "no parsed data found for step %s: %v", stepID, err)
	}

	var parsedData map[string]any
	if len(parsedRow.ParsedData) > 0 {
		_ = json.Unmarshal(parsedRow.ParsedData, &parsedData)
	}

	toolRow, err := s.queries.GetToolByID(ctx, parsedRow.ToolID)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "tool not found: %v", err)
	}

	knownKeys := make(map[string]bool)
	columns := buildMediumKnownColumns(toolRow.OutputSchema)
	for _, col := range columns {
		knownKeys[col.Key] = true
	}

	dataRows := make([]map[string]any, 0)
	if rawRows, ok := parsedData["data"].([]any); ok {
		for _, item := range rawRows {
			if row, ok := item.(map[string]any); ok {
				dataRows = append(dataRows, row)
			}
		}
	}

	discoveredColumns := discoverMediumColumns(dataRows, knownKeys, len(columns))

	dataStructs := make([]*structpb.Struct, 0, len(dataRows))
	for _, row := range dataRows {
		item, err := structpb.NewStruct(row)
		if err == nil {
			dataStructs = append(dataStructs, item)
		}
	}

	allFindings, err := s.queries.ListFindingsByJob(ctx, jobUUID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to load findings: %v", err)
	}
	stepFindings := make([]*mediumspb.Finding, 0)
	for _, row := range allFindings {
		if row.StepID == stepUUID {
			stepFindings = append(stepFindings, mapDBFindingToProto(row))
		}
	}

	lines := extractMediumParsedLines(parsedData, dataRows)
	lineCount := int32(len(lines))
	if v, ok := parsedData["line_count"].(float64); ok {
		lineCount = int32(v)
	}
	findingsCount := int32(len(stepFindings))
	if v, ok := parsedData["findings_count"].(float64); ok {
		findingsCount = int32(v)
	}
	parseMethod := "line"
	if v, ok := parsedData["parse_method"].(string); ok && stringsTrim(v) != "" {
		parseMethod = v
	}

	createdAt := timestamppb.New(stepRuntime.QueuedAt)
	if stepRuntime.StartedAt != nil {
		createdAt = timestamppb.New(*stepRuntime.StartedAt)
	}

	return &mediumspb.GetParsedDataResponse{
		StepId:            stepID,
		JobId:             jobRuntime.JobID,
		ToolName:          toolRow.ToolName,
		ParseMethod:       parseMethod,
		LineCount:         lineCount,
		FindingsCount:     findingsCount,
		Lines:             lines,
		Findings:          stepFindings,
		CreatedAt:         createdAt,
		Columns:           columns,
		DiscoveredColumns: discoveredColumns,
		Data:              dataStructs,
	}, nil
}

func buildMediumKnownColumns(outputSchema []byte) []*mediumspb.TableColumn {
	var schema mediumOutputSchemaSpec
	if err := json.Unmarshal(outputSchema, &schema); err != nil {
		return nil
	}

	columns := make([]*mediumspb.TableColumn, 0, len(schema.Fields))
	for i, field := range schema.Fields {
		label := field.Label
		if label == "" {
			label = mediumKeyToTitle(field.Key)
		}
		renderHints := make(map[string]string)
		if field.FindingTitle {
			renderHints["role"] = "title"
		}
		if field.FindingSeverity {
			renderHints["role"] = "severity"
		}
		if field.FindingHost {
			renderHints["role"] = "host"
		}
		if field.FindingDescription {
			renderHints["role"] = "description"
		}
		if field.PipelineExtract {
			renderHints["piped_to_next"] = "true"
		}
		columns = append(columns, &mediumspb.TableColumn{
			Key:            field.Key,
			Label:          label,
			Type:           field.Type,
			Description:    field.Description,
			DefaultVisible: true,
			Order:          int32(i),
			Known:          true,
			RenderHints:    renderHints,
		})
	}
	return columns
}

func discoverMediumColumns(dataRows []map[string]any, knownKeys map[string]bool, startOrder int) []*mediumspb.TableColumn {
	discoveredKeys := make(map[string]bool)
	for _, row := range dataRows {
		for key := range row {
			if !knownKeys[key] {
				discoveredKeys[key] = true
			}
		}
	}
	if len(discoveredKeys) == 0 {
		return nil
	}

	columns := make([]*mediumspb.TableColumn, 0, len(discoveredKeys))
	order := startOrder
	for key := range discoveredKeys {
		columns = append(columns, &mediumspb.TableColumn{
			Key:            key,
			Label:          mediumKeyToTitle(key),
			Type:           inferMediumColumnType(dataRows, key),
			DefaultVisible: false,
			Order:          int32(order),
			Known:          false,
		})
		order++
	}
	return columns
}

func inferMediumColumnType(rows []map[string]any, key string) string {
	for _, row := range rows {
		value, ok := row[key]
		if !ok || value == nil {
			continue
		}
		switch value.(type) {
		case float64:
			return "number"
		case bool:
			return "boolean"
		case []any:
			return "array"
		case map[string]any:
			return "object"
		default:
			return "string"
		}
	}
	return "string"
}

func mediumKeyToTitle(key string) string {
	normalized := strings.NewReplacer("-", " ", "_", " ").Replace(stringsTrim(key))
	parts := strings.Fields(normalized)
	for i, part := range parts {
		if len(part) == 0 {
			continue
		}
		parts[i] = strings.ToUpper(part[:1]) + part[1:]
	}
	return strings.Join(parts, " ")
}

func extractMediumParsedLines(parsedData map[string]any, dataRows []map[string]any) []string {
	if rawLines, ok := parsedData["lines"].([]any); ok {
		lines := make([]string, 0, len(rawLines))
		for _, item := range rawLines {
			if line, ok := item.(string); ok && stringsTrim(line) != "" {
				lines = append(lines, line)
			}
		}
		if len(lines) > 0 {
			return lines
		}
	}

	lines := make([]string, 0, len(dataRows))
	for _, row := range dataRows {
		if b, err := json.Marshal(row); err == nil {
			lines = append(lines, string(b))
		}
	}
	return lines
}
