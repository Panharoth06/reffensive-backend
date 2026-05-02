package advancedscan

import (
	"context"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"time"

	advancedpb "go-server/gen/advanced"
	db "go-server/internal/database/sqlc"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type paginatedFindingRows struct {
	Items      []db.Finding
	Limit      int
	Offset     int
	HasMore    bool
	NextCursor string
}

func applyPagination(items []db.Finding, p *advancedpb.Pagination) paginatedFindingRows {
	limit := 100
	offset := 0
	if p != nil {
		if p.GetLimit() > 0 {
			limit = int(p.GetLimit())
		}
		if p.GetOffset() > 0 {
			offset = int(p.GetOffset())
		}
	}
	if offset >= len(items) {
		return paginatedFindingRows{
			Items:      []db.Finding{},
			Limit:      limit,
			Offset:     offset,
			HasMore:    false,
			NextCursor: "",
		}
	}
	end := offset + limit
	if end > len(items) {
		end = len(items)
	}
	hasMore := end < len(items)
	nextCursor := ""
	if hasMore {
		nextCursor = strconv.Itoa(end)
	}
	return paginatedFindingRows{
		Items:      items[offset:end],
		Limit:      limit,
		Offset:     offset,
		HasMore:    hasMore,
		NextCursor: nextCursor,
	}
}

func (s *advancedScanServer) loadFindingsForResults(ctx context.Context, jobUUID uuid.UUID, filter *advancedpb.ResultsFilter) ([]db.Finding, error) {
	if filter == nil || len(filter.GetSeverityIn()) == 0 {
		rows, err := s.queries.ListFindingsByJob(ctx, jobUUID)
		if err != nil {
			return nil, err
		}
		return filterFindings(rows, filter), nil
	}

	byID := make(map[uuid.UUID]db.Finding)
	for _, sev := range filter.GetSeverityIn() {
		dbSeverity := protoSeverityToDB(sev)
		if !dbSeverity.Valid {
			continue
		}
		rows, err := s.queries.ListFindingsBySeverity(ctx, db.ListFindingsBySeverityParams{
			JobID:    jobUUID,
			Severity: dbSeverity,
		})
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			byID[row.FindingID] = row
		}
	}
	merged := make([]db.Finding, 0, len(byID))
	for _, row := range byID {
		merged = append(merged, row)
	}
	sort.Slice(merged, func(i, j int) bool {
		ti := time.Time{}
		tj := time.Time{}
		if merged[i].CreatedAt.Valid {
			ti = merged[i].CreatedAt.Time
		}
		if merged[j].CreatedAt.Valid {
			tj = merged[j].CreatedAt.Time
		}
		return ti.After(tj)
	})
	return filterFindings(merged, filter), nil
}

func filterFindings(rows []db.Finding, filter *advancedpb.ResultsFilter) []db.Finding {
	if filter == nil {
		return rows
	}
	out := make([]db.Finding, 0, len(rows))
	hostContains := strings.ToLower(stringsTrim(filter.GetHostContains()))
	fingerprintEq := stringsTrim(filter.GetFingerprintEq())
	createdAfter := filter.GetCreatedAfter()
	for _, row := range rows {
		if hostContains != "" {
			host := ""
			if row.Host.Valid {
				host = strings.ToLower(row.Host.String)
			}
			if !strings.Contains(host, hostContains) {
				continue
			}
		}
		if filter.GetPortEq() > 0 {
			if !row.Port.Valid || row.Port.Int32 != filter.GetPortEq() {
				continue
			}
		}
		if fingerprintEq != "" {
			if !row.Fingerprint.Valid || row.Fingerprint.String != fingerprintEq {
				continue
			}
		}
		if createdAfter != nil && createdAfter.IsValid() {
			if !row.CreatedAt.Valid || row.CreatedAt.Time.Before(createdAfter.AsTime()) {
				continue
			}
		}
		out = append(out, row)
	}
	return out
}

func mapDBFindingToProto(row db.Finding) *advancedpb.Finding {
	title := ""
	if row.Title.Valid {
		title = row.Title.String
	}
	host := ""
	if row.Host.Valid {
		host = row.Host.String
	}
	fingerprint := ""
	if row.Fingerprint.Valid {
		fingerprint = row.Fingerprint.String
	}
	port := int32(0)
	if row.Port.Valid {
		port = row.Port.Int32
	}
	created := timestamppb.Now()
	if row.CreatedAt.Valid {
		created = timestamppb.New(row.CreatedAt.Time)
	}
	return &advancedpb.Finding{
		FindingId:   row.FindingID.String(),
		StepId:      row.StepID.String(),
		JobId:       row.JobID.String(),
		Title:       title,
		Severity:    dbSeverityToProto(row.Severity),
		Fingerprint: fingerprint,
		Host:        host,
		Port:        port,
		Metadata:    map[string]string{},
		Tags:        map[string]string{},
		CreatedAt:   created,
	}
}

func (s *advancedScanServer) GetResults(ctx context.Context, req *advancedpb.GetResultsRequest) (*advancedpb.GetResultsResponse, error) {
	scopeID := req.GetJobId()
	jobID := req.GetJobId()
	stepID := req.GetStepId()
	if stepID != "" {
		scopeID = stepID
		stepUUID, err := uuid.Parse(stepID)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid step_id: %v", err)
		}
		stepRow, _, err := s.requireOwnedStep(ctx, stepUUID)
		if err != nil {
			return nil, err
		}
		jobID = stepRow.JobID.String()
	}

	if jobID == "" {
		return nil, status.Error(codes.InvalidArgument, "job_id or step_id is required")
	}
	jobUUID, err := uuid.Parse(jobID)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid job_id: %v", err)
	}
	if _, err := s.requireOwnedJob(ctx, jobUUID); err != nil {
		return nil, err
	}

	findingsRows, err := s.loadFindingsForResults(ctx, jobUUID, req.GetFilter())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to load findings: %v", err)
	}
	if stepID != "" {
		filtered := make([]db.Finding, 0, len(findingsRows))
		for _, row := range findingsRows {
			if row.StepID.String() == stepID {
				filtered = append(filtered, row)
			}
		}
		findingsRows = filtered
	}

	totalCount := int32(len(findingsRows))
	pg := applyPagination(findingsRows, req.GetPagination())
	findings := make([]*advancedpb.Finding, 0, len(pg.Items))
	for _, row := range pg.Items {
		findings = append(findings, mapDBFindingToProto(row))
	}

	resp := &advancedpb.GetResultsResponse{
		ScopeId:    scopeID,
		Findings:   findings,
		TotalCount: totalCount,
		Pagination: &advancedpb.Pagination{
			Limit:      int32(pg.Limit),
			Offset:     int32(pg.Offset),
			HasMore:    pg.HasMore,
			NextCursor: pg.NextCursor,
		},
	}

	if stepID != "" {
		stepUUID, _ := uuid.Parse(stepID)
		resultsRows, err := s.queries.ListScanResultsByStep(ctx, db.ListScanResultsByStepParams{
			StepID: stepUUID,
			JobID:  jobUUID,
		})
		if err == nil && len(resultsRows) > 0 {
			last := resultsRows[len(resultsRows)-1]
			if len(last.RawData) > 0 {
				resp.RawOutput = &advancedpb.GetResultsResponse_RawOutputInline{
					RawOutputInline: last.RawData,
				}
			}
			createdAt := timestamppb.Now()
			if last.CreatedAt.Valid {
				createdAt = timestamppb.New(last.CreatedAt.Time)
			}
			resp.ParsingMetadata = &advancedpb.ParsingMetadata{
				ParserName:      "line_parser_v1",
				ParserVersion:   "1.0.0",
				ParsedAt:        createdAt,
				RawSizeBytes:    int32(len(last.RawData)),
				ParsedSizeBytes: int32(len(last.ParsedData)),
				ParsingError:    "",
				IsPartial:       false,
			}
		}
	}

	return resp, nil
}

// GetParsedData returns structured parsed results for a single step,
// including column definitions (known + discovered) and data rows for table rendering.
func (s *advancedScanServer) GetParsedData(ctx context.Context, req *advancedpb.GetParsedDataRequest) (*advancedpb.GetParsedDataResponse, error) {
	stepID := req.GetStepId()
	if stepID == "" {
		return nil, status.Error(codes.InvalidArgument, "step_id is required")
	}
	stepUUID, err := uuid.Parse(stepID)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid step_id: %v", err)
	}
	stepRow, jobRow, err := s.requireOwnedStep(ctx, stepUUID)
	if err != nil {
		return nil, err
	}

	parsedRow, err := s.queries.GetParsedDataByStep(ctx, db.GetParsedDataByStepParams{
		StepID: stepUUID,
		JobID:  jobRow.JobID,
	})
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "no parsed data found for step %s: %v", stepID, err)
	}

	// Parse parsed_data JSONB.
	var parsedData map[string]any
	if len(parsedRow.ParsedData) > 0 {
		_ = json.Unmarshal(parsedRow.ParsedData, &parsedData)
	}

	// Load tool row for output_schema.
	toolRow, err := s.queries.GetToolByID(ctx, parsedRow.ToolID)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "tool not found: %v", err)
	}

	// Build known columns from output_schema.fields.
	knownKeys := make(map[string]bool)
	columns := buildKnownColumns(toolRow.OutputSchema)
	for _, c := range columns {
		knownKeys[c.Key] = true
	}

	// Extract structured data rows.
	var dataRows []map[string]any
	if raw, ok := parsedData["data"].([]any); ok {
		for _, item := range raw {
			if obj, ok := item.(map[string]any); ok {
				dataRows = append(dataRows, obj)
			}
		}
	}

	// Discover unknown columns from actual data.
	discoveredColumns := discoverColumns(dataRows, knownKeys, len(columns))

	// Convert data rows to protobuf Struct.
	var dataStructs []*structpb.Struct
	for _, row := range dataRows {
		s, err := structpb.NewStruct(row)
		if err == nil {
			dataStructs = append(dataStructs, s)
		}
	}

	// Load findings.
	allFindings, err := s.loadFindingsForResults(ctx, jobRow.JobID, nil)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to load findings: %v", err)
	}
	stepFindings := make([]*advancedpb.Finding, 0)
	for _, row := range allFindings {
		if row.StepID == stepUUID {
			stepFindings = append(stepFindings, mapDBFindingToProto(row))
		}
	}

	// Backward compat: raw lines from data.
	rawLines := make([]string, 0, len(dataRows))
	for _, row := range dataRows {
		if b, err := json.Marshal(row); err == nil {
			rawLines = append(rawLines, string(b))
		}
	}

	lineCount := int32(len(dataRows))
	if v, ok := parsedData["line_count"].(float64); ok {
		lineCount = int32(v)
	}
	findingsCount := int32(len(stepFindings))
	if v, ok := parsedData["findings_count"].(float64); ok {
		findingsCount = int32(v)
	}
	parseMethod := "line"
	if v, ok := parsedData["parse_method"].(string); ok {
		parseMethod = v
	}

	createdAt := timestamppb.Now()
	if stepRow.StartedAt.Valid {
		createdAt = timestamppb.New(stepRow.StartedAt.Time)
	}

	return &advancedpb.GetParsedDataResponse{
		StepId:            stepID,
		JobId:             jobRow.JobID.String(),
		ToolName:          toolRow.ToolName,
		ParseMethod:       parseMethod,
		LineCount:         lineCount,
		FindingsCount:     findingsCount,
		Lines:             rawLines,
		Findings:          stepFindings,
		CreatedAt:         createdAt,
		Columns:           columns,
		DiscoveredColumns: discoveredColumns,
		Data:              dataStructs,
	}, nil
}

// buildKnownColumns reads outputSchema.fields and returns TableColumn definitions.
func buildKnownColumns(outputSchema []byte) []*advancedpb.TableColumn {
	var schema outputSchemaSpec
	if err := json.Unmarshal(outputSchema, &schema); err != nil {
		return nil
	}

	columns := make([]*advancedpb.TableColumn, 0, len(schema.Fields))
	for i, field := range schema.Fields {
		label := field.Label
		if label == "" {
			label = kebabToTitle(field.Key)
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
		columns = append(columns, &advancedpb.TableColumn{
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

// discoverColumns scans data rows for keys not in knownKeys and returns column definitions.
func discoverColumns(dataRows []map[string]any, knownKeys map[string]bool, startOrder int) []*advancedpb.TableColumn {
	allKeys := make(map[string]bool)
	for _, row := range dataRows {
		for key := range row {
			if !knownKeys[key] {
				allKeys[key] = true
			}
		}
	}
	if len(allKeys) == 0 {
		return nil
	}

	out := make([]*advancedpb.TableColumn, 0, len(allKeys))
	order := startOrder
	for key := range allKeys {
		inferredType := inferColumnType(dataRows, key)
		out = append(out, &advancedpb.TableColumn{
			Key:            key,
			Label:          kebabToTitle(key),
			Type:           inferredType,
			DefaultVisible: false,
			Order:          int32(order),
			Known:          false,
		})
		order++
	}
	return out
}

// inferColumnType samples the first non-null value to guess the type.
func inferColumnType(rows []map[string]any, key string) string {
	for _, row := range rows {
		if v, ok := row[key]; ok && v != nil {
			switch v.(type) {
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
	}
	return "string"
}

// kebabToTitle converts kebab-case to Title Case.
func kebabToTitle(s string) string {
	parts := strings.Split(s, "-")
	for i, p := range parts {
		if len(p) > 0 {
			parts[i] = strings.ToUpper(p[:1]) + p[1:]
		}
	}
	return strings.Join(parts, " ")
}
