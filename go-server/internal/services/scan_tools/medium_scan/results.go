package mediumscan

import (
	"context"
	"strconv"
	"strings"

	mediumspb "go-server/gen/mediumscan"
	db "go-server/internal/database/sqlc"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (s *mediumScanServer) GetResults(ctx context.Context, req *mediumspb.GetResultsRequest) (*mediumspb.GetResultsResponse, error) {
	jobID := req.GetJobId()
	stepID := req.GetStepId()

	if stepID != "" {
		if _, _, err := s.requireOwnedMediumStep(ctx, stepID); err != nil {
			return nil, err
		}
	} else if jobID != "" {
		if _, err := s.requireOwnedMediumJob(ctx, jobID); err != nil {
			return nil, err
		}
	} else {
		return nil, status.Error(codes.InvalidArgument, "job_id or step_id is required")
	}

	scopeID := jobID
	if stepID != "" {
		scopeID = stepID
		stepUUID, err := uuid.Parse(stepID)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid step_id: %v", err)
		}
		stepRow, err := s.queries.GetScanStepByID(ctx, stepUUID)
		if err != nil {
			return nil, status.Errorf(codes.NotFound, "step not found: %v", err)
		}
		jobID = stepRow.JobID.String()
	}

	jobUUID, err := uuid.Parse(jobID)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid job_id: %v", err)
	}

	findingsRows, err := s.queries.ListFindingsByJob(ctx, jobUUID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to load findings: %v", err)
	}
	findingsRows = filterFindings(findingsRows, req.GetFilter(), stepID)
	totalCount := int32(len(findingsRows))
	pg := applyPagination(findingsRows, req.GetPagination())
	findings := make([]*mediumspb.Finding, 0, len(pg.Items))
	for _, row := range pg.Items {
		findings = append(findings, mapDBFindingToProto(row))
	}

	resp := &mediumspb.GetResultsResponse{
		ScopeId:    scopeID,
		Findings:   findings,
		TotalCount: totalCount,
		Pagination: &mediumspb.Pagination{
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
				resp.RawOutput = &mediumspb.GetResultsResponse_RawOutputInline{RawOutputInline: last.RawData}
			}
		}
	} else {
		resultsRows, err := s.queries.ListScanResultsByJob(ctx, jobUUID)
		if err == nil && len(resultsRows) > 0 {
			last := resultsRows[len(resultsRows)-1]
			if len(last.RawData) > 0 {
				resp.RawOutput = &mediumspb.GetResultsResponse_RawOutputInline{RawOutputInline: last.RawData}
			}
		}
	}

	return resp, nil
}

func filterFindings(rows []db.Finding, filter *mediumspb.ResultsFilter, stepID string) []db.Finding {
	if filter == nil && stepID == "" {
		return rows
	}
	out := make([]db.Finding, 0, len(rows))
	hostContains := ""
	portEq := int32(0)
	severitySet := map[db.SeverityLevel]struct{}{}
	if filter != nil {
		hostContains = strings.ToLower(stringsTrim(filter.GetHostContains()))
		portEq = filter.GetPortEq()
		for _, sev := range filter.GetSeverityIn() {
			switch sev {
			case mediumspb.Severity_SEVERITY_INFO:
				severitySet[db.SeverityLevelInfo] = struct{}{}
			case mediumspb.Severity_SEVERITY_LOW:
				severitySet[db.SeverityLevelLow] = struct{}{}
			case mediumspb.Severity_SEVERITY_MEDIUM:
				severitySet[db.SeverityLevelMedium] = struct{}{}
			case mediumspb.Severity_SEVERITY_HIGH:
				severitySet[db.SeverityLevelHigh] = struct{}{}
			case mediumspb.Severity_SEVERITY_CRITICAL:
				severitySet[db.SeverityLevelCritical] = struct{}{}
			}
		}
	}

	for _, row := range rows {
		if stepID != "" && row.StepID.String() != stepID {
			continue
		}
		if len(severitySet) > 0 {
			if !row.Severity.Valid {
				continue
			}
			if _, ok := severitySet[row.Severity.SeverityLevel]; !ok {
				continue
			}
		}
		if hostContains != "" {
			host := ""
			if row.Host.Valid {
				host = strings.ToLower(row.Host.String)
			}
			if !strings.Contains(host, hostContains) {
				continue
			}
		}
		if portEq > 0 {
			if !row.Port.Valid || row.Port.Int32 != portEq {
				continue
			}
		}
		out = append(out, row)
	}
	return out
}

type paginatedFindingRows struct {
	Items      []db.Finding
	Limit      int
	Offset     int
	HasMore    bool
	NextCursor string
}

func applyPagination(items []db.Finding, p *mediumspb.Pagination) paginatedFindingRows {
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
		return paginatedFindingRows{Items: []db.Finding{}, Limit: limit, Offset: offset}
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

func mapDBFindingToProto(row db.Finding) *mediumspb.Finding {
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
	return &mediumspb.Finding{
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

func dbSeverityToProto(severity db.NullSeverityLevel) mediumspb.Severity {
	if !severity.Valid {
		return mediumspb.Severity_SEVERITY_UNSPECIFIED
	}
	switch severity.SeverityLevel {
	case db.SeverityLevelInfo:
		return mediumspb.Severity_SEVERITY_INFO
	case db.SeverityLevelLow:
		return mediumspb.Severity_SEVERITY_LOW
	case db.SeverityLevelMedium:
		return mediumspb.Severity_SEVERITY_MEDIUM
	case db.SeverityLevelHigh:
		return mediumspb.Severity_SEVERITY_HIGH
	case db.SeverityLevelCritical:
		return mediumspb.Severity_SEVERITY_CRITICAL
	default:
		return mediumspb.Severity_SEVERITY_UNSPECIFIED
	}
}
