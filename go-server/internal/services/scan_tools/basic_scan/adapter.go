package basicscan

import (
	"context"
	"fmt"
	"strings"

	advancedpb "go-server/gen/advanced"
	basicpb "go-server/gen/basic"

	emptypb "google.golang.org/protobuf/types/known/emptypb"
)

type server struct {
	basicpb.UnimplementedBasicScanServiceServer
	advanced advancedpb.AdvancedScanServiceServer
}

func New(advanced advancedpb.AdvancedScanServiceServer) basicpb.BasicScanServiceServer {
	return &server{advanced: advanced}
}

func (s *server) SubmitScan(ctx context.Context, req *basicpb.SubmitScanRequest) (*basicpb.SubmitScanResponse, error) {
	advReq, err := toAdvancedSubmitRequest(req)
	if err != nil {
		return nil, err
	}
	resp, err := s.advanced.SubmitScan(ctx, advReq)
	if err != nil {
		return nil, err
	}
	return &basicpb.SubmitScanResponse{
		JobId:              resp.GetJobId(),
		StepId:             resp.GetStepId(),
		Status:             mapStepStatus(resp.GetStatus()),
		IsIdempotentReplay: resp.GetIsIdempotentReplay(),
		OriginalRequestId:  resp.GetOriginalRequestId(),
		QueuedAt:           resp.GetQueuedAt(),
	}, nil
}

func (s *server) GetStepStatus(ctx context.Context, req *basicpb.GetStepStatusRequest) (*basicpb.GetStepStatusResponse, error) {
	resp, err := s.advanced.GetStepStatus(ctx, &advancedpb.GetStepStatusRequest{StepId: req.GetStepId()})
	if err != nil {
		return nil, err
	}
	return &basicpb.GetStepStatusResponse{
		StepId:            resp.GetStepId(),
		JobId:             resp.GetJobId(),
		ToolName:          resp.GetToolName(),
		Status:            mapStepStatus(resp.GetStatus()),
		ExitCode:          resp.GetExitCode(),
		ErrorMessage:      resp.GetErrorMessage(),
		QueuedAt:          resp.GetQueuedAt(),
		StartedAt:         resp.GetStartedAt(),
		FinishedAt:        resp.GetFinishedAt(),
		DurationMs:        resp.GetDurationMs(),
		FindingsCount:     resp.GetFindingsCount(),
		RawOutputLocation: resp.GetRawOutputLocation(),
		HasParsedResults:  resp.GetHasParsedResults(),
	}, nil
}

func (s *server) GetJobStatus(ctx context.Context, req *basicpb.GetJobStatusRequest) (*basicpb.GetJobStatusResponse, error) {
	resp, err := s.advanced.GetJobStatus(ctx, &advancedpb.GetJobStatusRequest{JobId: req.GetJobId()})
	if err != nil {
		return nil, err
	}
	steps := make([]*basicpb.StepSummary, 0, len(resp.GetSteps()))
	for _, item := range resp.GetSteps() {
		steps = append(steps, &basicpb.StepSummary{
			StepId:        item.GetStepId(),
			ToolName:      item.GetToolName(),
			StepOrder:     item.GetStepOrder(),
			Status:        mapStepStatus(item.GetStatus()),
			FindingsCount: item.GetFindingsCount(),
			StartedAt:     item.GetStartedAt(),
			FinishedAt:    item.GetFinishedAt(),
		})
	}
	return &basicpb.GetJobStatusResponse{
		JobId:          resp.GetJobId(),
		ProjectId:      resp.GetProjectId(),
		Status:         mapJobStatus(resp.GetStatus()),
		TotalSteps:     resp.GetTotalSteps(),
		CompletedSteps: resp.GetCompletedSteps(),
		FailedSteps:    resp.GetFailedSteps(),
		PendingSteps:   resp.GetPendingSteps(),
		TotalFindings:  resp.GetTotalFindings(),
		CreatedAt:      resp.GetCreatedAt(),
		StartedAt:      resp.GetStartedAt(),
		FinishedAt:     resp.GetFinishedAt(),
		Steps:          steps,
	}, nil
}

func (s *server) GetResults(ctx context.Context, req *basicpb.GetResultsRequest) (*basicpb.GetResultsResponse, error) {
	pagination := req.GetPagination()
	if pagination == nil {
		pagination = &basicpb.Pagination{}
	}
	advReq := &advancedpb.GetResultsRequest{
		Pagination: &advancedpb.Pagination{
			Limit:      pagination.GetLimit(),
			Offset:     pagination.GetOffset(),
			NextCursor: pagination.GetNextCursor(),
			HasMore:    pagination.GetHasMore(),
		},
	}
	if req.GetStepId() != "" {
		advReq.Scope = &advancedpb.GetResultsRequest_StepId{StepId: req.GetStepId()}
	} else {
		advReq.Scope = &advancedpb.GetResultsRequest_JobId{JobId: req.GetJobId()}
	}
	resp, err := s.advanced.GetResults(ctx, advReq)
	if err != nil {
		return nil, err
	}

	findings := make([]*basicpb.Finding, 0, len(resp.GetFindings()))
	for _, item := range resp.GetFindings() {
		findings = append(findings, &basicpb.Finding{
			FindingId:   item.GetFindingId(),
			StepId:      item.GetStepId(),
			JobId:       item.GetJobId(),
			Title:       item.GetTitle(),
			Severity:    mapSeverity(item.GetSeverity()),
			Fingerprint: item.GetFingerprint(),
			Host:        item.GetHost(),
			Port:        item.GetPort(),
			Protocol:    item.GetProtocol(),
			Url:         item.GetUrl(),
			Description: item.GetDescription(),
			Remediation: item.GetRemediation(),
			References:  item.GetReferences(),
			Metadata:    item.GetMetadata(),
			Tags:        item.GetTags(),
			CreatedAt:   item.GetCreatedAt(),
		})
	}

	out := &basicpb.GetResultsResponse{
		ScopeId:    resp.GetScopeId(),
		Findings:   findings,
		TotalCount: resp.GetTotalCount(),
		Pagination: &basicpb.Pagination{
			Limit:      resp.GetPagination().GetLimit(),
			Offset:     resp.GetPagination().GetOffset(),
			NextCursor: resp.GetPagination().GetNextCursor(),
			HasMore:    resp.GetPagination().GetHasMore(),
		},
	}
	switch raw := resp.GetRawOutput().(type) {
	case *advancedpb.GetResultsResponse_RawOutputInline:
		out.RawOutput = &basicpb.GetResultsResponse_RawOutputInline{RawOutputInline: raw.RawOutputInline}
	case *advancedpb.GetResultsResponse_RawOutputS3Url:
		out.RawOutput = &basicpb.GetResultsResponse_RawOutputS3Url{RawOutputS3Url: raw.RawOutputS3Url}
	}
	return out, nil
}

func (s *server) HealthCheck(ctx context.Context, _ *emptypb.Empty) (*basicpb.HealthCheckResponse, error) {
	resp, err := s.advanced.HealthCheck(ctx, &emptypb.Empty{})
	if err != nil {
		return nil, err
	}
	return &basicpb.HealthCheckResponse{
		Status:        mapHealthStatus(resp.GetStatus()),
		UptimeSeconds: resp.GetUptimeSeconds(),
		ActiveScans:   resp.GetActiveScans(),
		QueuedScans:   resp.GetQueuedScans(),
	}, nil
}

func toAdvancedSubmitRequest(req *basicpb.SubmitScanRequest) (*advancedpb.SubmitScanRequest, error) {
	if req == nil {
		return nil, fmt.Errorf("request is required")
	}
	normalizedFlags, err := normalizeRawFlags(req.GetCustomFlags())
	if err != nil {
		return nil, err
	}
	normalizedToolArgs := trimMap(req.GetToolArgs())
	if len(normalizedToolArgs) > 0 {
		return nil, fmt.Errorf("tool_args are not supported in basic mode command adapter; use keyword presets or advanced scan command")
	}

	toolName := strings.ToLower(strings.TrimSpace(req.GetToolName()))
	commandParts := make([]string, 0, 1+len(normalizedFlags))
	commandParts = append(commandParts, shellEscapeToken(toolName))
	for _, raw := range normalizedFlags {
		commandParts = append(commandParts, shellEscapeToken(raw))
	}
	command := strings.Join(commandParts, " ")

	return &advancedpb.SubmitScanRequest{
		ProjectId:      strings.TrimSpace(req.GetProjectId()),
		TargetId:       strings.TrimSpace(req.GetTargetId()),
		TargetValue:    strings.TrimSpace(req.GetTarget()),
		IdempotencyKey: strings.TrimSpace(req.GetIdempotencyKey()),
		// The advanced service re-resolves the tool from the command name, so the
		// tool's stored shadow_output_config still governs structured capture here.
		Command:       command,
		ExecutionMode: advancedpb.ExecutionMode_EXECUTION_MODE_WEB,
	}, nil
}

func shellEscapeToken(v string) string {
	if v == "" {
		return "''"
	}
	if !strings.ContainsAny(v, " \t\r\n'\"\\|") {
		return v
	}
	return "'" + strings.ReplaceAll(v, "'", "'\"'\"'") + "'"
}

func trimMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return out
}

func mapStepStatus(v advancedpb.StepStatus) basicpb.StepStatus {
	switch v {
	case advancedpb.StepStatus_STEP_STATUS_PENDING:
		return basicpb.StepStatus_STEP_STATUS_PENDING
	case advancedpb.StepStatus_STEP_STATUS_QUEUED:
		return basicpb.StepStatus_STEP_STATUS_QUEUED
	case advancedpb.StepStatus_STEP_STATUS_RUNNING:
		return basicpb.StepStatus_STEP_STATUS_RUNNING
	case advancedpb.StepStatus_STEP_STATUS_COMPLETED:
		return basicpb.StepStatus_STEP_STATUS_COMPLETED
	case advancedpb.StepStatus_STEP_STATUS_FAILED:
		return basicpb.StepStatus_STEP_STATUS_FAILED
	case advancedpb.StepStatus_STEP_STATUS_CANCELLED:
		return basicpb.StepStatus_STEP_STATUS_CANCELLED
	case advancedpb.StepStatus_STEP_STATUS_SKIPPED:
		return basicpb.StepStatus_STEP_STATUS_SKIPPED
	default:
		return basicpb.StepStatus_STEP_STATUS_UNSPECIFIED
	}
}

func mapJobStatus(v advancedpb.JobStatus) basicpb.JobStatus {
	switch v {
	case advancedpb.JobStatus_JOB_STATUS_PENDING:
		return basicpb.JobStatus_JOB_STATUS_PENDING
	case advancedpb.JobStatus_JOB_STATUS_RUNNING:
		return basicpb.JobStatus_JOB_STATUS_RUNNING
	case advancedpb.JobStatus_JOB_STATUS_COMPLETED:
		return basicpb.JobStatus_JOB_STATUS_COMPLETED
	case advancedpb.JobStatus_JOB_STATUS_FAILED:
		return basicpb.JobStatus_JOB_STATUS_FAILED
	case advancedpb.JobStatus_JOB_STATUS_CANCELLED:
		return basicpb.JobStatus_JOB_STATUS_CANCELLED
	case advancedpb.JobStatus_JOB_STATUS_PARTIAL:
		return basicpb.JobStatus_JOB_STATUS_PARTIAL
	default:
		return basicpb.JobStatus_JOB_STATUS_UNSPECIFIED
	}
}

func mapSeverity(v advancedpb.Severity) basicpb.Severity {
	switch v {
	case advancedpb.Severity_SEVERITY_INFO:
		return basicpb.Severity_SEVERITY_INFO
	case advancedpb.Severity_SEVERITY_LOW:
		return basicpb.Severity_SEVERITY_LOW
	case advancedpb.Severity_SEVERITY_MEDIUM:
		return basicpb.Severity_SEVERITY_MEDIUM
	case advancedpb.Severity_SEVERITY_HIGH:
		return basicpb.Severity_SEVERITY_HIGH
	case advancedpb.Severity_SEVERITY_CRITICAL:
		return basicpb.Severity_SEVERITY_CRITICAL
	default:
		return basicpb.Severity_SEVERITY_UNSPECIFIED
	}
}

func mapHealthStatus(v advancedpb.HealthStatus) basicpb.HealthStatus {
	switch v {
	case advancedpb.HealthStatus_HEALTH_STATUS_HEALTHY:
		return basicpb.HealthStatus_HEALTH_STATUS_HEALTHY
	case advancedpb.HealthStatus_HEALTH_STATUS_DEGRADED:
		return basicpb.HealthStatus_HEALTH_STATUS_DEGRADED
	case advancedpb.HealthStatus_HEALTH_STATUS_UNHEALTHY:
		return basicpb.HealthStatus_HEALTH_STATUS_UNHEALTHY
	default:
		return basicpb.HealthStatus_HEALTH_STATUS_UNSPECIFIED
	}
}
