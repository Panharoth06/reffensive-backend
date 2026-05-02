package advancedscan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	advancedpb "go-server/gen/advanced"
	db "go-server/internal/database/sqlc"
	"go-server/internal/interceptor"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (s *advancedScanServer) recomputeJobStatusLocked(jobID string) {
	job, ok := s.jobs[jobID]
	if !ok {
		return
	}

	var completed, failed, pending int32
	var earliestStart *time.Time
	var latestFinish *time.Time
	for _, stepID := range job.StepIDs {
		step, ok := s.steps[stepID]
		if !ok {
			continue
		}
		switch step.Status {
		case advancedpb.StepStatus_STEP_STATUS_COMPLETED:
			completed++
		case advancedpb.StepStatus_STEP_STATUS_FAILED:
			failed++
		case advancedpb.StepStatus_STEP_STATUS_PENDING,
			advancedpb.StepStatus_STEP_STATUS_QUEUED,
			advancedpb.StepStatus_STEP_STATUS_RUNNING:
			pending++
		}

		if step.StartedAt != nil {
			if earliestStart == nil || step.StartedAt.Before(*earliestStart) {
				tmp := *step.StartedAt
				earliestStart = &tmp
			}
		}
		if step.FinishedAt != nil {
			if latestFinish == nil || step.FinishedAt.After(*latestFinish) {
				tmp := *step.FinishedAt
				latestFinish = &tmp
			}
		}
	}

	job.Status = deriveJobStatus(completed, failed, pending)
	job.StartedAt = earliestStart
	job.FinishedAt = latestFinish
}

func deriveJobStatus(completed, failed, pending int32) advancedpb.JobStatus {
	switch {
	case failed > 0 && completed > 0:
		return advancedpb.JobStatus_JOB_STATUS_PARTIAL
	case failed > 0 && pending == 0:
		return advancedpb.JobStatus_JOB_STATUS_FAILED
	case completed > 0 && pending == 0 && failed == 0:
		return advancedpb.JobStatus_JOB_STATUS_COMPLETED
	case pending > 0:
		return advancedpb.JobStatus_JOB_STATUS_RUNNING
	default:
		return advancedpb.JobStatus_JOB_STATUS_PENDING
	}
}

func isTerminalStepStatus(status advancedpb.StepStatus) bool {
	switch status {
	case advancedpb.StepStatus_STEP_STATUS_COMPLETED,
		advancedpb.StepStatus_STEP_STATUS_FAILED,
		advancedpb.StepStatus_STEP_STATUS_CANCELLED,
		advancedpb.StepStatus_STEP_STATUS_SKIPPED:
		return true
	default:
		return false
	}
}

func toProtoTS(t *time.Time) *timestamppb.Timestamp {
	if t == nil {
		return nil
	}
	return timestamppb.New(*t)
}

func stringsTrim(v string) string {
	return strings.TrimSpace(v)
}

func canonicalToolName(v string) string {
	return strings.ToLower(stringsTrim(v))
}

func cloneSubmitResponse(src *advancedpb.SubmitScanResponse) *advancedpb.SubmitScanResponse {
	if src == nil {
		return nil
	}
	return &advancedpb.SubmitScanResponse{
		JobId:              src.JobId,
		StepId:             src.StepId,
		Status:             src.Status,
		IsIdempotentReplay: src.IsIdempotentReplay,
		OriginalRequestId:  src.OriginalRequestId,
		QueuedAt:           src.QueuedAt,
	}
}

func idempotencyHashForRequest(req *advancedpb.SubmitScanRequest) (string, error) {
	clone := proto.Clone(req).(*advancedpb.SubmitScanRequest)
	clone.IdempotencyKey = ""
	clone.JobId = ""
	clone.StepId = ""

	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(clone)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func (s *advancedScanServer) resolveTool(ctx context.Context, req *advancedpb.SubmitScanRequest) (db.Tool, error) {
	toolName := stringsTrim(req.GetToolName())
	toolIDText := stringsTrim(req.GetToolId())

	switch {
	case toolName != "":
		toolRow, err := s.resolveToolByName(ctx, toolName)
		if err != nil {
			return db.Tool{}, err
		}
		if toolIDText == "" {
			return toolRow, nil
		}
		toolID, err := uuid.Parse(toolIDText)
		if err != nil {
			return db.Tool{}, status.Errorf(codes.InvalidArgument, "invalid tool_id: %v", err)
		}
		if toolRow.ToolID != toolID {
			return db.Tool{}, status.Error(codes.InvalidArgument, "tool_name and tool_id refer to different tools")
		}
		return toolRow, nil
	case toolIDText != "":
		toolID, err := uuid.Parse(toolIDText)
		if err != nil {
			return db.Tool{}, status.Errorf(codes.InvalidArgument, "invalid tool_id: %v", err)
		}
		toolRow, err := s.queries.GetToolByID(ctx, toolID)
		if err != nil {
			return db.Tool{}, status.Errorf(codes.NotFound, "tool_id %q not found: %v", toolIDText, err)
		}
		return toolRow, nil
	default:
		return db.Tool{}, status.Error(codes.InvalidArgument, "tool_name is required")
	}
}

func (s *advancedScanServer) resolveToolByName(ctx context.Context, toolName string) (db.Tool, error) {
	trimmedName := stringsTrim(toolName)
	if trimmedName == "" {
		return db.Tool{}, status.Error(codes.InvalidArgument, "tool_name is required")
	}

	toolRow, err := s.queries.GetToolByName(ctx, trimmedName)
	if err == nil {
		return toolRow, nil
	}

	normalizedName := canonicalToolName(trimmedName)
	tools, listErr := s.queries.ListTools(ctx)
	if listErr != nil {
		return db.Tool{}, status.Errorf(codes.NotFound, "tool_name %q not found: %v", trimmedName, err)
	}

	var match *db.Tool
	for i := range tools {
		if canonicalToolName(tools[i].ToolName) != normalizedName {
			continue
		}
		if match != nil && match.ToolID != tools[i].ToolID {
			return db.Tool{}, status.Errorf(codes.FailedPrecondition, "tool_name %q matches multiple tools case-insensitively", trimmedName)
		}
		match = &tools[i]
	}
	if match != nil {
		return *match, nil
	}

	return db.Tool{}, status.Errorf(codes.NotFound, "tool_name %q not found: %v", trimmedName, err)
}

func (s *advancedScanServer) logChannel(stepID string) string {
	return fmt.Sprintf("%s:%s", s.redisChannelPrefix, stepID)
}

func dbStepStatusToProto(status db.NullScanStepStatus) advancedpb.StepStatus {
	if !status.Valid {
		return advancedpb.StepStatus_STEP_STATUS_UNSPECIFIED
	}
	switch status.ScanStepStatus {
	case db.ScanStepStatusCompleted:
		return advancedpb.StepStatus_STEP_STATUS_COMPLETED
	case db.ScanStepStatusSkipped:
		return advancedpb.StepStatus_STEP_STATUS_SKIPPED
	case db.ScanStepStatusRunning:
		return advancedpb.StepStatus_STEP_STATUS_RUNNING
	case db.ScanStepStatusPending:
		return advancedpb.StepStatus_STEP_STATUS_PENDING
	case db.ScanStepStatusFailed:
		return advancedpb.StepStatus_STEP_STATUS_FAILED
	default:
		return advancedpb.StepStatus_STEP_STATUS_FAILED
	}
}

func dbJobStatusToProto(status db.NullScanJobStatus) advancedpb.JobStatus {
	if !status.Valid {
		return advancedpb.JobStatus_JOB_STATUS_UNSPECIFIED
	}
	switch status.ScanJobStatus {
	case db.ScanJobStatusCompleted:
		return advancedpb.JobStatus_JOB_STATUS_COMPLETED
	case db.ScanJobStatusRunning:
		return advancedpb.JobStatus_JOB_STATUS_RUNNING
	case db.ScanJobStatusPending:
		return advancedpb.JobStatus_JOB_STATUS_PENDING
	case db.ScanJobStatusFailed:
		return advancedpb.JobStatus_JOB_STATUS_FAILED
	default:
		return advancedpb.JobStatus_JOB_STATUS_FAILED
	}
}

func nanoCPULimitToQuota(nano int64) int64 {
	// Docker CPU quota is in microseconds per 100ms period.
	// 1 CPU ~= 1e9 nano CPU ~= quota 100000.
	if nano <= 0 {
		return 0
	}
	return (nano * 100000) / 1_000_000_000
}

func networkModeToDocker(cfg *advancedpb.ExecutionConfig) string {
	if cfg == nil || cfg.GetNetworkPolicy() == nil {
		return ""
	}
	switch cfg.GetNetworkPolicy().GetMode() {
	case advancedpb.NetworkMode_NETWORK_MODE_NONE:
		return "none"
	case advancedpb.NetworkMode_NETWORK_MODE_BRIDGE:
		return "bridge"
	case advancedpb.NetworkMode_NETWORK_MODE_HOST:
		return "host"
	default:
		return ""
	}
}

func envOrDefault(key, fallback string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	return v
}

func requireAuthorizedProject(ctx context.Context, projectID, ownerUserID uuid.UUID) error {
	if apiProjectID, ok := interceptor.GetAPIProjectID(ctx); ok && stringsTrim(apiProjectID) != "" {
		apiProjectUUID, err := uuid.Parse(stringsTrim(apiProjectID))
		if err != nil {
			return status.Errorf(codes.InvalidArgument, "invalid api project_id: %v", err)
		}
		if apiProjectUUID != projectID {
			return status.Error(codes.PermissionDenied, "api key does not allow access to this project")
		}
		return nil
	}

	userID, err := interceptor.RequireUserID(ctx)
	if err != nil {
		return err
	}
	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "invalid user_id: %v", err)
	}
	if ownerUserID != userUUID {
		return status.Error(codes.PermissionDenied, "project does not belong to authenticated user")
	}
	return nil
}

func apiKeyUUIDFromContext(ctx context.Context) (pgtype.UUID, error) {
	apiKeyID, ok := interceptor.GetAPIKeyID(ctx)
	if !ok || stringsTrim(apiKeyID) == "" {
		return pgtype.UUID{Valid: false}, nil
	}
	parsed, err := uuid.Parse(stringsTrim(apiKeyID))
	if err != nil {
		return pgtype.UUID{}, status.Errorf(codes.InvalidArgument, "invalid api_key_id: %v", err)
	}
	return pgtype.UUID{Bytes: parsed, Valid: true}, nil
}

func (s *advancedScanServer) requireOwnedJob(ctx context.Context, jobUUID uuid.UUID) (db.ScanJob, error) {
	jobRow, err := s.queries.GetScanJobByID(ctx, jobUUID)
	if err != nil {
		return db.ScanJob{}, status.Errorf(codes.NotFound, "job_id %q not found: %v", jobUUID.String(), err)
	}
	projectRow, err := s.queries.GetProjectByIDInternal(ctx, jobRow.ProjectID)
	if err != nil {
		return db.ScanJob{}, status.Errorf(codes.NotFound, "project for job_id %q not found: %v", jobUUID.String(), err)
	}
	if err := requireAuthorizedProject(ctx, projectRow.ProjectID, projectRow.UserID); err != nil {
		return db.ScanJob{}, err
	}
	return jobRow, nil
}

func (s *advancedScanServer) requireOwnedStep(ctx context.Context, stepUUID uuid.UUID) (db.ScanStep, db.ScanJob, error) {
	stepRow, err := s.queries.GetScanStepByID(ctx, stepUUID)
	if err != nil {
		return db.ScanStep{}, db.ScanJob{}, status.Errorf(codes.NotFound, "step_id %q not found: %v", stepUUID.String(), err)
	}
	jobRow, err := s.requireOwnedJob(ctx, stepRow.JobID)
	if err != nil {
		return db.ScanStep{}, db.ScanJob{}, err
	}
	return stepRow, jobRow, nil
}

func stepDurationMS(startedAt, finishedAt *time.Time) int64 {
	if startedAt == nil {
		return 0
	}
	end := time.Now().UTC()
	if finishedAt != nil {
		end = *finishedAt
	}
	if end.Before(*startedAt) {
		return 0
	}
	return end.Sub(*startedAt).Milliseconds()
}

func scanResultExitCodeAndError(rawData []byte) (int64, string) {
	if len(rawData) == 0 {
		return 0, ""
	}
	var payload struct {
		ExitCode int64  `json:"exit_code"`
		Error    string `json:"error"`
	}
	if err := json.Unmarshal(rawData, &payload); err != nil {
		return 0, ""
	}
	return payload.ExitCode, payload.Error
}
