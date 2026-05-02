package advancedscan

import (
	"context"
	"fmt"
	"strings"
	"time"

	advancedpb "go-server/gen/advanced"
	db "go-server/internal/database/sqlc"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (s *advancedScanServer) StreamLogs(req *advancedpb.StreamLogsRequest, stream advancedpb.AdvancedScanService_StreamLogsServer) error {
	stepID := stringsTrim(req.GetStepId())
	if stepID == "" {
		return status.Error(codes.InvalidArgument, "step_id is required")
	}

	stepUUID, err := uuid.Parse(stepID)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "invalid step_id: %v", err)
	}
	if _, _, err := s.requireOwnedStep(stream.Context(), stepUUID); err != nil {
		return err
	}

	s.mu.RLock()
	stepRuntime, ok := s.steps[stepID]
	if !ok {
		s.mu.RUnlock()
		return status.Error(codes.NotFound, "in-memory log history is not available for this step")
	}

	toolName := stepRuntime.ToolName
	lastSentSequence := int64(0)
	historyChunks := selectReplayableLogChunks(stepRuntime.Logs, req)
	if !req.GetIncludeHistory() && len(stepRuntime.Logs) > 0 {
		lastSentSequence = stepRuntime.Logs[len(stepRuntime.Logs)-1].GetSequenceNum()
	}
	s.mu.RUnlock()

	for _, chunk := range historyChunks {
		if err := stream.Send(chunk); err != nil {
			return err
		}
		lastSentSequence = chunk.GetSequenceNum()
	}

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	emittedAnyChunk := len(historyChunks) > 0
	for {
		select {
		case <-stream.Context().Done():
			return nil
		case <-ticker.C:
			s.mu.RLock()
			stepRuntime, ok := s.steps[stepID]
			if !ok {
				s.mu.RUnlock()
				return status.Error(codes.NotFound, "step not found")
			}

			liveChunks := collectLiveLogChunks(stepRuntime.Logs, req.GetFilter(), lastSentSequence)
			stepStatus := stepRuntime.Status
			nextSequenceNumber := stepRuntime.SequenceNum + 1
			s.mu.RUnlock()

			for _, chunk := range liveChunks {
				if err := stream.Send(chunk); err != nil {
					return err
				}
				lastSentSequence = chunk.GetSequenceNum()
				emittedAnyChunk = true
			}

			if isTerminalStepStatus(stepStatus) {
				if !emittedAnyChunk {
					if err := stream.Send(&advancedpb.LogChunk{
						StepId:           stepID,
						ToolName:         toolName,
						Line:             "step finished",
						Source:           advancedpb.LogSource_LOG_SOURCE_SYSTEM,
						Timestamp:        timestamppb.Now(),
						SequenceNum:      nextSequenceNumber,
						IsFinalChunk:     true,
						CompletionStatus: stepStatus,
					}); err != nil {
						return err
					}
				}
				return nil
			}
		}
	}
}

func (s *advancedScanServer) GetStepStatus(ctx context.Context, req *advancedpb.GetStepStatusRequest) (*advancedpb.GetStepStatusResponse, error) {
	stepID := stringsTrim(req.GetStepId())
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

	findingsByStep, _, findingsErr := s.findingsCountByStep(ctx, jobRow.JobID)
	if findingsErr != nil {
		return nil, status.Errorf(codes.Internal, "failed to load findings for step_id %q: %v", stepID, findingsErr)
	}
	findingsCount := findingsByStep[stepUUID]

	if runtimeResp := s.runtimeStepStatusSnapshot(stepID, findingsCount); runtimeResp != nil {
		return runtimeResp, nil
	}

	toolName, err := s.resolveToolNameCached(ctx, map[uuid.UUID]string{}, stepRow.ToolID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to resolve tool for step %q: %v", stepID, err)
	}

	resultsRows, err := s.queries.ListScanResultsByStep(ctx, db.ListScanResultsByStepParams{
		StepID: stepUUID,
		JobID:  jobRow.JobID,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to load scan results for step_id %q: %v", stepID, err)
	}

	var exitCode int64
	var errorMessage string
	hasParsedResults := false
	if len(resultsRows) > 0 {
		last := resultsRows[len(resultsRows)-1]
		exitCode, errorMessage = scanResultExitCodeAndError(last.RawData)
		hasParsedResults = len(last.ParsedData) > 0 || findingsCount > 0
	}

	var startedAtPtr *time.Time
	if stepRow.StartedAt.Valid {
		t := stepRow.StartedAt.Time
		startedAtPtr = &t
	}
	var finishedAtPtr *time.Time
	if stepRow.FinishedAt.Valid {
		t := stepRow.FinishedAt.Time
		finishedAtPtr = &t
	}

	return &advancedpb.GetStepStatusResponse{
		StepId:            stepRow.StepID.String(),
		JobId:             stepRow.JobID.String(),
		ToolName:          toolName,
		Status:            dbStepStatusToProto(stepRow.Status),
		ExitCode:          exitCode,
		ErrorMessage:      errorMessage,
		QueuedAt:          pgTimestampToProto(stepRow.CreatedAt),
		StartedAt:         pgTimestampToProto(stepRow.StartedAt),
		FinishedAt:        pgTimestampToProto(stepRow.FinishedAt),
		DurationMs:        stepDurationMS(startedAtPtr, finishedAtPtr),
		FindingsCount:     findingsCount,
		RawOutputLocation: "",
		HasParsedResults:  hasParsedResults,
	}, nil
}

func (s *advancedScanServer) GetJobStatus(ctx context.Context, req *advancedpb.GetJobStatusRequest) (*advancedpb.GetJobStatusResponse, error) {
	jobID := stringsTrim(req.GetJobId())
	if jobID == "" {
		return nil, status.Error(codes.InvalidArgument, "job_id is required")
	}
	jobUUID, err := uuid.Parse(jobID)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid job_id: %v", err)
	}

	jobRow, err := s.requireOwnedJob(ctx, jobUUID)
	if err != nil {
		return nil, err
	}

	findingsByStep, totalFindings, findingsErr := s.findingsCountByStep(ctx, jobUUID)
	if findingsErr != nil {
		return nil, status.Errorf(codes.Internal, "failed to load findings for job_id %q: %v", jobID, findingsErr)
	}

	// Prefer runtime state when available so clients see in-progress transitions.
	if runtimeResp := s.runtimeJobStatusSnapshot(jobID, findingsByStep, totalFindings); runtimeResp != nil {
		return runtimeResp, nil
	}

	stepRows, err := s.queries.ListScanStepsByJob(ctx, jobUUID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list scan steps for job_id %q: %v", jobID, err)
	}

	toolNameByID := make(map[uuid.UUID]string)
	stepSummaries := make([]*advancedpb.StepSummary, 0, len(stepRows))
	var completed, failed, pending int32
	var startedAt *time.Time

	for _, row := range stepRows {
		toolName, nameErr := s.resolveToolNameCached(ctx, toolNameByID, row.ToolID)
		if nameErr != nil {
			return nil, status.Errorf(codes.Internal, "failed to resolve tool for step %q: %v", row.StepID.String(), nameErr)
		}

		stepStatus := dbStepStatusToProto(row.Status)
		switch stepStatus {
		case advancedpb.StepStatus_STEP_STATUS_COMPLETED:
			completed++
		case advancedpb.StepStatus_STEP_STATUS_FAILED:
			failed++
		case advancedpb.StepStatus_STEP_STATUS_PENDING,
			advancedpb.StepStatus_STEP_STATUS_QUEUED,
			advancedpb.StepStatus_STEP_STATUS_RUNNING:
			pending++
		}

		if row.StartedAt.Valid {
			t := row.StartedAt.Time
			if startedAt == nil || t.Before(*startedAt) {
				startedAt = &t
			}
		}

		stepSummaries = append(stepSummaries, &advancedpb.StepSummary{
			StepId:        row.StepID.String(),
			ToolName:      toolName,
			StepOrder:     row.StepOrder,
			Status:        stepStatus,
			FindingsCount: findingsByStep[row.StepID],
			StartedAt:     pgTimestampToProto(row.StartedAt),
			FinishedAt:    pgTimestampToProto(row.FinishedAt),
		})
	}

	jobStatus := dbJobStatusToProto(jobRow.Status)
	if jobStatus == advancedpb.JobStatus_JOB_STATUS_UNSPECIFIED {
		jobStatus = deriveJobStatus(completed, failed, pending)
	}

	return &advancedpb.GetJobStatusResponse{
		JobId:          jobRow.JobID.String(),
		ProjectId:      jobRow.ProjectID.String(),
		Status:         jobStatus,
		TotalSteps:     int32(len(stepSummaries)),
		CompletedSteps: completed,
		FailedSteps:    failed,
		PendingSteps:   pending,
		TotalFindings:  totalFindings,
		CreatedAt:      pgTimestampToProto(jobRow.CreatedAt),
		StartedAt:      timePtrToProto(startedAt),
		FinishedAt:     pgTimestampToProto(jobRow.FinishedAt),
		Steps:          stepSummaries,
	}, nil
}

func (s *advancedScanServer) runtimeStepStatusSnapshot(stepID string, findingsCount int32) *advancedpb.GetStepStatusResponse {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stepRuntime, ok := s.steps[stepID]
	if !ok {
		return nil
	}

	if stepRuntime.Findings > 0 {
		findingsCount = stepRuntime.Findings
	}

	return &advancedpb.GetStepStatusResponse{
		StepId:            stepRuntime.StepID,
		JobId:             stepRuntime.JobID,
		ToolName:          stepRuntime.ToolName,
		Status:            stepRuntime.Status,
		ExitCode:          stepRuntime.ExitCode,
		ErrorMessage:      stepRuntime.Error,
		QueuedAt:          timestamppb.New(stepRuntime.QueuedAt),
		StartedAt:         timePtrToProto(stepRuntime.StartedAt),
		FinishedAt:        timePtrToProto(stepRuntime.FinishedAt),
		DurationMs:        stepDurationMS(stepRuntime.StartedAt, stepRuntime.FinishedAt),
		FindingsCount:     findingsCount,
		RawOutputLocation: stepRuntime.ArtifactPath,
		HasParsedResults:  stepRuntime.HasParsedData || findingsCount > 0,
	}
}

func selectReplayableLogChunks(logChunks []*advancedpb.LogChunk, req *advancedpb.StreamLogsRequest) []*advancedpb.LogChunk {
	if !req.GetIncludeHistory() || len(logChunks) == 0 {
		return nil
	}

	filteredChunks := filterLogChunks(logChunks, req.GetFilter(), 0)
	historyLimit := int(req.GetHistoryLimit())
	if historyLimit <= 0 || historyLimit >= len(filteredChunks) {
		return filteredChunks
	}
	return append([]*advancedpb.LogChunk(nil), filteredChunks[len(filteredChunks)-historyLimit:]...)
}

func collectLiveLogChunks(logChunks []*advancedpb.LogChunk, filter *advancedpb.LogFilter, afterSequenceNumber int64) []*advancedpb.LogChunk {
	filteredChunks := filterLogChunks(logChunks, filter, afterSequenceNumber)
	if len(filteredChunks) == 0 {
		return nil
	}
	return filteredChunks
}

func filterLogChunks(logChunks []*advancedpb.LogChunk, filter *advancedpb.LogFilter, afterSequenceNumber int64) []*advancedpb.LogChunk {
	filteredChunks := make([]*advancedpb.LogChunk, 0, len(logChunks))
	for _, chunk := range logChunks {
		if chunk.GetSequenceNum() <= afterSequenceNumber {
			continue
		}
		if !matchesLogFilter(chunk, filter) {
			continue
		}
		filteredChunks = append(filteredChunks, chunk)
	}
	return filteredChunks
}

func matchesLogFilter(chunk *advancedpb.LogChunk, filter *advancedpb.LogFilter) bool {
	if chunk == nil {
		return false
	}
	if filter == nil {
		return true
	}

	if len(filter.GetSources()) > 0 {
		sourceAllowed := false
		for _, source := range filter.GetSources() {
			if chunk.GetSource() == source {
				sourceAllowed = true
				break
			}
		}
		if !sourceAllowed {
			return false
		}
	}

	keyword := strings.ToLower(stringsTrim(filter.GetKeyword()))
	if keyword != "" && !strings.Contains(strings.ToLower(chunk.GetLine()), keyword) {
		return false
	}

	afterTimestamp := filter.GetAfterTimestamp()
	if afterTimestamp > 0 {
		chunkTimestamp := int64(0)
		if chunk.GetTimestamp() != nil {
			chunkTimestamp = chunk.GetTimestamp().AsTime().Unix()
		}
		if chunkTimestamp <= afterTimestamp {
			return false
		}
	}

	return true
}

func (s *advancedScanServer) runtimeJobStatusSnapshot(jobID string, findingsByStep map[uuid.UUID]int32, totalFindings int32) *advancedpb.GetJobStatusResponse {
	s.mu.RLock()
	defer s.mu.RUnlock()

	jobRuntime, ok := s.jobs[jobID]
	if !ok {
		return nil
	}

	stepSummaries := make([]*advancedpb.StepSummary, 0, len(jobRuntime.StepIDs))
	var completed, failed, pending int32
	var earliestStart *time.Time
	var latestFinish *time.Time
	for idx, stepID := range jobRuntime.StepIDs {
		step := s.steps[stepID]
		if step == nil {
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

		findingsCount := step.Findings
		if findingsCount == 0 {
			if parsedUUID, err := uuid.Parse(step.StepID); err == nil {
				if dbCount, ok := findingsByStep[parsedUUID]; ok {
					findingsCount = dbCount
				}
			}
		}

		stepSummaries = append(stepSummaries, &advancedpb.StepSummary{
			StepId:        step.StepID,
			ToolName:      step.ToolName,
			StepOrder:     int32(idx + 1),
			Status:        step.Status,
			FindingsCount: findingsCount,
			StartedAt:     timePtrToProto(step.StartedAt),
			FinishedAt:    timePtrToProto(step.FinishedAt),
		})
	}

	status := deriveJobStatus(completed, failed, pending)
	if len(stepSummaries) == 0 {
		status = jobRuntime.Status
	}
	startedAt := earliestStart
	if startedAt == nil {
		startedAt = jobRuntime.StartedAt
	}
	finishedAt := latestFinish
	if finishedAt == nil {
		finishedAt = jobRuntime.FinishedAt
	}

	return &advancedpb.GetJobStatusResponse{
		JobId:          jobRuntime.JobID,
		ProjectId:      jobRuntime.ProjectID,
		Status:         status,
		TotalSteps:     int32(len(stepSummaries)),
		CompletedSteps: completed,
		FailedSteps:    failed,
		PendingSteps:   pending,
		TotalFindings:  totalFindings,
		CreatedAt:      timestamppb.New(jobRuntime.CreatedAt),
		StartedAt:      timePtrToProto(startedAt),
		FinishedAt:     timePtrToProto(finishedAt),
		Steps:          stepSummaries,
	}
}

func (s *advancedScanServer) resolveToolNameCached(ctx context.Context, cache map[uuid.UUID]string, toolID uuid.UUID) (string, error) {
	if name, ok := cache[toolID]; ok {
		return name, nil
	}
	row, err := s.queries.GetToolByID(ctx, toolID)
	if err != nil {
		return "", fmt.Errorf("get tool by id %q: %w", toolID.String(), err)
	}
	cache[toolID] = row.ToolName
	return row.ToolName, nil
}

func (s *advancedScanServer) findingsCountByStep(ctx context.Context, jobID uuid.UUID) (map[uuid.UUID]int32, int32, error) {
	rows, err := s.queries.ListFindingsByJob(ctx, jobID)
	if err != nil {
		return nil, 0, err
	}
	out := make(map[uuid.UUID]int32)
	for _, row := range rows {
		out[row.StepID]++
	}
	return out, int32(len(rows)), nil
}

func pgTimestampToProto(ts pgtype.Timestamptz) *timestamppb.Timestamp {
	if !ts.Valid {
		return nil
	}
	return timestamppb.New(ts.Time)
}

func timePtrToProto(t *time.Time) *timestamppb.Timestamp {
	if t == nil {
		return nil
	}
	return timestamppb.New(*t)
}
