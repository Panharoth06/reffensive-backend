package mediumscan

import (
	"context"
	"time"

	mediumspb "go-server/gen/mediumscan"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (s *mediumScanServer) GetScanStatus(ctx context.Context, req *mediumspb.GetScanStatusRequest) (*mediumspb.GetScanStatusResponse, error) {
	resp, err := s.GetStepStatus(ctx, &mediumspb.GetStepStatusRequest{StepId: req.GetScanId()})
	if err != nil {
		return nil, err
	}
	return &mediumspb.GetScanStatusResponse{
		StepId:            resp.StepId,
		JobId:             resp.JobId,
		ToolName:          resp.ToolName,
		Status:            resp.Status,
		ExitCode:          resp.ExitCode,
		ErrorMessage:      resp.ErrorMessage,
		QueuedAt:          resp.QueuedAt,
		StartedAt:         resp.StartedAt,
		FinishedAt:        resp.FinishedAt,
		DurationMs:        resp.DurationMs,
		FindingsCount:     resp.FindingsCount,
		RawOutputLocation: resp.RawOutputLocation,
		HasParsedResults:  resp.HasParsedResults,
	}, nil
}

func (s *mediumScanServer) GetStepStatus(ctx context.Context, req *mediumspb.GetStepStatusRequest) (*mediumspb.GetStepStatusResponse, error) {
	step, _, err := s.requireOwnedMediumStep(ctx, req.GetStepId())
	if err != nil {
		return nil, err
	}

	var startedAt, finishedAt *timestamppb.Timestamp
	var durationMS int64
	if step.StartedAt != nil {
		startedAt = timestamppb.New(*step.StartedAt)
	}
	if step.FinishedAt != nil {
		finishedAt = timestamppb.New(*step.FinishedAt)
	}
	if step.StartedAt != nil && step.FinishedAt != nil {
		durationMS = step.FinishedAt.Sub(*step.StartedAt).Milliseconds()
	}

	return &mediumspb.GetStepStatusResponse{
		StepId:            step.StepID,
		JobId:             step.JobID,
		ToolName:          step.ToolName,
		Status:            step.Status,
		ExitCode:          step.ExitCode,
		ErrorMessage:      step.Error,
		QueuedAt:          timestamppb.New(step.QueuedAt),
		StartedAt:         startedAt,
		FinishedAt:        finishedAt,
		DurationMs:        durationMS,
		FindingsCount:     step.Findings,
		RawOutputLocation: step.ArtifactPath,
		HasParsedResults:  step.Findings > 0,
	}, nil
}

func (s *mediumScanServer) GetJobStatus(ctx context.Context, req *mediumspb.GetJobStatusRequest) (*mediumspb.GetJobStatusResponse, error) {
	_, err := s.requireOwnedMediumJob(ctx, req.GetJobId())
	if err != nil {
		return nil, err
	}

	s.mu.RLock()
	job := s.jobs[req.GetJobId()]

	steps := make([]*mediumspb.StepSummary, 0, len(job.StepIDs))
	var completed, failed, pending int32
	var totalFindings int32
	for idx, stepID := range job.StepIDs {
		step, ok := s.steps[stepID]
		if !ok {
			continue
		}
		switch step.Status {
		case mediumspb.ScanStatus_SCAN_STATUS_COMPLETED:
			completed++
		case mediumspb.ScanStatus_SCAN_STATUS_FAILED, mediumspb.ScanStatus_SCAN_STATUS_CANCELLED, mediumspb.ScanStatus_SCAN_STATUS_SKIPPED:
			failed++
		case mediumspb.ScanStatus_SCAN_STATUS_PENDING, mediumspb.ScanStatus_SCAN_STATUS_QUEUED, mediumspb.ScanStatus_SCAN_STATUS_RUNNING:
			pending++
		}

		summary := &mediumspb.StepSummary{
			StepId:        step.StepID,
			ToolName:      step.ToolName,
			StepOrder:     int32(idx + 1),
			Status:        step.Status,
			FindingsCount: step.Findings,
		}
		if step.StartedAt != nil {
			summary.StartedAt = timestamppb.New(*step.StartedAt)
		}
		if step.FinishedAt != nil {
			summary.FinishedAt = timestamppb.New(*step.FinishedAt)
		}
		totalFindings += step.Findings
		steps = append(steps, summary)
	}
	s.mu.RUnlock()

	return &mediumspb.GetJobStatusResponse{
		JobId:          job.JobID,
		ProjectId:      job.ProjectID,
		Status:         job.Status,
		TotalSteps:     int32(len(job.StepIDs)),
		CompletedSteps: completed,
		FailedSteps:    failed,
		PendingSteps:   pending,
		TotalFindings:  totalFindings,
		CreatedAt:      timestamppb.New(job.CreatedAt),
		StartedAt:      toProtoTS(job.StartedAt),
		FinishedAt:     toProtoTS(job.FinishedAt),
		Steps:          steps,
	}, nil
}

func (s *mediumScanServer) StreamLogs(req *mediumspb.StreamLogsRequest, stream mediumspb.MediumScanService_StreamLogsServer) error {
	step, _, err := s.requireOwnedMediumStep(stream.Context(), req.GetStepId())
	if err != nil {
		return err
	}

	s.mu.RLock()
	stepID := step.StepID
	toolName := step.ToolName
	sent := 0
	s.mu.RUnlock()

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-stream.Context().Done():
			return nil
		case <-ticker.C:
			s.mu.RLock()
			step, ok := s.steps[stepID]
			if !ok {
				s.mu.RUnlock()
				return status.Error(codes.NotFound, "step not found")
			}
			logs := step.Logs
			statusNow := step.Status
			s.mu.RUnlock()

			for sent < len(logs) {
				if err := stream.Send(logs[sent]); err != nil {
					return err
				}
				sent++
			}

			if isTerminalStepStatus(statusNow) {
				if len(logs) == 0 {
					if err := stream.Send(&mediumspb.LogChunk{
						StepId:           stepID,
						ToolName:         toolName,
						Line:             "step finished",
						Source:           mediumspb.LogSource_LOG_SOURCE_SYSTEM,
						Timestamp:        timestamppb.Now(),
						SequenceNum:      int64(sent + 1),
						IsFinalChunk:     true,
						CompletionStatus: statusNow,
					}); err != nil {
						return err
					}
				}
				return nil
			}
		}
	}
}

func (s *mediumScanServer) CancelScan(ctx context.Context, req *mediumspb.CancelScanRequest) (*mediumspb.CancelScanResponse, error) {
	id := stringsTrim(req.GetScanId())
	if id == "" {
		return nil, status.Error(codes.InvalidArgument, "scan_id is required")
	}

	now := time.Now().UTC()

	s.mu.Lock()
	if step, ok := s.steps[id]; ok {
		// Verify ownership via the job's project
		job, jobOK := s.jobs[step.JobID]
		if !jobOK {
			s.mu.Unlock()
			return nil, status.Error(codes.NotFound, "job not found for step")
		}
		s.mu.Unlock()

		projectRow, err := s.queries.GetProjectByIDInternal(ctx, uuid.MustParse(job.ProjectID))
		if err != nil {
			return nil, status.Errorf(codes.NotFound, "project for job_id %q not found: %v", job.ProjectID, err)
		}
		if err := requireAuthorizedMediumProject(ctx, job.ProjectID, projectRow.UserID.String()); err != nil {
			return nil, err
		}

		s.mu.Lock()
		step.Status = mediumspb.ScanStatus_SCAN_STATUS_CANCELLED
		step.FinishedAt = &now
		step.Error = stringsTrim(req.GetReason())
		if job, exists := s.jobs[step.JobID]; exists {
			job.Status = mediumspb.JobStatus_JOB_STATUS_CANCELLED
			job.FinishedAt = &now
		}
		s.mu.Unlock()
		stepUUID, _ := uuid.Parse(step.StepID)
		_ = s.syncStepTerminalStatusToDB(stepUUID, mediumspb.ScanStatus_SCAN_STATUS_CANCELLED)
		go s.syncJobStatusToDB(step.JobID)
		return &mediumspb.CancelScanResponse{
			ScanId:      id,
			Cancelled:   true,
			Message:     "scan marked as cancelled",
			CancelledAt: timestamppb.New(now),
		}, nil
	}
	if job, ok := s.jobs[id]; ok {
		s.mu.Unlock()

		projectRow, err := s.queries.GetProjectByIDInternal(ctx, uuid.MustParse(job.ProjectID))
		if err != nil {
			return nil, status.Errorf(codes.NotFound, "project for job_id %q not found: %v", job.ProjectID, err)
		}
		if err := requireAuthorizedMediumProject(ctx, job.ProjectID, projectRow.UserID.String()); err != nil {
			return nil, err
		}

		s.mu.Lock()
		for _, stepID := range job.StepIDs {
			if step, exists := s.steps[stepID]; exists && !isTerminalStepStatus(step.Status) {
				step.Status = mediumspb.ScanStatus_SCAN_STATUS_CANCELLED
				step.FinishedAt = &now
				step.Error = stringsTrim(req.GetReason())
			}
		}
		job.Status = mediumspb.JobStatus_JOB_STATUS_CANCELLED
		job.FinishedAt = &now
		s.mu.Unlock()
		go s.syncJobStatusToDB(job.JobID)
		return &mediumspb.CancelScanResponse{
			ScanId:      id,
			Cancelled:   true,
			Message:     "job marked as cancelled",
			CancelledAt: timestamppb.New(now),
		}, nil
	}
	s.mu.Unlock()

	return nil, status.Error(codes.NotFound, "scan not found")
}

func (s *mediumScanServer) HealthCheck(ctx context.Context, req *emptypb.Empty) (*mediumspb.MediumHealthResponse, error) {
	_ = ctx
	_ = req

	s.mu.RLock()
	active := int32(0)
	queued := int32(0)
	for _, step := range s.steps {
		switch step.Status {
		case mediumspb.ScanStatus_SCAN_STATUS_RUNNING:
			active++
		case mediumspb.ScanStatus_SCAN_STATUS_QUEUED, mediumspb.ScanStatus_SCAN_STATUS_PENDING:
			queued++
		}
	}
	s.mu.RUnlock()

	return &mediumspb.MediumHealthResponse{
		Status:        mediumspb.HealthStatus_HEALTH_STATUS_HEALTHY,
		UptimeSeconds: int64(time.Since(s.startedAt).Seconds()),
		ActiveScans:   active,
		QueuedScans:   queued,
	}, nil
}
