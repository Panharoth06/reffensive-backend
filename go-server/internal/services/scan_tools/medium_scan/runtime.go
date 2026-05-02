package mediumscan

import (
	"context"
	"fmt"
	"time"

	mediumspb "go-server/gen/mediumscan"
	db "go-server/internal/database/sqlc"

	"github.com/google/uuid"
)

func (s *mediumScanServer) markStepRunning(stepID, jobID string, stepUUID uuid.UUID, startedAt time.Time) bool {
	stepCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := s.queries.StartScanStep(stepCtx, stepUUID); err != nil {
		s.publishLog(stepID, "", mediumspb.LogSource_LOG_SOURCE_SYSTEM, fmt.Sprintf("warning: failed to mark step running in DB: %v", err))
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	step, ok := s.steps[stepID]
	if !ok {
		return false
	}
	if isTerminalStepStatus(step.Status) {
		return false
	}
	step.Status = mediumspb.ScanStatus_SCAN_STATUS_RUNNING
	step.StartedAt = &startedAt
	step.Error = ""
	s.recomputeJobStatusLocked(jobID)
	go s.syncJobStatusToDB(jobID)
	return true
}

func (s *mediumScanServer) recomputeJobStatusLocked(jobID string) {
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
		case mediumspb.ScanStatus_SCAN_STATUS_COMPLETED:
			completed++
		case mediumspb.ScanStatus_SCAN_STATUS_FAILED, mediumspb.ScanStatus_SCAN_STATUS_CANCELLED, mediumspb.ScanStatus_SCAN_STATUS_SKIPPED:
			failed++
		case mediumspb.ScanStatus_SCAN_STATUS_PENDING, mediumspb.ScanStatus_SCAN_STATUS_QUEUED, mediumspb.ScanStatus_SCAN_STATUS_RUNNING:
			pending++
		}
		if step.StartedAt != nil && (earliestStart == nil || step.StartedAt.Before(*earliestStart)) {
			tmp := *step.StartedAt
			earliestStart = &tmp
		}
		if step.FinishedAt != nil && (latestFinish == nil || step.FinishedAt.After(*latestFinish)) {
			tmp := *step.FinishedAt
			latestFinish = &tmp
		}
	}

	job.Status = deriveJobStatus(completed, failed, pending)
	job.StartedAt = earliestStart
	job.FinishedAt = latestFinish
}

func deriveJobStatus(completed, failed, pending int32) mediumspb.JobStatus {
	switch {
	case failed > 0 && completed > 0:
		return mediumspb.JobStatus_JOB_STATUS_PARTIAL
	case failed > 0 && pending == 0:
		return mediumspb.JobStatus_JOB_STATUS_FAILED
	case completed > 0 && pending == 0 && failed == 0:
		return mediumspb.JobStatus_JOB_STATUS_COMPLETED
	case pending > 0:
		return mediumspb.JobStatus_JOB_STATUS_RUNNING
	default:
		return mediumspb.JobStatus_JOB_STATUS_PENDING
	}
}

func (s *mediumScanServer) syncStepTerminalStatusToDB(stepUUID uuid.UUID, status mediumspb.ScanStatus) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := s.queries.FinishScanStep(ctx, db.FinishScanStepParams{
		StepID: stepUUID,
		Status: db.NullScanStepStatus{ScanStepStatus: protoStepStatusToDB(status), Valid: true},
	})
	return err
}

func (s *mediumScanServer) syncJobStatusToDB(jobID string) {
	s.mu.RLock()
	job, ok := s.jobs[jobID]
	s.mu.RUnlock()
	if !ok {
		return
	}
	jobUUID, err := uuid.Parse(jobID)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, _ = s.queries.UpdateScanJobStatus(ctx, db.UpdateScanJobStatusParams{
		JobID:  jobUUID,
		Status: db.NullScanJobStatus{ScanJobStatus: protoJobStatusToDB(job.Status), Valid: true},
	})
	if isTerminalJobStatus(job.Status) {
		_, _ = s.queries.FinishScanJob(ctx, db.FinishScanJobParams{
			JobID:  jobUUID,
			Status: db.NullScanJobStatus{ScanJobStatus: protoJobStatusToDB(job.Status), Valid: true},
		})
	}
}

func requestExecutionModeToDB(mode mediumspb.ExecutionMode) db.ExecutionMode {
	switch mode {
	case mediumspb.ExecutionMode_EXECUTION_MODE_CLI:
		return db.ExecutionModeCli
	case mediumspb.ExecutionMode_EXECUTION_MODE_CICD:
		return db.ExecutionModeCicd
	default:
		return db.ExecutionModeWeb
	}
}

func protoStepStatusToDB(status mediumspb.ScanStatus) db.ScanStepStatus {
	switch status {
	case mediumspb.ScanStatus_SCAN_STATUS_COMPLETED:
		return db.ScanStepStatusCompleted
	case mediumspb.ScanStatus_SCAN_STATUS_SKIPPED:
		return db.ScanStepStatusSkipped
	case mediumspb.ScanStatus_SCAN_STATUS_RUNNING:
		return db.ScanStepStatusRunning
	case mediumspb.ScanStatus_SCAN_STATUS_QUEUED, mediumspb.ScanStatus_SCAN_STATUS_PENDING:
		return db.ScanStepStatusPending
	default:
		return db.ScanStepStatusFailed
	}
}

func protoJobStatusToDB(status mediumspb.JobStatus) db.ScanJobStatus {
	switch status {
	case mediumspb.JobStatus_JOB_STATUS_COMPLETED:
		return db.ScanJobStatusCompleted
	case mediumspb.JobStatus_JOB_STATUS_RUNNING:
		return db.ScanJobStatusRunning
	case mediumspb.JobStatus_JOB_STATUS_PENDING:
		return db.ScanJobStatusPending
	default:
		return db.ScanJobStatusFailed
	}
}

func isTerminalJobStatus(status mediumspb.JobStatus) bool {
	switch status {
	case mediumspb.JobStatus_JOB_STATUS_COMPLETED,
		mediumspb.JobStatus_JOB_STATUS_FAILED,
		mediumspb.JobStatus_JOB_STATUS_CANCELLED,
		mediumspb.JobStatus_JOB_STATUS_PARTIAL:
		return true
	default:
		return false
	}
}

func isTerminalStepStatus(status mediumspb.ScanStatus) bool {
	switch status {
	case mediumspb.ScanStatus_SCAN_STATUS_COMPLETED,
		mediumspb.ScanStatus_SCAN_STATUS_FAILED,
		mediumspb.ScanStatus_SCAN_STATUS_CANCELLED,
		mediumspb.ScanStatus_SCAN_STATUS_SKIPPED:
		return true
	default:
		return false
	}
}
