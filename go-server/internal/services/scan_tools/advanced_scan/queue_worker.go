package advancedscan

import (
	"context"
	"fmt"
	"strings"
	"time"

	advancedpb "go-server/gen/advanced"
	redisutil "go-server/redis"

	"github.com/google/uuid"
)

// ProcessJob implements the redis.ServiceHandler interface.
// Called by the shared queue manager when an "advanced" scan job is dequeued.
func (s *advancedScanServer) ProcessJob(ctx context.Context, payload *redisutil.ScanJobPayload, receipt string, workerID int) {
	jobID := payload.JobID
	logPrefix := fmt.Sprintf("advanced-scan-worker-%d", workerID)
	s.publishLog("", logPrefix, advancedpb.LogSource_LOG_SOURCE_SYSTEM, fmt.Sprintf("starting job %s", jobID))

	s.ensureRuntimeForPayload(payload)

	// Reconstruct chain spec from payload
	chain := make([]chainStepSpec, 0, len(payload.Steps))

	var targetUUID uuid.UUID
	for i, stepPayload := range payload.Steps {
		// Resolve tool from DB
		toolUUID, err := uuid.Parse(stepPayload.ToolID)
		if err != nil {
			s.publishLog(stepPayload.StepID, stepPayload.ToolName, advancedpb.LogSource_LOG_SOURCE_SYSTEM, fmt.Sprintf("failed to parse tool UUID: %v", err))
			redisutil.GetManager().Complete(context.Background(), receipt)
			return
		}

		toolRow, err := s.queries.GetToolByID(context.Background(), toolUUID)
		if err != nil {
			s.publishLog(stepPayload.StepID, stepPayload.ToolName, advancedpb.LogSource_LOG_SOURCE_SYSTEM, fmt.Sprintf("failed to resolve tool: %v", err))
			redisutil.GetManager().Complete(context.Background(), receipt)
			return
		}

		stepUUID, _ := uuid.Parse(stepPayload.StepUUID)
		stepRow, err := s.queries.GetScanStepByID(context.Background(), stepUUID)
		if err != nil {
			s.publishLog(stepPayload.StepID, stepPayload.ToolName, advancedpb.LogSource_LOG_SOURCE_SYSTEM, fmt.Sprintf("failed to load step metadata: %v", err))
			redisutil.GetManager().Complete(context.Background(), receipt)
			return
		}
		jobUUID := payload.JobUUID
		projectUUID, _ := uuid.Parse(payload.ProjectID)
		inputStepUUID := uuid.Nil
		if strings.TrimSpace(stepPayload.InputStepID) != "" {
			inputStepUUID, _ = uuid.Parse(stepPayload.InputStepID)
		} else if stepRow.InputStepID.Valid {
			inputStepUUID = stepRow.InputStepID.Bytes
		}

		// Store target UUID from first step
		if i == 0 {
			targetUUID, _ = uuid.Parse(payload.TargetUUID)
		}

		chain = append(chain, chainStepSpec{
			StepID:         stepPayload.StepID,
			JobID:          jobID,
			ToolRow:        toolRow,
			ToolArgs:       stepPayload.ToolArgs,
			RawCustomFlags: stepPayload.RawCustomFlags,
			InputStepUUID:  inputStepUUID,
			StepUUID:       stepUUID,
			JobUUID:        jobUUID,
			ProjectUUID:    projectUUID,
			TargetUUID:     targetUUID,
		})
	}

	if len(chain) == 0 {
		s.publishLog("", logPrefix, advancedpb.LogSource_LOG_SOURCE_SYSTEM, fmt.Sprintf("job %s has no steps", jobID))
		redisutil.GetManager().Complete(context.Background(), receipt)
		return
	}

	request, err := buildQueuedExecutionRequest(payload)
	if err != nil {
		s.publishLog(chain[0].StepID, chain[0].ToolRow.ToolName, advancedpb.LogSource_LOG_SOURCE_SYSTEM, fmt.Sprintf("failed to rebuild queued request: %v", err))
		redisutil.GetManager().Complete(context.Background(), receipt)
		return
	}

	// Update job status to running
	s.mu.Lock()
	if job, ok := s.jobs[jobID]; ok {
		now := time.Now().UTC()
		job.Status = advancedpb.JobStatus_JOB_STATUS_RUNNING
		job.StartedAt = &now
	}
	s.mu.Unlock()

	for i := range chain {
		s.publishLog(chain[i].StepID, chain[i].ToolRow.ToolName, advancedpb.LogSource_LOG_SOURCE_SYSTEM, "step dequeued, starting execution")
	}

	// Execute the chain
	s.executeStepChain(request, chain)

	// Mark job complete in queue
	if err := redisutil.GetManager().Complete(context.Background(), receipt); err != nil {
		s.publishLog(jobID, logPrefix, advancedpb.LogSource_LOG_SOURCE_SYSTEM, fmt.Sprintf("failed to complete job in queue: %v", err))
	}

	s.publishLog(jobID, logPrefix, advancedpb.LogSource_LOG_SOURCE_SYSTEM, fmt.Sprintf("completed job %s", jobID))
}

func (s *advancedScanServer) ensureRuntimeForPayload(payload *redisutil.ScanJobPayload) {
	if payload == nil {
		return
	}

	now := time.Now().UTC()

	s.mu.Lock()
	defer s.mu.Unlock()

	job, ok := s.jobs[payload.JobID]
	if !ok {
		job = &jobRuntime{
			JobID:     payload.JobID,
			ProjectID: payload.ProjectID,
			Status:    advancedpb.JobStatus_JOB_STATUS_QUEUED,
			CreatedAt: payload.SubmittedAt,
		}
		if job.CreatedAt.IsZero() {
			job.CreatedAt = now
		}
		s.jobs[payload.JobID] = job
	}

	for _, stepPayload := range payload.Steps {
		if _, ok := s.steps[stepPayload.StepID]; ok {
			if !containsStepID(job.StepIDs, stepPayload.StepID) {
				job.StepIDs = append(job.StepIDs, stepPayload.StepID)
			}
			continue
		}
		s.steps[stepPayload.StepID] = &stepRuntime{
			StepID:       stepPayload.StepID,
			JobID:        payload.JobID,
			ToolName:     stepPayload.ToolName,
			Status:       advancedpb.StepStatus_STEP_STATUS_QUEUED,
			QueuedAt:     now,
			CommandPlan:  nil,
			Logs:         make([]*advancedpb.LogChunk, 0, 64),
			SequenceNum:  0,
			ArtifactPath: "",
		}
		if !containsStepID(job.StepIDs, stepPayload.StepID) {
			job.StepIDs = append(job.StepIDs, stepPayload.StepID)
		}
	}
}

func containsStepID(stepIDs []string, target string) bool {
	for _, stepID := range stepIDs {
		if stepID == target {
			return true
		}
	}
	return false
}
