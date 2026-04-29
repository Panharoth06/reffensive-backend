package advancedscan

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	advancedpb "go-server/gen/advanced"
	redisutil "go-server/redis"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// GetQueueStatus returns the current queue status
func (s *advancedScanServer) GetQueueStatus(ctx context.Context, req *advancedpb.QueueStatusRequest) (*advancedpb.QueueStatusResponse, error) {
	qm := redisutil.GetManager()
	stats, err := qm.GetQueueStats(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get queue stats: %v", err)
	}

	cfg := qm.Config()
	return &advancedpb.QueueStatusResponse{
		QueuedJobs:       queueStatInt64(stats["queued"]),
		ProcessingJobs:   queueStatInt64(stats["processing"]),
		TotalJobs:        queueStatInt64(stats["total"]),
		MaxConcurrent:    int32(cfg.MaxConcurrent),
		MaxQueueCapacity: int32(cfg.MaxQueueCapacity),
	}, nil
}

// GetJobQueuePosition returns the position of a specific job in the queue
func (s *advancedScanServer) GetJobQueuePosition(ctx context.Context, req *advancedpb.JobQueuePositionRequest) (*advancedpb.JobQueuePositionResponse, error) {
	jobID := stringsTrim(req.GetJobId())
	if jobID == "" {
		return nil, status.Error(codes.InvalidArgument, "job_id is required")
	}
	jobUUID, err := uuid.Parse(jobID)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid job_id: %v", err)
	}
	if _, err := s.requireOwnedJob(ctx, jobUUID); err != nil {
		return nil, err
	}

	qm := redisutil.GetManager()
	position, err := qm.GetJobPosition(ctx, jobID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get job position: %v", err)
	}

	resp := &advancedpb.JobQueuePositionResponse{
		JobId: jobID,
	}

	switch position {
	case -1:
		resp.Status = "not_in_queue"
		resp.Position = -1
	case -2:
		resp.Status = "processing"
		resp.Position = 0
	default:
		resp.Status = "queued"
		resp.Position = position
	}

	return resp, nil
}

// CancelQueuedJob removes a job from the queue if it hasn't started processing
func (s *advancedScanServer) CancelQueuedJob(ctx context.Context, req *advancedpb.CancelQueuedJobRequest) (*advancedpb.CancelQueuedJobResponse, error) {
	jobID := stringsTrim(req.GetJobId())
	if jobID == "" {
		return nil, status.Error(codes.InvalidArgument, "job_id is required")
	}
	jobUUID, err := uuid.Parse(jobID)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid job_id: %v", err)
	}
	if _, err := s.requireOwnedJob(ctx, jobUUID); err != nil {
		return nil, err
	}

	qm := redisutil.GetManager()
	position, err := qm.GetJobPosition(ctx, jobID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get job position: %v", err)
	}

	if position == -1 {
		return &advancedpb.CancelQueuedJobResponse{
			Success: false,
			Message: "job not found in queue (may already be processing or completed)",
		}, nil
	}

	if position == -2 {
		return &advancedpb.CancelQueuedJobResponse{
			Success: false,
			Message: "job is already being processed and cannot be cancelled",
		}, nil
	}

	// Job is in queue - remove it
	// We need to rebuild the queue without this job
	items, err := qm.GetQueueItems(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to read queue: %v", err)
	}

	removed := false
	keptItems := make([]string, 0, len(items))
	for _, item := range items {
		var payload redisutil.ScanJobPayload
		if err := json.Unmarshal([]byte(item), &payload); err != nil {
			keptItems = append(keptItems, item)
			continue
		}
		if payload.JobID == jobID && !removed {
			removed = true
			continue
		}
		keptItems = append(keptItems, item)
	}

	if !removed {
		return &advancedpb.CancelQueuedJobResponse{
			Success: false,
			Message: "job not found in queue",
		}, nil
	}

	// Recreate queue with remaining items
	if err := qm.RebuildQueue(ctx, keptItems); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to rebuild queue: %v", err)
	}

	// Update in-memory state
	s.mu.Lock()
	if job, ok := s.jobs[jobID]; ok {
		job.Status = advancedpb.JobStatus_JOB_STATUS_CANCELLED
	}
	s.mu.Unlock()

	return &advancedpb.CancelQueuedJobResponse{
		Success: true,
		Message: fmt.Sprintf("job %s cancelled successfully", jobID),
	}, nil
}

func queueStatInt64(v any) int64 {
	switch value := v.(type) {
	case nil:
		return 0
	case int:
		return int64(value)
	case int8:
		return int64(value)
	case int16:
		return int64(value)
	case int32:
		return int64(value)
	case int64:
		return value
	case uint:
		return int64(value)
	case uint8:
		return int64(value)
	case uint16:
		return int64(value)
	case uint32:
		return int64(value)
	case uint64:
		if value > uint64(^uint64(0)>>1) {
			return int64(^uint64(0) >> 1)
		}
		return int64(value)
	case float32:
		return int64(value)
	case float64:
		return int64(value)
	case json.Number:
		if i, err := value.Int64(); err == nil {
			return i
		}
		if f, err := value.Float64(); err == nil {
			return int64(f)
		}
	case string:
		if i, err := strconv.ParseInt(value, 10, 64); err == nil {
			return i
		}
		if f, err := strconv.ParseFloat(value, 64); err == nil {
			return int64(f)
		}
	}
	return 0
}
