package services

import (
	"time"

	tool "go-server/gen/tool"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type buildJobRecord struct {
	ID            string
	ToolID        string
	InstallMethod string
	ImageSource   string
	BuildJSON     string
	Status        tool.BuildJobStatus
	QueuedAt      time.Time
	StartedAt     *time.Time
	FinishedAt    *time.Time
	Error         string
}

type buildJobQueue struct {
	jobs   map[string]*buildJobRecord
	queued []string
}

func newBuildJobQueue() *buildJobQueue {
	return &buildJobQueue{
		jobs: make(map[string]*buildJobRecord),
	}
}

func (q *buildJobQueue) Enqueue(toolID, installMethod, imageSource, buildJSON string) *buildJobRecord {
	now := time.Now().UTC()
	job := &buildJobRecord{
		ID:            uuid.NewString(),
		ToolID:        toolID,
		InstallMethod: installMethod,
		ImageSource:   imageSource,
		BuildJSON:     buildJSON,
		Status:        tool.BuildJobStatus_QUEUED,
		QueuedAt:      now,
	}
	q.jobs[job.ID] = job
	q.queued = append(q.queued, job.ID)
	return cloneBuildJobRecord(job)
}

func (q *buildJobQueue) Claim(limit int) []*buildJobRecord {
	if limit <= 0 {
		limit = 10
	}
	if limit > len(q.queued) {
		limit = len(q.queued)
	}
	out := make([]*buildJobRecord, 0, limit)
	for _, id := range q.queued[:limit] {
		if job, ok := q.jobs[id]; ok {
			out = append(out, cloneBuildJobRecord(job))
		}
	}
	q.queued = append([]string(nil), q.queued[limit:]...)
	return out
}

func (q *buildJobQueue) UpdateStatus(id string, status tool.BuildJobStatus) (*buildJobRecord, bool) {
	job, ok := q.jobs[id]
	if !ok {
		return nil, false
	}
	job.Status = status
	if status == tool.BuildJobStatus_RUNNING && job.StartedAt == nil {
		now := time.Now().UTC()
		job.StartedAt = &now
	}
	return cloneBuildJobRecord(job), true
}

func (q *buildJobQueue) Finish(id string, status tool.BuildJobStatus, errText string) (*buildJobRecord, bool) {
	job, ok := q.jobs[id]
	if !ok {
		return nil, false
	}
	now := time.Now().UTC()
	job.Status = status
	job.Error = errText
	job.FinishedAt = &now
	if job.StartedAt == nil {
		job.StartedAt = &now
	}
	return cloneBuildJobRecord(job), true
}

func cloneBuildJobRecord(job *buildJobRecord) *buildJobRecord {
	if job == nil {
		return nil
	}
	cloned := *job
	if job.StartedAt != nil {
		started := *job.StartedAt
		cloned.StartedAt = &started
	}
	if job.FinishedAt != nil {
		finished := *job.FinishedAt
		cloned.FinishedAt = &finished
	}
	return &cloned
}

func buildJobToProto(job *buildJobRecord) *tool.BuildJob {
	if job == nil {
		return nil
	}
	out := &tool.BuildJob{
		Id:            job.ID,
		ToolId:        job.ToolID,
		InstallMethod: job.InstallMethod,
		ImageSource:   job.ImageSource,
		BuildJsonb:    job.BuildJSON,
		Status:        job.Status,
		QueuedAt:      timestamppb.New(job.QueuedAt),
		Error:         job.Error,
	}
	if job.StartedAt != nil {
		out.StartedAt = timestamppb.New(*job.StartedAt)
	}
	if job.FinishedAt != nil {
		out.FinishedAt = timestamppb.New(*job.FinishedAt)
	}
	return out
}
