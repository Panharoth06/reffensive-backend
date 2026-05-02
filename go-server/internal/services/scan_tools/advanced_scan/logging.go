package advancedscan

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	advancedpb "go-server/gen/advanced"
	redisutil "go-server/redis"

	"google.golang.org/protobuf/types/known/timestamppb"
)

func (s *advancedScanServer) publishLog(stepID, toolName string, source advancedpb.LogSource, line string) {
	line = strings.TrimRight(line, "\r")
	if line == "" {
		return
	}

	now := time.Now().UTC()

	s.mu.Lock()
	step, ok := s.steps[stepID]
	if !ok {
		s.mu.Unlock()
		return
	}
	step.SequenceNum++
	seq := step.SequenceNum
	completion := step.Status
	isFinalChunk := isTerminalStepStatus(step.Status)
	chunk := &advancedpb.LogChunk{
		StepId:           step.StepID,
		ToolName:         toolName,
		Line:             line,
		Source:           source,
		Timestamp:        timestamppb.New(now),
		SequenceNum:      seq,
		IsFinalChunk:     isFinalChunk,
		CompletionStatus: completion,
	}
	step.Logs = append(step.Logs, chunk)
	if len(step.Logs) > 2000 {
		step.Logs = step.Logs[len(step.Logs)-2000:]
	}
	jobID := step.JobID
	s.mu.Unlock()

	payload := map[string]any{
		"step_id":           stepID,
		"job_id":            jobID,
		"tool_name":         toolName,
		"source":            source.String(),
		"line":              line,
		"timestamp":         now.Format(time.RFC3339Nano),
		"sequence_num":      seq,
		"is_final_chunk":    isFinalChunk,
		"completion_status": completion.String(),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return
	}

	channel := s.logChannel(stepID)
	pubCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = redisutil.PublishResult(pubCtx, s.redisClient, channel, string(body))
}
