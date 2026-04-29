package queue

import (
	"encoding/json"
	"fmt"

	"github.com/hibiken/asynq"
)

const TypeRunScan = "sonarqube:scan:run"

type ScanTaskPayload struct {
	ScanID     string `json:"scan_id"`
	RepoURL    string `json:"repo_url"`
	ProjectKey string `json:"project_key"`
	Branch     string `json:"branch,omitempty"`
}

func NewScanTask(payload ScanTaskPayload) (*asynq.Task, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal sonarqube scan task: %w", err)
	}
	return asynq.NewTask(TypeRunScan, data), nil
}

func ParseScanTask(task *asynq.Task) (ScanTaskPayload, error) {
	var payload ScanTaskPayload
	if err := json.Unmarshal(task.Payload(), &payload); err != nil {
		return ScanTaskPayload{}, fmt.Errorf("unmarshal sonarqube scan task: %w", err)
	}
	return payload, nil
}
