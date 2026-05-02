package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

// ScanJobPayload represents a scan job that gets enqueued
type ScanJobPayload struct {
	JobID               string        `json:"job_id"`
	JobUUID             uuid.UUID     `json:"job_uuid"`
	ProjectID           string        `json:"project_id"`
	TargetUUID          string        `json:"target_uuid"`
	TargetValue         string        `json:"target_value"`
	Steps               []StepPayload `json:"steps"`
	ExecutionConfigJSON string        `json:"execution_config_json,omitempty"`
	ShadowConfigJSON    string        `json:"shadow_config_json,omitempty"`
	SubmittedAt         time.Time     `json:"submitted_at"`
	ServiceName         string        `json:"service_name"` // "advanced", "basic", "medium" — determines which handler processes this job
}

type StepPayload struct {
	StepID         string            `json:"step_id"`
	StepUUID       string            `json:"step_uuid"`
	InputStepID    string            `json:"input_step_id,omitempty"`
	ToolName       string            `json:"tool_name"`
	ToolID         string            `json:"tool_id"`
	ToolArgs       map[string]string `json:"tool_args"`
	RawCustomFlags []string          `json:"raw_custom_flags"`
	StepOrder      int               `json:"step_order"`
}

// QueueConfig holds Redis queue configuration
type QueueConfig struct {
	QueueName         string
	ProcessingName    string
	MaxRetries        int
	VisibilityTimeout time.Duration
	MaxConcurrent     int // max jobs processed simultaneously
	MaxQueueCapacity  int // max jobs allowed in queue (0 = unlimited)
}

// DefaultQueueConfig returns a sensible default
func DefaultQueueConfig() QueueConfig {
	return QueueConfig{
		QueueName:         "scan:queue",
		ProcessingName:    "scan:processing",
		MaxRetries:        3,
		VisibilityTimeout: 30 * time.Minute,
		MaxConcurrent:     20,
		MaxQueueCapacity:  20,
	}
}

// ConfigFromEnv builds the queue config from environment variables with sensible defaults.
// This is the recommended way to configure the queue manager in production.
func ConfigFromEnv() QueueConfig {
	cfg := DefaultQueueConfig()

	if v := os.Getenv("SCAN_QUEUE_NAME"); v != "" {
		cfg.QueueName = v
	}
	if v := os.Getenv("SCAN_PROCESSING_NAME"); v != "" {
		cfg.ProcessingName = v
	}
	if v := os.Getenv("SCAN_MAX_CONCURRENT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.MaxConcurrent = n
		}
	}
	if v := os.Getenv("SCAN_MAX_QUEUE_CAPACITY"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			cfg.MaxQueueCapacity = n
		}
	}

	return cfg
}

// ScanQueue provides Redis-backed job queue functionality
type ScanQueue struct {
	client *redis.Client
	config QueueConfig
}

// NewScanQueue creates a new scan queue
func NewScanQueue(client *redis.Client, config QueueConfig) *ScanQueue {
	return &ScanQueue{
		client: client,
		config: config,
	}
}

// Config returns the queue configuration (for exposing config via status endpoints)
func (q *ScanQueue) Config() QueueConfig {
	return q.config
}

// Enqueue adds a job to the queue
func (q *ScanQueue) Enqueue(ctx context.Context, payload *ScanJobPayload) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Add to queue (LPUSH for stack-like behavior, RPUSH for FIFO)
	if err := q.client.RPush(ctx, q.config.QueueName, data).Err(); err != nil {
		return fmt.Errorf("failed to enqueue: %w", err)
	}

	// Track job position for status queries
	if err := q.client.HSet(ctx, "scan:queue:positions", payload.JobID, time.Now().Unix()).Err(); err != nil {
		return fmt.Errorf("failed to track position: %w", err)
	}

	return nil
}

// IsQueueFull checks if the queue has reached its capacity limit.
// Returns (isFull, queuedCount, processingCount, error).
func (q *ScanQueue) IsQueueFull(ctx context.Context) (bool, int64, int64, error) {
	if q.config.MaxQueueCapacity <= 0 {
		return false, 0, 0, nil // no limit
	}

	queuedLen, err := q.GetQueueLength(ctx)
	if err != nil {
		return false, 0, 0, err
	}

	processingLen, err := q.GetProcessingLength(ctx)
	if err != nil {
		return false, 0, 0, err
	}

	totalActive := queuedLen + processingLen
	return totalActive >= int64(q.config.MaxQueueCapacity), queuedLen, processingLen, nil
}

// EnqueueWithCapacityCheck checks capacity first, then enqueues if space is available.
// Returns ErrQueueFull if the queue is at capacity.
var ErrQueueFull = fmt.Errorf("queue is full")

func (q *ScanQueue) EnqueueWithCapacityCheck(ctx context.Context, payload *ScanJobPayload) error {
	isFull, queuedLen, processingLen, err := q.IsQueueFull(ctx)
	if err != nil {
		return fmt.Errorf("failed to check queue capacity: %w", err)
	}
	if isFull {
		return fmt.Errorf("%w: %d active jobs (max %d)", ErrQueueFull, queuedLen+processingLen, q.config.MaxQueueCapacity)
	}

	return q.Enqueue(ctx, payload)
}

// Dequeue gets the next job from the queue with visibility timeout
// Returns the payload and a receipt for completion/death
func (q *ScanQueue) Dequeue(ctx context.Context) (*ScanJobPayload, string, error) {
	// BRPOPLPUSH atomically pops from queue and pushes to processing
	result, err := q.client.BRPopLPush(ctx, q.config.QueueName, q.config.ProcessingName, 1*time.Second).Result()
	if err == redis.Nil {
		return nil, "", nil // Queue empty
	}
	if err != nil {
		return nil, "", fmt.Errorf("failed to dequeue: %w", err)
	}

	var payload ScanJobPayload
	if err := json.Unmarshal([]byte(result), &payload); err != nil {
		return nil, "", fmt.Errorf("failed to unmarshal payload: %w", err)
	}

	// Create receipt (job_id + timestamp)
	receipt := fmt.Sprintf("%s:%d", payload.JobID, time.Now().UnixNano())

	// Store receipt mapping for visibility timeout management
	receiptKey := fmt.Sprintf("scan:receipt:%s", receipt)
	if err := q.client.HSet(ctx, receiptKey, "job_id", payload.JobID, "started_at", time.Now().Unix()).Err(); err != nil {
		return nil, "", fmt.Errorf("failed to store receipt: %w", err)
	}
	q.client.Expire(ctx, receiptKey, q.config.VisibilityTimeout)

	return &payload, receipt, nil
}

// Complete marks a job as successfully processed
func (q *ScanQueue) Complete(ctx context.Context, receipt string) error {
	// Remove from processing queue
	var jobID string
	cursor := uint64(0)
	for {
		keys, nextCursor, err := q.client.HScan(ctx, "scan:receipt:"+receipt, cursor, "*", 10).Result()
		if err != nil {
			return fmt.Errorf("failed to scan receipt: %w", err)
		}

		for i := 0; i < len(keys); i += 2 {
			if keys[i] == "job_id" {
				jobID = keys[i+1]
				break
			}
		}

		if nextCursor == 0 {
			break
		}
		cursor = nextCursor
	}

	if jobID != "" {
		q.client.HDel(ctx, "scan:queue:positions", jobID)
	}

	// Delete receipt
	q.client.Del(ctx, "scan:receipt:"+receipt)

	return nil
}

// Requeue returns a failed job back to the main queue
func (q *ScanQueue) Requeue(ctx context.Context, receipt string) error {
	// Get job_id from receipt
	data, err := q.client.HGet(ctx, "scan:receipt:"+receipt, "job_id").Result()
	if err != nil {
		return fmt.Errorf("failed to get receipt: %w", err)
	}
	jobID := data

	// Find and move from processing back to queue
	// This requires scanning the processing queue
	items, err := q.client.LRange(ctx, q.config.ProcessingName, 0, -1).Result()
	if err != nil {
		return fmt.Errorf("failed to read processing queue: %w", err)
	}

	for _, item := range items {
		var payload ScanJobPayload
		if err := json.Unmarshal([]byte(item), &payload); err != nil {
			continue
		}
		if payload.JobID == jobID {
			// Remove from processing
			// LREM removes by value; we need to be careful here
			q.client.LRem(ctx, q.config.ProcessingName, 1, item)
			// Add back to main queue
			q.client.RPush(ctx, q.config.QueueName, item)
			break
		}
	}

	// Delete receipt
	q.client.Del(ctx, "scan:receipt:"+receipt)

	return nil
}

// GetQueueLength returns the number of jobs waiting in queue
func (q *ScanQueue) GetQueueLength(ctx context.Context) (int64, error) {
	return q.client.LLen(ctx, q.config.QueueName).Result()
}

// GetProcessingLength returns the number of jobs currently being processed
func (q *ScanQueue) GetProcessingLength(ctx context.Context) (int64, error) {
	return q.client.LLen(ctx, q.config.ProcessingName).Result()
}

// GetJobPosition returns the position of a job in the queue (0-indexed)
// Returns -1 if not found
func (q *ScanQueue) GetJobPosition(ctx context.Context, jobID string) (int64, error) {
	items, err := q.client.LRange(ctx, q.config.QueueName, 0, -1).Result()
	if err != nil {
		return -1, fmt.Errorf("failed to read queue: %w", err)
	}

	for i, item := range items {
		var payload ScanJobPayload
		if err := json.Unmarshal([]byte(item), &payload); err != nil {
			continue
		}
		if payload.JobID == jobID {
			return int64(i), nil
		}
	}

	// Check if it's being processed
	processingItems, err := q.client.LRange(ctx, q.config.ProcessingName, 0, -1).Result()
	if err != nil {
		return -1, fmt.Errorf("failed to read processing queue: %w", err)
	}

	for _, item := range processingItems {
		var payload ScanJobPayload
		if err := json.Unmarshal([]byte(item), &payload); err != nil {
			continue
		}
		if payload.JobID == jobID {
			return -2, nil // -2 means currently processing
		}
	}

	return -1, nil // Not in queue
}

// GetQueueStats returns comprehensive queue statistics
func (q *ScanQueue) GetQueueStats(ctx context.Context) (map[string]interface{}, error) {
	queueLen, err := q.GetQueueLength(ctx)
	if err != nil {
		return nil, err
	}

	processingLen, err := q.GetProcessingLength(ctx)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"queued":     queueLen,
		"processing": processingLen,
		"total":      queueLen + processingLen,
	}, nil
}

// GetQueueItems returns all items in the queue (for filtering/manipulation)
func (q *ScanQueue) GetQueueItems(ctx context.Context) ([]string, error) {
	return q.client.LRange(ctx, q.config.QueueName, 0, -1).Result()
}

// RebuildQueue rebuilds the queue with provided items
func (q *ScanQueue) RebuildQueue(ctx context.Context, items []string) error {
	// Clear existing queue
	q.client.Del(ctx, q.config.QueueName)

	// Add items back
	if len(items) > 0 {
		args := []interface{}{q.config.QueueName}
		for _, item := range items {
			args = append(args, item)
		}
		return q.client.RPush(ctx, q.config.QueueName, args...).Err()
	}
	return nil
}

// CheckVisibilityTimeout finds jobs whose visibility timeout has expired
// and returns them for requeue
func (q *ScanQueue) CheckVisibilityTimeout(ctx context.Context) ([]string, error) {
	expiredReceipts := []string{}

	// Scan all receipt keys
	iter := q.client.Scan(ctx, 0, "scan:receipt:*", 100).Iterator()
	for iter.Next(ctx) {
		receiptKey := iter.Val()

		// Check if key still exists (hasn't expired)
		ttl, err := q.client.TTL(ctx, receiptKey).Result()
		if err != nil {
			continue
		}

		if ttl == -2 { // Key doesn't exist
			continue
		}

		if ttl <= 0 { // Expired
			receipt := receiptKey[len("scan:receipt:"):]
			expiredReceipts = append(expiredReceipts, receipt)
		}
	}

	return expiredReceipts, iter.Err()
}
