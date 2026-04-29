package redis

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// ServiceHandler is the interface that any scan service (advanced, basic, medium)
// must implement to process jobs dequeued from the shared queue.
type ServiceHandler interface {
	// ProcessJob is called by a worker when a job for this service is dequeued.
	// The service is responsible for marking the job complete via receipt when done.
	ProcessJob(ctx context.Context, payload *ScanJobPayload, receipt string, workerID int)
}

// serviceRegistration holds a handler and its associated logger prefix.
type serviceRegistration struct {
	handler   ServiceHandler
	logPrefix string // e.g. "advanced-scan-worker", "basic-scan-worker"
}

// Manager is the global shared queue manager.
// It owns the Redis client, the queue instance, and the worker goroutines.
// Any scan service can enqueue jobs and register a handler.
type Manager struct {
	redisClient *redis.Client
	queue       *ScanQueue
	config      QueueConfig

	mu         sync.RWMutex
	handlers   map[string]*serviceRegistration // serviceName -> registration
	started    bool
	stopCh     chan struct{}
}

var (
	globalManager *Manager
	once          sync.Once
)

// GetManager returns the global queue manager singleton.
// Panics if InitManager has not been called yet.
func GetManager() *Manager {
	if globalManager == nil {
		panic("queue manager not initialized — call queue.InitManager() first")
	}
	return globalManager
}

// InitManager creates the global queue manager, connects to Redis, and starts workers.
// Must be called exactly once (typically from main.go).
func InitManager(redisAddr string, config QueueConfig) error {
	var initErr error
	once.Do(func() {
		client := NewClient(redisAddr)
		pingCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := client.Ping(pingCtx).Err(); err != nil {
			initErr = fmt.Errorf("redis unavailable at %s: %w", redisAddr, err)
			return
		}

		q := NewScanQueue(client, config)

		globalManager = &Manager{
			redisClient: client,
			queue:       q,
			config:      config,
			handlers:    make(map[string]*serviceRegistration),
			stopCh:      make(chan struct{}),
		}

		// Start workers
		go globalManager.runWorkers()
	})
	return initErr
}

// RegisterHandler registers a service handler for a given service name.
// Jobs enqueued with payload.ServiceName = serviceName will be routed to this handler.
// logPrefix is used in worker log messages (e.g. "advanced-scan-worker-0").
func (m *Manager) RegisterHandler(serviceName string, handler ServiceHandler, logPrefix string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.handlers[serviceName] = &serviceRegistration{
		handler:   handler,
		logPrefix: logPrefix,
	}
}

// Enqueue adds a job to the shared queue.
// The payload's ServiceName field determines which registered handler will process it.
func (m *Manager) Enqueue(ctx context.Context, payload *ScanJobPayload) error {
	return m.queue.Enqueue(ctx, payload)
}

// EnqueueWithCapacityCheck checks capacity first, then enqueues if space is available.
func (m *Manager) EnqueueWithCapacityCheck(ctx context.Context, payload *ScanJobPayload) error {
	return m.queue.EnqueueWithCapacityCheck(ctx, payload)
}

// IsQueueFull checks if the queue has reached its capacity limit.
func (m *Manager) IsQueueFull(ctx context.Context) (bool, int64, int64, error) {
	return m.queue.IsQueueFull(ctx)
}

// Complete marks a job as successfully processed (deletes receipt).
func (m *Manager) Complete(ctx context.Context, receipt string) error {
	return m.queue.Complete(ctx, receipt)
}

// Requeue returns a failed job back to the main queue.
func (m *Manager) Requeue(ctx context.Context, receipt string) error {
	return m.queue.Requeue(ctx, receipt)
}

// GetQueueStats returns {"queued": N, "processing": N, "total": N}
func (m *Manager) GetQueueStats(ctx context.Context) (map[string]interface{}, error) {
	return m.queue.GetQueueStats(ctx)
}

// GetJobPosition returns the position of a job in the queue.
// Returns -1 if not found, -2 if processing.
func (m *Manager) GetJobPosition(ctx context.Context, jobID string) (int64, error) {
	return m.queue.GetJobPosition(ctx, jobID)
}

// GetQueueItems returns all items in the queue.
func (m *Manager) GetQueueItems(ctx context.Context) ([]string, error) {
	return m.queue.GetQueueItems(ctx)
}

// RebuildQueue rebuilds the queue with the provided items.
func (m *Manager) RebuildQueue(ctx context.Context, items []string) error {
	return m.queue.RebuildQueue(ctx, items)
}

// Config returns the queue configuration.
func (m *Manager) Config() QueueConfig {
	return m.config
}

// Queue returns the underlying ScanQueue for services that need direct access.
func (m *Manager) Queue() *ScanQueue {
	return m.queue
}
