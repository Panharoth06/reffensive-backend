package redis

import (
	"context"
	"fmt"
	"log"
	"time"
)

// runWorkers starts all queue worker goroutines and the visibility timeout checker.
// Each worker independently pulls jobs from the queue and dispatches them
// to the registered handler based on payload.ServiceName.
func (m *Manager) runWorkers() {
	numWorkers := m.config.MaxConcurrent
	if numWorkers <= 0 {
		numWorkers = 1
	}

	log.Printf("[queue] starting %d workers (maxConcurrent=%d, maxQueueCapacity=%d)",
		numWorkers, m.config.MaxConcurrent, m.config.MaxQueueCapacity)

	// Start visibility timeout checker (single instance)
	go m.runVisibilityTimeoutChecker()

	// Start workers
	for i := 0; i < numWorkers; i++ {
		go m.workerLoop(i)
	}
}

// workerLoop is the main loop for a single queue worker goroutine.
func (m *Manager) workerLoop(workerID int) {
	for {
		select {
		case <-m.stopCh:
			return
		default:
		}

		payload, receipt, err := m.queue.Dequeue(context.Background())
		if err != nil {
			log.Printf("[queue-worker-%d] dequeue error: %v", workerID, err)
			time.Sleep(1 * time.Second)
			continue
		}

		if payload == nil {
			// Queue empty, wait a bit
			time.Sleep(500 * time.Millisecond)
			continue
		}

		// Dispatch to the registered handler for this service
		go m.dispatchJob(payload, receipt, workerID)
	}
}

// dispatchJob looks up the handler for payload.ServiceName and calls ProcessJob.
func (m *Manager) dispatchJob(payload *ScanJobPayload, receipt string, workerID int) {
	serviceName := payload.ServiceName
	if serviceName == "" {
		// Backward compatibility: if no service name, default to "advanced"
		serviceName = "advanced"
	}

	m.mu.RLock()
	reg, ok := m.handlers[serviceName]
	m.mu.RUnlock()

	if !ok {
		log.Printf("[queue-worker-%d] no handler registered for service %q — marking job %s complete without processing",
			workerID, serviceName, payload.JobID)
		m.queue.Complete(context.Background(), receipt)
		return
	}

	logPrefix := fmt.Sprintf("%s-%d", reg.logPrefix, workerID)
	log.Printf("[%s] dispatching job %s to service %q", logPrefix, payload.JobID, serviceName)

	reg.handler.ProcessJob(context.Background(), payload, receipt, workerID)
}

// runVisibilityTimeoutChecker periodically requeues jobs whose visibility timeout has expired.
func (m *Manager) runVisibilityTimeoutChecker() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		select {
		case <-m.stopCh:
			return
		default:
		}

		expired, err := m.queue.CheckVisibilityTimeout(context.Background())
		if err != nil {
			log.Printf("[queue-visibility] check error: %v", err)
			continue
		}

		for _, receipt := range expired {
			log.Printf("[queue-visibility] requeueing expired receipt: %s", receipt)
			if err := m.queue.Requeue(context.Background(), receipt); err != nil {
				log.Printf("[queue-visibility] requeue error: %v", err)
			}
		}
	}
}
