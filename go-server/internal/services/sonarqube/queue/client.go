package queue

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/hibiken/asynq"
)

const defaultRedisAddr = "localhost:6379"

type Client struct {
	asynq *asynq.Client
}

func NewClient(redisAddr string) *Client {
	return &Client{asynq: asynq.NewClient(redisOpt(redisAddr))}
}

func (c *Client) Close() error {
	return c.asynq.Close()
}

func (c *Client) EnqueueScan(ctx context.Context, payload ScanTaskPayload) error {
	task, err := NewScanTask(payload)
	if err != nil {
		return err
	}
	_, err = c.asynq.EnqueueContext(
		ctx,
		task,
		asynq.Queue("sonarqube"),
		asynq.MaxRetry(3),
		asynq.Timeout(45*time.Minute),
	)
	if err != nil {
		return fmt.Errorf("enqueue sonarqube scan task: %w", err)
	}
	return nil
}

func redisOpt(redisAddr string) asynq.RedisClientOpt {
	redisAddr = strings.TrimSpace(redisAddr)
	if redisAddr == "" {
		redisAddr = defaultRedisAddr
	}
	if strings.HasPrefix(redisAddr, "redis://") {
		return asynq.RedisClientOpt{Addr: strings.TrimPrefix(redisAddr, "redis://")}
	}
	return asynq.RedisClientOpt{Addr: redisAddr}
}
