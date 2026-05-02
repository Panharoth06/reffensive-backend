package queue

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const defaultProgressChannelPrefix = "sonarqube:scan:progress"

type ProgressEvent struct {
	ScanID       string    `json:"scan_id"`
	Type         string    `json:"type"`
	Status       string    `json:"status,omitempty"`
	Phase        string    `json:"phase,omitempty"`
	Progress     int32     `json:"progress,omitempty"`
	ErrorMessage string    `json:"error_message,omitempty"`
	PublishedAt  time.Time `json:"published_at"`
}

type ProgressPublisher struct {
	client        *redis.Client
	channelPrefix string
}

func NewProgressPublisher(redisAddr, channelPrefix string) *ProgressPublisher {
	redisAddr = strings.TrimSpace(redisAddr)
	if redisAddr == "" {
		redisAddr = defaultRedisAddr
	}
	if strings.HasPrefix(redisAddr, "redis://") {
		redisAddr = strings.TrimPrefix(redisAddr, "redis://")
	}
	channelPrefix = strings.TrimSpace(channelPrefix)
	if channelPrefix == "" {
		channelPrefix = defaultProgressChannelPrefix
	}
	return &ProgressPublisher{
		client:        redis.NewClient(&redis.Options{Addr: redisAddr}),
		channelPrefix: channelPrefix,
	}
}

func (p *ProgressPublisher) Close() error {
	return p.client.Close()
}

func (p *ProgressPublisher) Publish(ctx context.Context, event ProgressEvent) error {
	if event.PublishedAt.IsZero() {
		event.PublishedAt = time.Now().UTC()
	}
	body, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal sonarqube progress event: %w", err)
	}
	if err := p.client.Publish(ctx, p.Channel(event.ScanID), body).Err(); err != nil {
		return fmt.Errorf("publish sonarqube progress event: %w", err)
	}
	return nil
}

func (p *ProgressPublisher) Channel(scanID string) string {
	return fmt.Sprintf("%s:%s", p.channelPrefix, scanID)
}
