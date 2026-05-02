package redis

import (
	"context"
	"net"
	"strings"

	"github.com/redis/go-redis/v9"
)

func NewClient(addr string) *redis.Client {
	addr = normalizeRedisAddr(addr)

	return redis.NewClient(&redis.Options{
		Addr: addr,
	})
}

func PublishResult(ctx context.Context, client *redis.Client, channel, message string) error {
	// v9 requires context as first argument
	return client.Publish(ctx, channel, message).Err()
}

func normalizeRedisAddr(addr string) string {
	a := strings.TrimSpace(addr)
	if a == "" {
		return "127.0.0.1:6379"
	}

	host, port, err := net.SplitHostPort(a)
	if err != nil {
		// Keep current behavior for uncommon address formats.
		return a
	}

	if strings.EqualFold(host, "localhost") {
		host = "127.0.0.1"
	}

	return net.JoinHostPort(host, port)
}
