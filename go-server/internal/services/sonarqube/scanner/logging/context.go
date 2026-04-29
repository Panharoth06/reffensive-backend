package logging

import (
	"context"
	"strings"
)

const (
	LevelInfo  = "INFO"
	LevelWarn  = "WARN"
	LevelError = "ERROR"
)

type Sink interface {
	Record(ctx context.Context, level, line string)
}

type sinkKey struct{}
type phaseKey struct{}

func WithSink(ctx context.Context, sink Sink) context.Context {
	return context.WithValue(ctx, sinkKey{}, sink)
}

func WithPhase(ctx context.Context, phase string) context.Context {
	return context.WithValue(ctx, phaseKey{}, strings.TrimSpace(phase))
}

func Phase(ctx context.Context) string {
	phase, _ := ctx.Value(phaseKey{}).(string)
	return strings.TrimSpace(phase)
}

func Record(ctx context.Context, level, line string) {
	sink, _ := ctx.Value(sinkKey{}).(Sink)
	if sink == nil {
		return
	}
	sink.Record(ctx, normalizeLevel(level), line)
}

func Info(ctx context.Context, line string) {
	Record(ctx, LevelInfo, line)
}

func Warn(ctx context.Context, line string) {
	Record(ctx, LevelWarn, line)
}

func Error(ctx context.Context, line string) {
	Record(ctx, LevelError, line)
}

func normalizeLevel(level string) string {
	switch strings.ToUpper(strings.TrimSpace(level)) {
	case LevelWarn:
		return LevelWarn
	case LevelError:
		return LevelError
	default:
		return LevelInfo
	}
}
