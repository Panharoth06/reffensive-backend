package logger

import (
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

func New(levelText string) zerolog.Logger {
	level := zerolog.InfoLevel
	if parsed, err := zerolog.ParseLevel(strings.TrimSpace(strings.ToLower(levelText))); err == nil {
		level = parsed
	}
	zerolog.SetGlobalLevel(level)
	zerolog.TimeFieldFormat = time.RFC3339
	return zerolog.New(os.Stdout).With().Timestamp().Logger()
}