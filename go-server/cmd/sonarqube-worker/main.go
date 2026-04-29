package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/hibiken/asynq"

	"go-server/internal/database"
	sonarqubequeue "go-server/internal/services/sonarqube/queue"
	sonarqubeservice "go-server/internal/services/sonarqube/service"
	appconfig "go-server/pkg/config"
	applogger "go-server/pkg/logger"
)

func main() {
	cfg, err := appconfig.Load()
	if err != nil {
		panic(err)
	}
	log := applogger.New(cfg.LogLevel)

	if cfg.DBDSN != "" {
		_ = os.Setenv("DATABASE_URL", cfg.DBDSN)
	}
	if cfg.SonarQubeBaseURL != "" {
		_ = os.Setenv("SONARQUBE_HOST", cfg.SonarQubeBaseURL)
	}
	if cfg.SonarQubeToken != "" {
		_ = os.Setenv("SONARQUBE_TOKEN", cfg.SonarQubeToken)
	}
	_ = os.Setenv("REDIS_ADDR", cfg.RedisAddr)

	store, err := database.ConnectAndMigrate()
	if err != nil {
		log.Fatal().Err(err).Msg("failed to initialize database")
	}
	defer store.Pool.Close()

	scanner, err := sonarqubeservice.NewScannerServer(store.Queries)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to initialize sonarqube scanner")
	}

	worker := sonarqubequeue.NewWorkerServer(cfg.RedisAddr, envInt("SONARQUBE_WORKER_CONCURRENCY", 2))
	mux := asynq.NewServeMux()
	mux.HandleFunc(sonarqubequeue.TypeRunScan, func(ctx context.Context, task *asynq.Task) error {
		payload, err := sonarqubequeue.ParseScanTask(task)
		if err != nil {
			return err
		}
		log.Info().Str("scan_id", payload.ScanID).Msg("processing sonarqube scan")
		if err := scanner.RunQueuedScan(ctx, payload); err != nil {
			return fmt.Errorf("run sonarqube scan %s: %w", payload.ScanID, err)
		}
		return nil
	})

	errCh := make(chan error, 1)
	go func() {
		log.Info().Str("redis_addr", cfg.RedisAddr).Msg("sonarqube worker started")
		errCh <- worker.Run(mux)
	}()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-signals:
		log.Info().Str("signal", sig.String()).Msg("stopping sonarqube worker")
		worker.Shutdown()
	case err := <-errCh:
		if err != nil {
			log.Fatal().Err(err).Msg("sonarqube worker stopped")
		}
	}
}

func envInt(key string, fallback int) int {
	value, err := strconv.Atoi(os.Getenv(key))
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}
