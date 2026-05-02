package main

import (
	"context"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go-server/internal/database"
	appserver "go-server/internal/server"
	appconfig "go-server/pkg/config"
	applogger "go-server/pkg/logger"
	redisutil "go-server/redis"
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

	store, err := database.ConnectAndMigrate()
	if err != nil {
		log.Fatal().Err(err).Msg("failed to initialize database")
	}
	defer store.Pool.Close()

	queueCfg := redisutil.ConfigFromEnv()
	if err := redisutil.InitManager(cfg.RedisAddr, queueCfg); err != nil {
		log.Fatal().Err(err).Msg("failed to initialize queue manager")
	}

	lis, err := net.Listen("tcp", ":"+cfg.GRPCPort)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to listen")
	}

	grpcServer, err := appserver.NewGRPCServer(store)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to build gRPC server")
	}

	go func() {
		log.Info().Str("addr", lis.Addr().String()).Msg("gRPC server listening")
		if serveErr := grpcServer.Serve(lis); serveErr != nil {
			log.Fatal().Err(serveErr).Msg("gRPC server stopped")
		}
	}()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	<-signals

	done := make(chan struct{})
	go func() {
		defer close(done)
		grpcServer.GracefulStop()
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		grpcServer.Stop()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = lis.Close()
	<-ctx.Done()
}
