package database

import (
	"bufio"
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	dbsqlc "go-server/internal/database/sqlc"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

type Store struct {
	Pool    *pgxpool.Pool
	Queries *dbsqlc.Queries
}

var (
	initOnce  sync.Once
	initStore *Store
	initErr   error
)

func ConnectAndMigrate() (*Store, error) {
	initOnce.Do(func() {
		initStore, initErr = connectAndMigrate()
	})
	return initStore, initErr
}

func connectAndMigrate() (*Store, error) {
	loadDotEnvIfPresent()

	dsn := postgresDSNFromEnv()
	if dsn == "" {
		return nil, errors.New("database connection is missing: set DATABASE_URL or DB_HOST/DB_PORT/DB_USER/DB_PASSWORD/DB_NAME")
	}

	// 1. Run migrations using standard database/sql
	if err := runMigrations(dsn); err != nil {
		return nil, fmt.Errorf("run migrations: %w", err)
	}

	// 2. Parse config for the native pgx pool
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse pgx config: %w", err)
	}

	// Translate old sql.DB settings to pgxpool equivalents
	config.MinConns = 5
	config.MaxConns = 20
	config.MaxConnLifetime = 30 * time.Minute

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 3. Connect the high-performance pool
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("connect pgxpool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}

	return &Store{
		Pool:    pool,
		Queries: dbsqlc.New(pool), // sqlc natively accepts *pgxpool.Pool
	}, nil
}

func runMigrations(dsn string) error {
	// Open a temporary standard connection strictly for Goose
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return fmt.Errorf("open migration db: %w", err)
	}
	defer db.Close() // Ensure it closes immediately after migrations

	goose.SetBaseFS(migrationsFS)
	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("set goose dialect: %w", err)
	}
	if err := goose.Up(db, "migrations"); err != nil {
		return fmt.Errorf("apply goose migrations: %w", err)
	}
	return nil
}

func postgresDSNFromEnv() string {
	if dsn := os.Getenv("DATABASE_URL"); dsn != "" {
		return dsn
	}

	host := os.Getenv("DB_HOST")
	port := envOrDefault("DB_PORT", "5432")
	user := os.Getenv("DB_USER")
	password := os.Getenv("DB_PASSWORD")
	name := os.Getenv("DB_NAME")
	sslMode := envOrDefault("DB_SSLMODE", "disable")
	timeZone := envOrDefault("DB_TIMEZONE", "UTC")

	if host == "" || user == "" || name == "" {
		return ""
	}

	return fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=%s TimeZone=%s",
		host,
		port,
		user,
		password,
		name,
		sslMode,
		timeZone,
	)
}

func envOrDefault(key string, defaultValue string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultValue
}

func loadDotEnvIfPresent() {
	paths := []string{
		".env",
		filepath.Join("..", ".env"),
	}

	for _, path := range paths {
		if err := loadEnvFile(path); err == nil {
			return
		}
	}
}

func loadEnvFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		value = strings.Trim(value, `"'`)
		if key == "" {
			continue
		}
		if _, exists := os.LookupEnv(key); exists {
			continue
		}
		_ = os.Setenv(key, value)
	}

	return scanner.Err()
}
