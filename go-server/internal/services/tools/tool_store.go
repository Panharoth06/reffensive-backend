package services

import (
	"context"
	"fmt"
	"go-server/internal/database"
	db "go-server/internal/database/sqlc"
	"sync"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// toolResultStore is the interface the service uses to access the DB.
type toolResultStore interface {
	GetDB() *pgxpool.Pool
	GetQueries() *db.Queries
}

// storeAdapter wraps database.Store and satisfies toolResultStore.
type storeAdapter struct {
	store *database.Store
}

func (a *storeAdapter) GetDB() *pgxpool.Pool {
	return a.store.Pool
}

func (a *storeAdapter) GetQueries() *db.Queries {
	return a.store.Queries
}

// Singleton DB store shared across all tool service instances.
var (
	dbInitOnce sync.Once
	dbInitErr  error
	dbStore    *database.Store
)

// Signleton initialization
// getStore initialises the database connection once and returns it.
func getStore() (*database.Store, error) {
	dbInitOnce.Do(func() {
		dbStore, dbInitErr = database.ConnectAndMigrate()
	})
	if dbInitErr != nil {
		return nil, fmt.Errorf("store initialization failed: %w", dbInitErr)
	}
	return dbStore, nil
}

// getOrCreateVersion looks up a version row by version_number.
// If none exists it inserts a new one and returns its UUID.
// Note: versions.version_number has no UNIQUE constraint, so this uses a
// simple SELECT-then-INSERT strategy (acceptable for low-concurrency admin use).
func getOrCreateVersion(ctx context.Context, pool *pgxpool.Pool, versionNumber string) (uuid.UUID, error) {
	// 1. Try to find an existing version with this number.
	var id uuid.UUID
	err := pool.QueryRow(ctx,
		`SELECT version_id FROM versions WHERE version_number = $1 LIMIT 1`,
		versionNumber,
	).Scan(&id)

	if err == nil {
		return id, nil // found
	}

	// 2. Not found — insert a new one.
	err = pool.QueryRow(ctx,
		`INSERT INTO versions (version_number) VALUES ($1) RETURNING version_id`,
		versionNumber,
	).Scan(&id)
	if err != nil {
		return uuid.Nil, fmt.Errorf("create version %q: %w", versionNumber, err)
	}
	return id, nil
}

// getCategoryByName resolves a category name to its UUID.
// Categories must be pre-created; unlike versions, they are not auto-created.
func getCategoryByName(ctx context.Context, pool *pgxpool.Pool, name string) (pgtype.UUID, error) {
	var id pgtype.UUID
	err := pool.QueryRow(ctx,
		`SELECT category_id FROM tool_categories WHERE name = $1 LIMIT 1`,
		name,
	).Scan(&id)
	if err != nil {
		return pgtype.UUID{}, fmt.Errorf("category %q not found: %w", name, err)
	}
	return id, nil
}
