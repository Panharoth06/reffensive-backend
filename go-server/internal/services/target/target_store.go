/*
@description: Target store module for database connections (same singleton pattern as project_store.go)
*/

package target

import (
	"go-server/internal/database"
	db "go-server/internal/database/sqlc"
	"sync"

	"github.com/jackc/pgx/v5/pgxpool"
)

type targetResultStore interface {
	GetDB() *pgxpool.Pool
	GetQueries() *db.Queries
}

type targetStoreAdapter struct {
	store *database.Store
}

func (a *targetStoreAdapter) GetDB() *pgxpool.Pool {
	return a.store.Pool
}

func (a *targetStoreAdapter) GetQueries() *db.Queries {
	return a.store.Queries
}

var (
	targetInitOnce sync.Once
	targetInitErr  error
	targetStore    *database.Store
)

// getTargetStore initialises the database connection once and returns it.
func getTargetStore() (*database.Store, error) {
	targetInitOnce.Do(func() {
		targetStore, targetInitErr = database.ConnectAndMigrate()
	})
	if targetInitErr != nil {
		return nil, targetInitErr
	}
	return targetStore, nil
}

// getTargetResultStore returns a targetStoreAdapter wrapping the singleton database.Store.
func getTargetResultStore() (targetResultStore, error) {
	store, err := getTargetStore()
	if err != nil {
		return nil, err
	}
	return &targetStoreAdapter{store: store}, nil
}
