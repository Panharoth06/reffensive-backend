/*
@author: @Panharoth06
@date: 2026-04-02
@description: A category store module for database connections
*/

package services

import (
	"go-server/internal/database"
	db "go-server/internal/database/sqlc"
	"sync"

	"github.com/jackc/pgx/v5/pgxpool"
)

// categoryResultStore is the interface the service uses to access the DB.
type categoryResultStore interface {
	GetDB() *pgxpool.Pool
	GetQueries() *db.Queries
}

// categoryStoreAdapter wraps database.Store and satisfies categoryResultStore.
//  A wrapper (adapter) that holds the actual database connection.
type categoryStoreAdapter struct {
	store *database.Store
}

// inject database conn
func (a *categoryStoreAdapter) GetDB() *pgxpool.Pool {
	return a.store.Pool
}

func (a *categoryStoreAdapter) GetQueries() *db.Queries {
	return a.store.Queries
}

// Singleton DB store shared across all category service instances.
var (
	catInitOnce sync.Once
	catInitErr  error
	catStore    *database.Store
)

// getCategoryStore initialises the database connection once and returns it.
func getCategoryStore() (*database.Store, error) {
	catInitOnce.Do(func() {
		catStore, catInitErr = database.ConnectAndMigrate()
	})
	if catInitErr != nil {
		return nil, catInitErr
	}
	return catStore, nil
}

// getCategoryResultStore returns a categoryStoreAdapter that wraps the singleton database.Store.
func getCategoryResultStore() (categoryResultStore, error) {
	store, err := getCategoryStore()
	if err != nil {
		return nil, err
	}
	return &categoryStoreAdapter{store: store}, nil
}
