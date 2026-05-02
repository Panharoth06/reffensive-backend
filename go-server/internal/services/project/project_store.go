/*
@author: @Panharoth06
@date: 2026-04-03
@description: A project store module for database conncetions
*/

package project

import (
	"go-server/internal/database"
	db "go-server/internal/database/sqlc"
	"github.com/jackc/pgx/v5/pgxpool"
	"sync"
)

type projectResultStore interface {
	GetDB() *pgxpool.Pool
	GetQueries() *db.Queries
}

type projectStoreAdapter struct {
	store *database.Store
}

func (a *projectStoreAdapter) GetDB() *pgxpool.Pool {
	return a.store.Pool
}

func (a *projectStoreAdapter) GetQueries() *db.Queries {
	return a.store.Queries
}

var (
	projectInitOnce sync.Once
	projectInitErr  error
	projectStore    *database.Store
)

// getProjectStore initialises the database conncetion once and reuturns it.
func getProjectStore() (*database.Store, error) {
	projectInitOnce.Do(func() {
		projectStore, projectInitErr = database.ConnectAndMigrate()
	})
	if projectInitErr != nil {
		return nil, projectInitErr
	}
	return projectStore, nil
}

// getProjectResultStore returns a projectStoreAdapter that wraps the singleton database.Store. 
func getProjectResultStore() (projectResultStore, error) {
	store, err := getProjectStore()
	if err != nil {
		return nil, err
	}
	return &projectStoreAdapter{store: store}, nil
}