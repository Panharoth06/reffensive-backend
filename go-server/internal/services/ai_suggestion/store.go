package aisuggestion

import (
	"go-server/internal/database"
	db "go-server/internal/database/sqlc"
	"sync"

	"github.com/jackc/pgx/v5/pgxpool"
)

type suggestionResultStore interface {
	GetDB() *pgxpool.Pool
	GetQueries() *db.Queries
}

type suggestionStoreAdapter struct {
	store *database.Store
}

func (a *suggestionStoreAdapter) GetDB() *pgxpool.Pool {
	return a.store.Pool
}

func (a *suggestionStoreAdapter) GetQueries() *db.Queries {
	return a.store.Queries
}

var (
	suggestionInitOnce sync.Once
	suggestionInitErr  error
	suggestionStore    *database.Store
)

func getSuggestionStore() (*database.Store, error) {
	suggestionInitOnce.Do(func() {
		suggestionStore, suggestionInitErr = database.ConnectAndMigrate()
	})
	if suggestionInitErr != nil {
		return nil, suggestionInitErr
	}
	return suggestionStore, nil
}

func getSuggestionResultStore() (suggestionResultStore, error) {
	store, err := getSuggestionStore()
	if err != nil {
		return nil, err
	}
	return &suggestionStoreAdapter{store: store}, nil
}
