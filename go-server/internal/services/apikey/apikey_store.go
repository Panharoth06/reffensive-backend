package apikey

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	db "go-server/internal/database/sqlc"
)

// APIKeyStore handles database operations for API keys
type APIKeyStore struct {
	queries *db.Queries
}

// NewAPIKeyStore creates a new API key store
func NewAPIKeyStore(queries *db.Queries) *APIKeyStore {
	return &APIKeyStore{queries: queries}
}

// CreateAPIKey inserts a new API key into the database
func (s *APIKeyStore) CreateAPIKey(ctx context.Context, params db.CreateAPIKeyParams) (db.ApiKey, error) {
	key, err := s.queries.CreateAPIKey(ctx, params)
	return key, err
}

// GetAPIKeyByID retrieves an API key by its ID
func (s *APIKeyStore) GetAPIKeyByID(ctx context.Context, keyID uuid.UUID) (db.ApiKey, error) {
	key, err := s.queries.GetAPIKeyByID(ctx, keyID)
	if err != nil {
		return db.ApiKey{}, status.Error(codes.NotFound, "API key not found")
	}
	return key, nil
}

// GetAPIKeyByPrefix retrieves an API key by its prefix
func (s *APIKeyStore) GetAPIKeyByPrefix(ctx context.Context, prefix string) (db.ApiKey, error) {
	key, err := s.queries.GetAPIKeyByPrefix(ctx, pgtype.Text{String: prefix, Valid: true})
	if err != nil {
		return db.ApiKey{}, status.Error(codes.NotFound, "API key prefix not found")
	}
	return key, nil
}

// ListProjectAPIKeys retrieves all API keys for a project
func (s *APIKeyStore) ListProjectAPIKeys(ctx context.Context, projectID uuid.UUID) ([]db.ApiKey, error) {
	keys, err := s.queries.ListAPIKeysByProject(ctx, projectID)
	if err != nil {
		return nil, status.Error(codes.Internal, "database error")
	}
	return keys, nil
}

// ListActiveAPIKeysByProject retrieves only active API keys for a project
func (s *APIKeyStore) ListActiveAPIKeysByProject(ctx context.Context, projectID uuid.UUID) ([]db.ApiKey, error) {
	keys, err := s.queries.ListActiveAPIKeysByProject(ctx, projectID)
	if err != nil {
		return nil, status.Error(codes.Internal, "database error")
	}
	return keys, nil
}

// RevokeAPIKey marks an API key as revoked
func (s *APIKeyStore) RevokeAPIKey(ctx context.Context, keyID uuid.UUID) (db.ApiKey, error) {
	key, err := s.queries.RevokeAPIKey(ctx, keyID)
	if err != nil {
		return db.ApiKey{}, status.Error(codes.Internal, "database error")
	}
	return key, nil
}

// DeleteAPIKey deletes an API key
func (s *APIKeyStore) DeleteAPIKey(ctx context.Context, keyID uuid.UUID) error {
	return s.queries.DeleteAPIKey(ctx, keyID)
}
