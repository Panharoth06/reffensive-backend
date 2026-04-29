package apikey

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	apikeygenerated "go-server/gen/apikey"
	db "go-server/internal/database/sqlc"
	"go-server/internal/interceptor"
)

type APIKeyServer struct {
	apikeygenerated.UnimplementedAPIKeyServiceServer
	queries *db.Queries
}

func NewAPIKeyServer(queries *db.Queries) *APIKeyServer {
	return &APIKeyServer{queries: queries}
}

type projectRequest struct {
}

func (s *APIKeyServer) requireOwnedProject(ctx context.Context, projectID uuid.UUID) (db.Project, error) {
	userID, err := interceptor.RequireUserID(ctx)
	if err != nil {
		return db.Project{}, err
	}

	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return db.Project{}, status.Error(codes.InvalidArgument, "user_id must be a valid UUID")
	}

	project, err := s.queries.GetProjectByID(ctx, db.GetProjectByIDParams{
		ProjectID: projectID,
		UserID:    userUUID,
	})
	if err != nil {
		return db.Project{}, status.Error(codes.NotFound, "project not found")
	}
	return project, nil
}

func (s *APIKeyServer) requireOwnedAPIKey(ctx context.Context, keyID uuid.UUID) (db.ApiKey, error) {
	apiKey, err := s.queries.GetAPIKeyByID(ctx, keyID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return db.ApiKey{}, status.Error(codes.NotFound, "api key not found")
		}
		return db.ApiKey{}, status.Errorf(codes.Internal, "failed to load api key: %v", err)
	}
	if _, err := s.requireOwnedProject(ctx, apiKey.ProjectID); err != nil {
		return db.ApiKey{}, err
	}
	return apiKey, nil
}

func (s *APIKeyServer) CreateAPIKey(ctx context.Context, req *apikeygenerated.CreateAPIKeyRequest) (*apikeygenerated.CreateAPIKeyResponse, error) {
	if req.ProjectId == "" || req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "missing required fields")
	}

	projectID, err := uuid.Parse(req.ProjectId)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "project_id must be a valid UUID")
	}

	project, err := s.requireOwnedProject(ctx, projectID)
	if err != nil {
		return nil, err
	}

	var scopes []string
	if req.ScopesJson != "" {
		if err := json.Unmarshal([]byte(req.ScopesJson), &scopes); err != nil {
			return nil, status.Error(codes.InvalidArgument, "scopes_json must be a JSON array of strings")
		}
	}

	prefix := "auto_" + randomString(11)
	secret := randomString(32)
	key := prefix + "." + secret

	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to generate key hash")
	}

	apiKey, err := s.queries.CreateAPIKey(ctx, db.CreateAPIKeyParams{
		ProjectID:    projectID,
		UserID:       project.UserID,
		Name:         pgtype.Text{String: req.Name, Valid: true},
		Prefix:       pgtype.Text{String: prefix, Valid: true},
		Description:  pgtype.Text{String: req.Description, Valid: req.Description != ""},
		HashedSecret: string(hash),
		Scopes:       scopes,
		IsActive:     pgtype.Bool{Bool: true, Valid: true},
		ExpiredAt:    pgtype.Timestamptz{Valid: false},
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create api key: %v", err)
	}

	resp := &apikeygenerated.CreateAPIKeyResponse{
		KeyId:    apiKey.KeyID.String(),
		PlainKey: key,
		Prefix:   prefix,
		Name:     req.Name,
	}
	if req.Description != "" {
		resp.Description = req.Description
	}
	if apiKey.CreatedAt.Valid {
		resp.CreatedAt = timestamppb.New(apiKey.CreatedAt.Time)
	}
	return resp, nil
}

func (s *APIKeyServer) ValidateAPIKey(ctx context.Context, req *apikeygenerated.ValidateAPIKeyRequest) (*apikeygenerated.ValidateAPIKeyResponse, error) {
	if req.Key == "" {
		return &apikeygenerated.ValidateAPIKeyResponse{
			Valid:  false,
			Reason: "missing key",
		}, nil
	}

	parts := strings.SplitN(req.Key, ".", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return &apikeygenerated.ValidateAPIKeyResponse{
			Valid:  false,
			Reason: "invalid key format",
		}, nil
	}

	prefix := parts[0]
	secret := parts[1]

	apiKey, err := s.queries.GetAPIKeyByPrefix(ctx, pgtype.Text{String: prefix, Valid: true})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return &apikeygenerated.ValidateAPIKeyResponse{
				Valid:  false,
				Reason: "key not found",
			}, nil
		}
		return nil, status.Errorf(codes.Internal, "failed to load api key: %v", err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(apiKey.HashedSecret), []byte(secret)); err != nil {
		return &apikeygenerated.ValidateAPIKeyResponse{
			Valid:  false,
			Reason: "invalid key",
		}, nil
	}

	if !apiKey.IsActive.Valid || !apiKey.IsActive.Bool {
		return &apikeygenerated.ValidateAPIKeyResponse{
			Valid:      false,
			ProjectId:  apiKey.ProjectID.String(),
			UserId:     apiKey.UserID.String(),
			ScopesJson: mustScopesJSON(apiKey.Scopes),
			Reason:     "key is not active",
			KeyId:      apiKey.KeyID.String(),
		}, nil
	}

	if apiKey.RevokedAt.Valid {
		return &apikeygenerated.ValidateAPIKeyResponse{
			Valid:      false,
			ProjectId:  apiKey.ProjectID.String(),
			UserId:     apiKey.UserID.String(),
			ScopesJson: mustScopesJSON(apiKey.Scopes),
			Reason:     "key is revoked",
			KeyId:      apiKey.KeyID.String(),
		}, nil
	}

	if apiKey.ExpiredAt.Valid && apiKey.ExpiredAt.Time.Before(time.Now().UTC()) {
		return &apikeygenerated.ValidateAPIKeyResponse{
			Valid:      false,
			ProjectId:  apiKey.ProjectID.String(),
			UserId:     apiKey.UserID.String(),
			ScopesJson: mustScopesJSON(apiKey.Scopes),
			Reason:     "key is expired",
			KeyId:      apiKey.KeyID.String(),
		}, nil
	}

	if strings.TrimSpace(req.Action) != "" && !scopeAllows(apiKey.Scopes, req.Action) {
		return &apikeygenerated.ValidateAPIKeyResponse{
			Valid:      false,
			ProjectId:  apiKey.ProjectID.String(),
			UserId:     apiKey.UserID.String(),
			ScopesJson: mustScopesJSON(apiKey.Scopes),
			Reason:     "scope not allowed",
			KeyId:      apiKey.KeyID.String(),
		}, nil
	}

	return &apikeygenerated.ValidateAPIKeyResponse{
		Valid:      true,
		ProjectId:  apiKey.ProjectID.String(),
		UserId:     apiKey.UserID.String(),
		ScopesJson: mustScopesJSON(apiKey.Scopes),
		KeyId:      apiKey.KeyID.String(),
	}, nil
}

func (s *APIKeyServer) RevokeAPIKey(ctx context.Context, req *apikeygenerated.RevokeAPIKeyRequest) (*apikeygenerated.RevokeAPIKeyResponse, error) {
	keyID, err := uuid.Parse(req.KeyId)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "key_id must be a valid UUID")
	}

	if _, err := s.requireOwnedAPIKey(ctx, keyID); err != nil {
		return nil, err
	}

	_, err = s.queries.RevokeAPIKey(ctx, keyID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, status.Error(codes.NotFound, "api key not found")
		}
		return nil, status.Errorf(codes.Internal, "failed to revoke api key: %v", err)
	}

	return &apikeygenerated.RevokeAPIKeyResponse{
		KeyId:   req.KeyId,
		Success: true,
	}, nil
}

func (s *APIKeyServer) ListProjectAPIKeys(ctx context.Context, req *apikeygenerated.ListProjectAPIKeysRequest) (*apikeygenerated.ListProjectAPIKeysResponse, error) {
	projectID, err := uuid.Parse(req.ProjectId)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "project_id must be a valid UUID")
	}

	if _, err := s.requireOwnedProject(ctx, projectID); err != nil {
		return nil, err
	}

	var keys []db.ApiKey
	if req.ActiveOnly {
		keys, err = s.queries.ListActiveAPIKeysByProject(ctx, projectID)
	} else {
		keys, err = s.queries.ListAPIKeysByProject(ctx, projectID)
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list api keys: %v", err)
	}

	resp := &apikeygenerated.ListProjectAPIKeysResponse{
		Keys: make([]*apikeygenerated.APIKeyResponse, 0, len(keys)),
	}
	for _, key := range keys {
		resp.Keys = append(resp.Keys, toProtoAPIKey(key))
	}
	return resp, nil
}

func (s *APIKeyServer) GetAPIKey(ctx context.Context, req *apikeygenerated.GetAPIKeyRequest) (*apikeygenerated.APIKeyResponse, error) {
	keyID, err := uuid.Parse(req.KeyId)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "key_id must be a valid UUID")
	}

	key, err := s.requireOwnedAPIKey(ctx, keyID)
	if err != nil {
		return nil, err
	}
	return toProtoAPIKey(key), nil
}

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func randomString(length int) string {
	b := make([]byte, length)
	for i := range b {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		b[i] = charset[n.Int64()]
	}
	return string(b)
}

func mustScopesJSON(scopes []string) string {
	b, err := json.Marshal(scopes)
	if err != nil {
		return "[]"
	}
	return string(b)
}

func scopeAllows(allowedScopes []string, action string) bool {
	action = strings.TrimSpace(action)
	if action == "" {
		return true
	}

	for _, raw := range allowedScopes {
		scope := strings.TrimSpace(raw)
		if scope == "" {
			continue
		}
		if scope == "*" || scope == "*:*" || scope == action {
			return true
		}
		if strings.HasSuffix(scope, ":*") {
			prefix := strings.TrimSuffix(scope, "*")
			if strings.HasPrefix(action, prefix) {
				return true
			}
		}
	}
	return false
}

func toProtoAPIKey(key db.ApiKey) *apikeygenerated.APIKeyResponse {
	resp := &apikeygenerated.APIKeyResponse{
		KeyId:       key.KeyID.String(),
		ProjectId:   key.ProjectID.String(),
		UserId:      key.UserID.String(),
		Name:        key.Name.String,
		Prefix:      key.Prefix.String,
		Description: key.Description.String,
		ScopesJson:  mustScopesJSON(key.Scopes),
		IsActive:    key.IsActive.Valid && key.IsActive.Bool,
	}
	if key.RevokedAt.Valid {
		resp.RevokedAt = timestamppb.New(key.RevokedAt.Time)
	}
	if key.ExpiredAt.Valid {
		resp.ExpiredAt = timestamppb.New(key.ExpiredAt.Time)
	}
	return resp
}
