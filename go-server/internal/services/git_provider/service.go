package git

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	userpb "go-server/gen/user"
	db "go-server/internal/database/sqlc"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Server struct {
	queries *db.Queries
}

func NewServer(queries *db.Queries) *Server {
	return &Server{queries: queries}
}

type upsertProviderAccountInput struct {
	UserID            string
	ProviderType      db.ProviderTypeEnum
	ProviderAccountID string
	ProviderUsername  string
	ProviderEmail     string
	AccessToken       *string
	RefreshToken      *string
}

func (s *Server) UpsertProviderAccount(ctx context.Context, req *userpb.UpsertProviderAccountRequest) (*userpb.ProviderAccountResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}

	providerType, err := ParseProviderType(strings.TrimSpace(req.GetProviderType()))
	if err != nil {
		return nil, err
	}

	var accessToken *string
	if req.AccessToken != nil {
		value := strings.TrimSpace(req.GetAccessToken())
		accessToken = &value
	}

	var refreshToken *string
	if req.RefreshToken != nil {
		value := strings.TrimSpace(req.GetRefreshToken())
		refreshToken = &value
	}

	return s.upsertProviderAccount(ctx, upsertProviderAccountInput{
		UserID:            req.GetUserId(),
		ProviderType:      providerType,
		ProviderAccountID: req.GetProviderAccountId(),
		ProviderUsername:  req.GetProviderUsername(),
		ProviderEmail:     req.GetProviderEmail(),
		AccessToken:       accessToken,
		RefreshToken:      refreshToken,
	})
}

func (s *Server) UpsertGithubProviderAccount(ctx context.Context, req *userpb.UpsertGithubProviderAccountRequest) (*userpb.ProviderAccountResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}

	accessToken := strings.TrimSpace(req.GetAccessToken())
	if accessToken == "" {
		return nil, status.Error(codes.InvalidArgument, "access_token is required")
	}
	var refreshToken *string
	if req.RefreshToken != nil {
		value := strings.TrimSpace(req.GetRefreshToken())
		refreshToken = &value
	}

	return s.upsertProviderAccount(ctx, upsertProviderAccountInput{
		UserID:            req.GetUserId(),
		ProviderType:      db.ProviderTypeEnumGithub,
		ProviderAccountID: req.GetProviderAccountId(),
		ProviderUsername:  req.GetProviderUsername(),
		ProviderEmail:     req.GetProviderEmail(),
		AccessToken:       &accessToken,
		RefreshToken:      refreshToken,
	})
}

func (s *Server) ListProviderAccounts(ctx context.Context, req *userpb.ListProviderAccountsRequest) (*userpb.ListProviderAccountsResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}

	userID, err := parseUserID(req.GetUserId())
	if err != nil {
		return nil, err
	}

	rows, err := s.queries.ListProviderAccountsByUser(ctx, userID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list provider accounts failed: %v", err)
	}

	accounts := make([]*userpb.ProviderAccount, 0, len(rows))
	for _, row := range rows {
		accounts = append(accounts, mapProviderAccount(row))
	}

	return &userpb.ListProviderAccountsResponse{Accounts: accounts}, nil
}

func (s *Server) ListProviderAuthAccounts(ctx context.Context, req *userpb.ListProviderAuthAccountsRequest) (*userpb.ListProviderAuthAccountsResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}

	userID, err := parseUserID(req.GetUserId())
	if err != nil {
		return nil, err
	}

	providerType, err := ParseProviderType(req.GetProviderType())
	if err != nil {
		return nil, err
	}

	rows, err := s.queries.ListProviderAccountsByUser(ctx, userID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list provider auth accounts failed: %v", err)
	}

	accounts := make([]*userpb.ProviderAuthAccount, 0, len(rows))
	for _, row := range rows {
		if row.ProviderType != providerType {
			continue
		}
		if row.Status != db.ProviderAccountStatusCONNECTED {
			continue
		}
		if strings.TrimSpace(row.AccessTokenEncrypted) == "" {
			continue
		}
		accounts = append(accounts, mapProviderAuthAccount(row))
	}

	return &userpb.ListProviderAuthAccountsResponse{Accounts: accounts}, nil
}

func mapProviderAccount(value db.ProviderAccount) *userpb.ProviderAccount {
	return &userpb.ProviderAccount{
		Id:                value.ID.String(),
		UserId:            value.UserID.String(),
		ProviderType:      string(value.ProviderType),
		ProviderAccountId: value.ProviderAccountID,
		ProviderUsername:  value.ProviderUsername,
		ProviderEmail:     textOrEmpty(value.ProviderEmail),
		Status:            string(value.Status),
		ConnectedAt:       formatTimestamp(value.ConnectedAt),
		UpdatedAt:         formatTimestamp(value.UpdatedAt),
	}
}

func mapProviderAuthAccount(value db.ProviderAccount) *userpb.ProviderAuthAccount {
	account := &userpb.ProviderAuthAccount{
		Id:                value.ID.String(),
		UserId:            value.UserID.String(),
		ProviderType:      string(value.ProviderType),
		ProviderAccountId: value.ProviderAccountID,
		ProviderUsername:  value.ProviderUsername,
		ProviderEmail:     textOrEmpty(value.ProviderEmail),
		Status:            string(value.Status),
		AccessToken:       value.AccessTokenEncrypted,
	}
	if value.RefreshTokenEncrypted.Valid {
		token := value.RefreshTokenEncrypted.String
		account.RefreshToken = &token
	}
	return account
}

func (s *Server) upsertProviderAccount(ctx context.Context, input upsertProviderAccountInput) (*userpb.ProviderAccountResponse, error) {
	userID, err := parseUserID(input.UserID)
	if err != nil {
		return nil, err
	}

	providerAccountID := strings.TrimSpace(input.ProviderAccountID)
	providerUsername := strings.TrimSpace(input.ProviderUsername)
	providerEmail := strings.TrimSpace(input.ProviderEmail)
	if providerAccountID == "" {
		return nil, status.Error(codes.InvalidArgument, "provider_account_id is required")
	}
	if providerUsername == "" {
		return nil, status.Error(codes.InvalidArgument, "provider_username is required")
	}

	accessToken := ""
	hasAccessToken := false
	if input.AccessToken != nil {
		accessToken = strings.TrimSpace(*input.AccessToken)
		hasAccessToken = accessToken != ""
	}

	var refreshTokenText pgtype.Text
	if input.RefreshToken != nil {
		refreshTokenText = toOptionalText(*input.RefreshToken)
	}

	if _, err := s.queries.GetUserByID(ctx, userID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, status.Error(codes.NotFound, "user not found")
		}
		return nil, status.Errorf(codes.Internal, "get user failed: %v", err)
	}

	getIdentity := db.GetProviderAccountByIdentityParams{
		ProviderType:      input.ProviderType,
		ProviderAccountID: providerAccountID,
	}
	emailText := toOptionalText(providerEmail)
	existing, err := s.queries.GetProviderAccountByIdentity(ctx, getIdentity)
	if err == nil {
		if existing.UserID != userID {
			return nil, status.Errorf(codes.AlreadyExists, "%s account is already linked to another user", string(input.ProviderType))
		}

		statusValue := existing.Status
		if hasAccessToken {
			statusValue = db.ProviderAccountStatusCONNECTED
		} else if statusValue == "" {
			statusValue = db.ProviderAccountStatusDISCONNECTED
		}

		accessTokenValue := existing.AccessTokenEncrypted
		if hasAccessToken {
			accessTokenValue = accessToken
		}

		if input.RefreshToken == nil {
			refreshTokenText = existing.RefreshTokenEncrypted
		}

		updated, err := s.queries.UpdateProviderAccountOAuthData(ctx, db.UpdateProviderAccountOAuthDataParams{
			ID:                    existing.ID,
			ProviderUsername:      providerUsername,
			ProviderEmail:         emailText,
			Status:                statusValue,
			AccessTokenEncrypted:  accessTokenValue,
			RefreshTokenEncrypted: refreshTokenText,
		})
		if err != nil {
			return nil, status.Errorf(codes.Internal, "update provider account failed: %v", err)
		}
		return &userpb.ProviderAccountResponse{Account: mapProviderAccount(updated)}, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, status.Errorf(codes.Internal, "get provider account failed: %v", err)
	}

	createStatus := db.ProviderAccountStatusDISCONNECTED
	if hasAccessToken {
		createStatus = db.ProviderAccountStatusCONNECTED
	}

	created, err := s.queries.CreateProviderAccount(ctx, db.CreateProviderAccountParams{
		UserID:            userID,
		ProviderType:      input.ProviderType,
		ProviderAccountID: providerAccountID,
		ProviderUsername:  providerUsername,
		ProviderEmail:     emailText,
		Status:            createStatus,
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, status.Error(codes.AlreadyExists, "provider account already exists")
		}
		return nil, status.Errorf(codes.Internal, "create provider account failed: %v", err)
	}

	if hasAccessToken || input.RefreshToken != nil {
		updated, err := s.queries.UpdateProviderAccountOAuthData(ctx, db.UpdateProviderAccountOAuthDataParams{
			ID:                    created.ID,
			ProviderUsername:      providerUsername,
			ProviderEmail:         emailText,
			Status:                createStatus,
			AccessTokenEncrypted:  accessToken,
			RefreshTokenEncrypted: refreshTokenText,
		})
		if err != nil {
			return nil, status.Errorf(codes.Internal, "persist provider token failed: %v", err)
		}
		return &userpb.ProviderAccountResponse{Account: mapProviderAccount(updated)}, nil
	}

	return &userpb.ProviderAccountResponse{Account: mapProviderAccount(created)}, nil
}

func ParseProviderType(raw string) (db.ProviderTypeEnum, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "github":
		return db.ProviderTypeEnumGithub, nil
	case "gitlab":
		return db.ProviderTypeEnumGitlab, nil
	case "bitbucket":
		return db.ProviderTypeEnumBitbucket, nil
	default:
		return "", status.Error(codes.InvalidArgument, fmt.Sprintf("unsupported provider_type: %s", raw))
	}
}

func parseUserID(raw string) (uuid.UUID, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return uuid.Nil, status.Error(codes.InvalidArgument, "user_id is required")
	}
	userID, err := uuid.Parse(value)
	if err != nil {
		return uuid.Nil, status.Error(codes.InvalidArgument, "user_id must be a valid UUID")
	}
	return userID, nil
}

func toOptionalText(value string) pgtype.Text {
	clean := strings.TrimSpace(value)
	if clean == "" {
		return pgtype.Text{}
	}
	return pgtype.Text{String: clean, Valid: true}
}

func textOrEmpty(value pgtype.Text) string {
	if value.Valid {
		return value.String
	}
	return ""
}

func formatTimestamp(value pgtype.Timestamptz) string {
	if value.Valid {
		return value.Time.UTC().Format(time.RFC3339)
	}
	return ""
}
