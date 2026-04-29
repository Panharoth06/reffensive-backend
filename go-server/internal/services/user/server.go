package user

import (
	"context"
	"errors"
	gitsvc "go-server/internal/services/git_provider"
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
	userpb.UnimplementedUserServiceServer
	queries      *db.Queries
	gitService   *gitsvc.Server
}

func NewServer(queries *db.Queries) *Server {
	return &Server{
		queries:      queries,
		gitService:   gitsvc.NewServer(queries),
	}
}

func (s *Server) CheckUserExists(ctx context.Context, req *userpb.CheckUserExistsRequest) (*userpb.CheckUserExistsResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}

	userIDText := strings.TrimSpace(req.GetUserId())
	email := strings.TrimSpace(req.GetEmail())
	username := strings.TrimSpace(req.GetUsername())

	if userIDText == "" && email == "" && username == "" {
		return nil, status.Error(codes.InvalidArgument, "at least one identifier (user_id, email, username) is required")
	}

	if userIDText != "" {
		if userID, err := uuid.Parse(userIDText); err == nil {
			record, err := s.queries.GetUserByID(ctx, userID)
			if err == nil {
				return &userpb.CheckUserExistsResponse{
					Exists:         true,
					MatchedBy:      "user_id",
					ResolvedUserId: record.UserID.String(),
				}, nil
			}
			if !errors.Is(err, pgx.ErrNoRows) {
				return nil, status.Errorf(codes.Internal, "lookup by user_id failed: %v", err)
			}
		}
	}

	if email != "" {
		record, err := s.queries.GetUserByEmail(ctx, email)
		if err == nil {
			return &userpb.CheckUserExistsResponse{
				Exists:         true,
				MatchedBy:      "email",
				ResolvedUserId: record.UserID.String(),
			}, nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return nil, status.Errorf(codes.Internal, "lookup by email failed: %v", err)
		}
	}

	if username != "" {
		record, err := s.queries.GetUserByUsername(ctx, username)
		if err == nil {
			return &userpb.CheckUserExistsResponse{
				Exists:         true,
				MatchedBy:      "username",
				ResolvedUserId: record.UserID.String(),
			}, nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return nil, status.Errorf(codes.Internal, "lookup by username failed: %v", err)
		}
	}

	return &userpb.CheckUserExistsResponse{Exists: false}, nil
}

func (s *Server) CreateUser(ctx context.Context, req *userpb.CreateUserRequest) (*userpb.UserResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}

	userID, err := parseUserID(req.GetUserId())
	if err != nil {
		return nil, err
	}

	username := strings.TrimSpace(req.GetUsername())
	email := strings.TrimSpace(req.GetEmail())
	if username == "" || email == "" {
		return nil, status.Error(codes.InvalidArgument, "username and email are required")
	}

	record, err := s.queries.CreateUser(
		ctx,
		db.CreateUserParams{
			UserID:        userID,
			Username:      username,
			Email:         email,
			AliasName:     toOptionalText(req.GetAliasName()),
			AvatarProfile: toOptionalText(req.GetAvatarProfile()),
		},
	)
	if err != nil {
		return nil, mapDBError("create user", err)
	}

	return &userpb.UserResponse{User: mapUser(record)}, nil
}

func (s *Server) GetUser(ctx context.Context, req *userpb.GetUserRequest) (*userpb.UserResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}

	userID, err := parseUserID(req.GetUserId())
	if err != nil {
		return nil, err
	}

	record, err := s.queries.GetUserByID(ctx, userID)
	if err != nil {
		return nil, mapDBError("get user", err)
	}

	return &userpb.UserResponse{User: mapUser(record)}, nil
}

func (s *Server) ListUsers(ctx context.Context, _ *userpb.ListUsersRequest) (*userpb.ListUsersResponse, error) {
	records, err := s.queries.ListUsers(ctx)
	if err != nil {
		return nil, mapDBError("list users", err)
	}

	users := make([]*userpb.User, 0, len(records))
	for _, record := range records {
		users = append(users, mapUser(record))
	}

	return &userpb.ListUsersResponse{Users: users}, nil
}

func (s *Server) UpdateUser(ctx context.Context, req *userpb.UpdateUserRequest) (*userpb.UserResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}

	userID, err := parseUserID(req.GetUserId())
	if err != nil {
		return nil, err
	}

	var usernameValue pgtype.Text
	if clean := strings.TrimSpace(req.GetUsername()); clean != "" {
		usernameValue = pgtype.Text{String: clean, Valid: true}
	}

	var emailValue pgtype.Text
	if clean := strings.TrimSpace(req.GetEmail()); clean != "" {
		emailValue = pgtype.Text{String: clean, Valid: true}
	}

	var aliasValue pgtype.Text
	if req.AliasName != nil {
		aliasValue = pgtype.Text{String: req.GetAliasName(), Valid: true}
	}

	var avatarValue pgtype.Text
	if req.AvatarProfile != nil {
		avatarValue = pgtype.Text{String: req.GetAvatarProfile(), Valid: true}
	}

	record, err := s.queries.UpdateUser(
		ctx,
		db.UpdateUserParams{
			UserID:        userID,
			Username:      usernameValue,
			Email:         emailValue,
			AliasName:     aliasValue,
			AvatarProfile: avatarValue,
		},
	)
	if err != nil {
		return nil, mapDBError("update user", err)
	}

	return &userpb.UserResponse{User: mapUser(record)}, nil
}

func (s *Server) DeleteUser(ctx context.Context, req *userpb.DeleteUserRequest) (*userpb.DeleteUserResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}

	userID, err := parseUserID(req.GetUserId())
	if err != nil {
		return nil, err
	}

	rows, err := s.queries.DeleteUser(ctx, userID)
	if err != nil {
		return nil, mapDBError("delete user", err)
	}
	if rows == 0 {
		return nil, status.Error(codes.NotFound, "user not found")
	}

	return &userpb.DeleteUserResponse{Deleted: true}, nil
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

func mapUser(value db.User) *userpb.User {
	return &userpb.User{
		UserId:        value.UserID.String(),
		Username:      value.Username,
		Email:         value.Email,
		AliasName:     textOrEmpty(value.AliasName),
		AvatarProfile: textOrEmpty(value.AvatarProfile),
		CreatedAt:     formatTimestamp(value.CreatedAt),
		LastModified:  formatTimestamp(value.LastModified),
	}
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

func mapDBError(action string, err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return status.Error(codes.NotFound, "user not found")
	}

	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return status.Error(codes.AlreadyExists, "user already exists")
	}

	return status.Errorf(codes.Internal, "%s failed: %v", action, err)
}
