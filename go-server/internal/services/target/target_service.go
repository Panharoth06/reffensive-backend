/*
@description: Target gRPC service — full CRUD using SQLC-generated queries.
              Auth: user ID extracted from gRPC metadata via interceptor.
              All target operations are scoped to (project_id, target_id) to
              prevent cross-project access.
*/

package target

import (
	"context"

	tg "go-server/gen/target"
	db "go-server/internal/database/sqlc"
	"go-server/internal/interceptor"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type targetServer struct {
	tg.UnimplementedTargetServiceServer
}

func NewTargetServer() tg.TargetServiceServer {
	return &targetServer{}
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func protoFromTarget(t db.Target) *tg.TargetResponse {
	resp := &tg.TargetResponse{
		TargetId:  t.TargetID.String(),
		ProjectId: t.ProjectID.String(),
		Name:      t.Name,
		Type:      t.Type,
	}
	if t.Description.Valid {
		resp.Description = t.Description.String
	}
	if t.CreatedAt.Valid {
		resp.CreatedAt = timestamppb.New(t.CreatedAt.Time)
	}
	return resp
}

func requireUserID(ctx context.Context) (string, error) {
	userID, err := interceptor.RequireUserID(ctx)
	if err != nil {
		return "", err
	}
	return userID, nil
}

// ─── CreateTarget ─────────────────────────────────────────────────────────────

func (s *targetServer) CreateTarget(ctx context.Context, req *tg.CreateTargetRequest) (*tg.TargetResponse, error) {
	if _, err := requireUserID(ctx); err != nil {
		return nil, err
	}

	store, err := getTargetResultStore()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "database unavailable: %v", err)
	}

	projectUUID, err := uuid.Parse(req.ProjectId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid project_id: %v", err)
	}
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	if req.Type == "" {
		return nil, status.Error(codes.InvalidArgument, "type is required")
	}

	t, err := store.GetQueries().CreateTarget(ctx, db.CreateTargetParams{
		ProjectID:   projectUUID,
		Name:        req.Name,
		Type:        req.Type,
		Description: pgtype.Text{String: req.Description, Valid: req.Description != ""},
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create target: %v", err)
	}

	return protoFromTarget(t), nil
}

// ─── GetTarget ────────────────────────────────────────────────────────────────

func (s *targetServer) GetTarget(ctx context.Context, req *tg.GetTargetRequest) (*tg.TargetResponse, error) {
	if _, err := requireUserID(ctx); err != nil {
		return nil, err
	}

	store, err := getTargetResultStore()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "database unavailable: %v", err)
	}

	targetUUID, err := uuid.Parse(req.TargetId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid target_id: %v", err)
	}

	t, err := store.GetQueries().GetTargetByID(ctx, targetUUID)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "target not found: %v", err)
	}

	// Verify the target belongs to the requested project.
	if req.ProjectId != "" {
		projectUUID, parseErr := uuid.Parse(req.ProjectId)
		if parseErr != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid project_id: %v", parseErr)
		}
		if t.ProjectID != projectUUID {
			return nil, status.Error(codes.NotFound, "target not found in this project")
		}
	}

	return protoFromTarget(t), nil
}

// ─── ListTargets ──────────────────────────────────────────────────────────────

func (s *targetServer) ListTargets(ctx context.Context, req *tg.ListTargetsRequest) (*tg.ListTargetsResponse, error) {
	if _, err := requireUserID(ctx); err != nil {
		return nil, err
	}

	store, err := getTargetResultStore()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "database unavailable: %v", err)
	}

	projectUUID, err := uuid.Parse(req.ProjectId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid project_id: %v", err)
	}

	targets, err := store.GetQueries().ListTargetsByProject(ctx, projectUUID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list targets: %v", err)
	}

	resp := &tg.ListTargetsResponse{
		Targets: make([]*tg.TargetResponse, 0, len(targets)),
	}
	for _, t := range targets {
		resp.Targets = append(resp.Targets, protoFromTarget(t))
	}
	return resp, nil
}

// ─── UpdateTarget ─────────────────────────────────────────────────────────────

func (s *targetServer) UpdateTarget(ctx context.Context, req *tg.UpdateTargetRequest) (*tg.TargetResponse, error) {
	if _, err := requireUserID(ctx); err != nil {
		return nil, err
	}

	store, err := getTargetResultStore()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "database unavailable: %v", err)
	}

	targetUUID, err := uuid.Parse(req.TargetId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid target_id: %v", err)
	}
	projectUUID, err := uuid.Parse(req.ProjectId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid project_id: %v", err)
	}

	params := db.UpdateTargetParams{
		TargetID:  targetUUID,
		ProjectID: projectUUID,
	}
	if req.Description != nil {
		params.Description = pgtype.Text{String: *req.Description, Valid: true}
	}
	// Note: name and type are intentionally not updatable after creation.

	t, err := store.GetQueries().UpdateTarget(ctx, params)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to update target: %v", err)
	}

	return protoFromTarget(t), nil
}

// ─── DeleteTarget ─────────────────────────────────────────────────────────────

func (s *targetServer) DeleteTarget(ctx context.Context, req *tg.DeleteTargetRequest) (*tg.DeleteTargetResponse, error) {
	if _, err := requireUserID(ctx); err != nil {
		return nil, err
	}

	store, err := getTargetResultStore()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "database unavailable: %v", err)
	}

	targetUUID, err := uuid.Parse(req.TargetId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid target_id: %v", err)
	}
	projectUUID, err := uuid.Parse(req.ProjectId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid project_id: %v", err)
	}

	if err := store.GetQueries().DeleteTarget(ctx, db.DeleteTargetParams{
		TargetID:  targetUUID,
		ProjectID: projectUUID,
	}); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to delete target: %v", err)
	}

	return &tg.DeleteTargetResponse{Success: true, TargetId: req.TargetId}, nil
}
