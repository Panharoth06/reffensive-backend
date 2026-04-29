/*
@author: @Panharoth06
@date: 2026-04-03
@description: Project service for managing projects
*/

package project

import (
	"context"
	pj "go-server/gen/projectpb"
	db "go-server/internal/database/sqlc"
	"go-server/internal/interceptor"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type projectServer struct {
	pj.UnimplementedProjectServiceServer
	store projectResultStore
}

func NewProjectServer() pj.ProjectServiceServer {
	return &projectServer{}
}

func (s *projectServer) CreateProject(ctx context.Context, req *pj.CreateProjectRequest) (*pj.ProjectResponse, error) {
	store, err := getProjectResultStore()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "database unavailable: %v", err)
	}

	userID, err := interceptor.RequireUserID(ctx)
	if err != nil {
		return nil, err
	}
	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid user_id: %v", err)
	}

	user, err := store.GetQueries().GetUserByID(ctx, userUUID)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "user not found: %v", err)
	}

	params := db.CreateProjectParams{
		UserID:      user.UserID,
		ProjectName: req.Name,
		Description: pgtype.Text{String: req.Description, Valid: req.Description != ""},
	}

	created, err := store.GetQueries().CreateProject(ctx, params)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create project: %v", err)
	}

	return &pj.ProjectResponse {
		ProjectId: created.ProjectID.String(),
		Name: created.ProjectName,
		Description: created.Description.String,
		OwnerId: created.UserID.String(),
		CreatedAt: timestamppb.New(created.CreatedAt.Time),
		LastModified: timestamppb.New(created.LastModified.Time),
	}, nil
}


func (s *projectServer) GetProject(ctx context.Context, req *pj.GetProjectRequest) (*pj.ProjectResponse, error) {
	store, err := getProjectResultStore()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "database unavailable: %v", err)
	}

	userID, err := interceptor.RequireUserID(ctx)
	if err != nil {
		return nil, err
	}
	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid user_id: %v", err)
	}

	var project db.Project
	var queryErr error

	switch v := req.GetProject().(type) {
	case *pj.GetProjectRequest_ProjectId:
		projectUUID, err := uuid.Parse(v.ProjectId)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid project_id: %v", err)
		}
		project, queryErr = store.GetQueries().GetProjectByID(ctx, db.GetProjectByIDParams{
			ProjectID: projectUUID,
			UserID:    userUUID,
		})
	case *pj.GetProjectRequest_ProjectName:
		project, queryErr = store.GetQueries().GetProjectByName(ctx, db.GetProjectByNameParams{
			ProjectName: v.ProjectName,
			UserID:      userUUID,
		})
	default:
		return nil, status.Error(codes.InvalidArgument, "either project_id or project_name must be provided")
	}

	if queryErr != nil {
		return nil, status.Errorf(codes.NotFound, "project not found: %v", queryErr)
	}

	return &pj.ProjectResponse{
		ProjectId:    project.ProjectID.String(),
		Name:         project.ProjectName,
		Description:  project.Description.String,
		OwnerId:      project.UserID.String(),
		CreatedAt:    timestamppb.New(project.CreatedAt.Time),
		LastModified: timestamppb.New(project.LastModified.Time),
	}, nil
}

func (s *projectServer) ListProjects(ctx context.Context, req *pj.ListProjectsRequest) (*pj.ListProjectsResponse, error) {
	store, err := getProjectResultStore()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "database unavailable: %v", err)
	}

	userID, err := interceptor.RequireUserID(ctx)
	if err != nil {
		return nil, err
	}
	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid user_id: %v", err)
	}

	projects, err := store.GetQueries().ListProjectsByUser(ctx, userUUID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list projects: %v", err)
	}

	responses := make([]*pj.ProjectResponse, 0, len(projects))
	for _, p := range projects {
		responses = append(responses, &pj.ProjectResponse{
			ProjectId:    p.ProjectID.String(),
			Name:         p.ProjectName,
			Description:  p.Description.String,
			OwnerId:      p.UserID.String(),
			CreatedAt:    timestamppb.New(p.CreatedAt.Time),
			LastModified: timestamppb.New(p.LastModified.Time),
		})
	}

	return &pj.ListProjectsResponse{Projects: responses}, nil
}

func (s *projectServer) UpdateProject(ctx context.Context, req *pj.UpdateProjectRequest) (*pj.ProjectResponse, error) {
	store, err := getProjectResultStore()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "database unavailable: %v", err)
	}

	userID, err := interceptor.RequireUserID(ctx)
	if err != nil {
		return nil, err
	}
	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid user_id: %v", err)
	}

	projectUUID, err := uuid.Parse(req.ProjectId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid project_id: %v", err)
	}

	params := db.UpdateProjectParams{
		ProjectID: projectUUID,
		UserID:    userUUID,
		ProjectName: pgtype.Text{
			String: req.GetName(),
			Valid:  req.Name != nil,
		},
		Description: pgtype.Text{
			String: req.GetDescription(),
			Valid:  req.Description != nil,
		},
	}

	updated, err := store.GetQueries().UpdateProject(ctx, params)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to update project: %v", err)
	}

	return &pj.ProjectResponse{
		ProjectId:    updated.ProjectID.String(),
		Name:         updated.ProjectName,
		Description:  updated.Description.String,
		OwnerId:      updated.UserID.String(),
		CreatedAt:    timestamppb.New(updated.CreatedAt.Time),
		LastModified: timestamppb.New(updated.LastModified.Time),
	}, nil
}

func (s *projectServer) DeleteProject(ctx context.Context, req *pj.DeleteProjectRequest) (*pj.DeleteProjectResponse, error) {
	store, err := getProjectResultStore()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "database unavailable: %v", err)
	}

	userID, err := interceptor.RequireUserID(ctx)
	if err != nil {
		return nil, err
	}
	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid user_id: %v", err)
	}

	projectUUID, err := uuid.Parse(req.ProjectId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid project_id: %v", err)
	}

	// Always cascade: delete in dependency order
	// 1. findings (references scan_results via raw_result_id, no CASCADE)
	// 2. scan_results (references scan_jobs, targets - no CASCADE on some)
	// 3. scan_jobs (CASCADE deletes scan_steps automatically)
	// 4. targets (references projects)
	// 5. project
	if err := store.GetQueries().DeleteProjectFindings(ctx, projectUUID); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to delete findings: %v", err)
	}
	if err := store.GetQueries().DeleteProjectScanResults(ctx, projectUUID); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to delete scan results: %v", err)
	}
	if err := store.GetQueries().DeleteProjectScanJobs(ctx, projectUUID); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to delete scan jobs: %v", err)
	}
	if err := store.GetQueries().DeleteProjectTargets(ctx, projectUUID); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to delete targets: %v", err)
	}

	params := db.DeleteProjectParams{
		ProjectID: projectUUID,
		UserID:    userUUID,
	}

	err = store.GetQueries().DeleteProject(ctx, params)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to delete project: %v", err)
	}

	return &pj.DeleteProjectResponse{Success: true}, nil
}