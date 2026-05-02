/*
@author: @Panharoth06
@date: 2026-04-02
@description: Category service for managing tool categories
*/

package services

import (
	"context"

	cat "go-server/gen/category"
	db "go-server/internal/database/sqlc"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ─── Server ───────────────────────────────────────────────────────────────────

type categoryServer struct {
	cat.UnimplementedCategoryServiceServer
	store categoryResultStore
}

func NewCategoryServer() cat.CategoryServiceServer {
	return &categoryServer{}
}

// ─── CreateCategory ───────────────────────────────────────────────────────────

func (s *categoryServer) CreateCategory(ctx context.Context, req *cat.CreateCategoryRequest) (*cat.CategoryResponse, error) {
	store, err := getCategoryResultStore()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "database unavailable: %v", err)
	}

	params := db.CreateToolCategoryParams{
		Name:        req.Name,
		Description: pgtype.Text{String: req.Description, Valid: req.Description != ""},
	}
	created, err := store.GetQueries().CreateToolCategory(ctx, params)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create category: %v", err)
	}
	return categoryToProto(created), nil
}

// ─── GetCategory ──────────────────────────────────────────────────────────────

func (s *categoryServer) GetCategory(ctx context.Context, req *cat.GetCategoryRequest) (*cat.CategoryResponse, error) {
	store, err := getCategoryResultStore()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "database unavailable: %v", err)
	}

	catID, err := uuid.Parse(req.CategoryId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid category_id: %v", err)
	}

	c, err := store.GetQueries().GetToolCategoryByID(ctx, catID)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "category not found: %v", err)
	}
	return categoryToProto(c), nil
}

// ─── ListCategories ───────────────────────────────────────────────────────────

func (s *categoryServer) ListCategories(ctx context.Context, _ *cat.ListCategoriesRequest) (*cat.ListCategoriesResponse, error) {
	store, err := getCategoryResultStore()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "database unavailable: %v", err)
	}

	cats, err := store.GetQueries().ListToolCategories(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list categories: %v", err)
	}

	resp := &cat.ListCategoriesResponse{}
	for _, c := range cats {
		resp.Categories = append(resp.Categories, categoryToProto(c))
	}
	return resp, nil
}

// ─── UpdateCategory ───────────────────────────────────────────────────────────

func (s *categoryServer) UpdateCategory(ctx context.Context, req *cat.UpdateCategoryRequest) (*cat.CategoryResponse, error) {
	store, err := getCategoryResultStore()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "database unavailable: %v", err)
	}

	catID, err := uuid.Parse(req.CategoryId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid category_id: %v", err)
	}

	params := db.UpdateToolCategoryParams{
		CategoryID:  catID,
		Name:        pgtype.Text{String: req.Name, Valid: req.Name != ""},
		Description: pgtype.Text{String: req.Description, Valid: req.Description != ""},
	}

	updated, err := store.GetQueries().UpdateToolCategory(ctx, params)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to update category: %v", err)
	}
	return categoryToProto(updated), nil
}

// ─── DeleteCategory ───────────────────────────────────────────────────────────

func (s *categoryServer) DeleteCategory(ctx context.Context, req *cat.DeleteCategoryRequest) (*cat.DeleteCategoryResponse, error) {
	store, err := getCategoryResultStore()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "database unavailable: %v", err)
	}

	catID, err := uuid.Parse(req.CategoryId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid category_id: %v", err)
	}

	if err := store.GetQueries().DeleteToolCategory(ctx, catID); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to delete category: %v", err)
	}
	return &cat.DeleteCategoryResponse{CategoryId: req.CategoryId, Deleted: true}, nil
}

// ─── Helper ───────────────────────────────────────────────────────────────────

func categoryToProto(c db.ToolCategory) *cat.CategoryResponse {
	resp := &cat.CategoryResponse{
		CategoryId:  c.CategoryID.String(),
		Name:        c.Name,
		Description: c.Description.String,
	}
	if c.CreatedAt.Valid {
		resp.CreatedAt = timestamppb.New(c.CreatedAt.Time)
	}
	if c.LastModified.Valid {
		resp.LastModified = timestamppb.New(c.LastModified.Time)
	}
	return resp
}
