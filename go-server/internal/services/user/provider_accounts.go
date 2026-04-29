package user

import (
	"context"

	userpb "go-server/gen/user"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *Server) UpsertProviderAccount(ctx context.Context, req *userpb.UpsertProviderAccountRequest) (*userpb.ProviderAccountResponse, error) {
	if s.gitService == nil {
		return nil, status.Error(codes.Internal, "git service is not initialized")
	}
	return s.gitService.UpsertProviderAccount(ctx, req)
}

func (s *Server) UpsertGithubProviderAccount(ctx context.Context, req *userpb.UpsertGithubProviderAccountRequest) (*userpb.ProviderAccountResponse, error) {
	if s.gitService == nil {
		return nil, status.Error(codes.Internal, "git service is not initialized")
	}
	return s.gitService.UpsertGithubProviderAccount(ctx, req)
}

func (s *Server) ListProviderAccounts(ctx context.Context, req *userpb.ListProviderAccountsRequest) (*userpb.ListProviderAccountsResponse, error) {
	if s.gitService == nil {
		return nil, status.Error(codes.Internal, "git service is not initialized")
	}
	return s.gitService.ListProviderAccounts(ctx, req)
}

func (s *Server) ListProviderAuthAccounts(ctx context.Context, req *userpb.ListProviderAuthAccountsRequest) (*userpb.ListProviderAuthAccountsResponse, error) {
	if s.gitService == nil {
		return nil, status.Error(codes.Internal, "git service is not initialized")
	}
	return s.gitService.ListProviderAuthAccounts(ctx, req)
}