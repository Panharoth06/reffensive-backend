package service

import (
	"errors"
	"testing"

	db "go-server/internal/database/sqlc"
	gitscanner "go-server/internal/services/sonarqube/scanner/git"
)

func TestParseProviderRepositoryURL(t *testing.T) {
	tests := []struct {
		name         string
		rawURL       string
		wantProvider db.ProviderTypeEnum
		wantFullName string
		wantErr      bool
	}{
		{
			name:         "github web url",
			rawURL:       "https://github.com/openai/codex",
			wantProvider: db.ProviderTypeEnumGithub,
			wantFullName: "openai/codex",
		},
		{
			name:         "github clone url trims suffix",
			rawURL:       "https://github.com/openai/codex.git",
			wantProvider: db.ProviderTypeEnumGithub,
			wantFullName: "openai/codex",
		},
		{
			name:         "gitlab nested group",
			rawURL:       "https://gitlab.com/group/subgroup/project.git",
			wantProvider: db.ProviderTypeEnumGitlab,
			wantFullName: "group/subgroup/project",
		},
		{
			name:    "unsupported host",
			rawURL:  "https://example.com/group/project",
			wantErr: true,
		},
		{
			name:    "missing repo name",
			rawURL:  "https://github.com/openai",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotProvider, gotFullName, err := parseProviderRepositoryURL(tt.rawURL)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("parseProviderRepositoryURL() error = %v", err)
			}
			if gotProvider != tt.wantProvider {
				t.Fatalf("provider = %q, want %q", gotProvider, tt.wantProvider)
			}
			if gotFullName != tt.wantFullName {
				t.Fatalf("full name = %q, want %q", gotFullName, tt.wantFullName)
			}
		})
	}
}

func TestAuthenticatedRepositoryURL(t *testing.T) {
	tests := []struct {
		name         string
		rawURL       string
		provider     db.ProviderTypeEnum
		token        string
		wantContains string
	}{
		{
			name:         "github credentials",
			rawURL:       "https://github.com/openai/codex.git",
			provider:     db.ProviderTypeEnumGithub,
			token:        "token-1",
			wantContains: "https://x-access-token:token-1@github.com/openai/codex.git",
		},
		{
			name:         "gitlab credentials",
			rawURL:       "https://gitlab.com/group/project.git",
			provider:     db.ProviderTypeEnumGitlab,
			token:        "token-2",
			wantContains: "https://oauth2:token-2@gitlab.com/group/project.git",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := authenticatedRepositoryURL(tt.rawURL, tt.provider, tt.token)
			if err != nil {
				t.Fatalf("authenticatedRepositoryURL() error = %v", err)
			}
			if got != tt.wantContains {
				t.Fatalf("authenticated url = %q, want %q", got, tt.wantContains)
			}
		})
	}
}

func TestShouldRetryCloneWithNextTarget(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "auth required", err: gitscanner.ErrAuthRequired, want: true},
		{name: "repo not found", err: gitscanner.ErrRepoNotFound, want: true},
		{name: "branch not found", err: gitscanner.ErrBranchNotFound, want: false},
		{name: "other error", err: errors.New("boom"), want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldRetryCloneWithNextTarget(tt.err); got != tt.want {
				t.Fatalf("shouldRetryCloneWithNextTarget(%v) = %t, want %t", tt.err, got, tt.want)
			}
		})
	}
}
