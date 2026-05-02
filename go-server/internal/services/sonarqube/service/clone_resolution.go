package service

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/google/uuid"

	db "go-server/internal/database/sqlc"
	gitscanner "go-server/internal/services/sonarqube/scanner/git"
)

func (s *ScannerServer) cloneTargetsForScan(ctx context.Context, scanID uuid.UUID, repoURL string) ([]string, error) {
	repoURL = strings.TrimSpace(repoURL)
	if repoURL == "" {
		return nil, errors.New("repo_url is required")
	}

	scan, err := s.scanRepo.RawByUUID(ctx, scanID)
	if err != nil {
		return nil, fmt.Errorf("load scan context: %w", err)
	}

	provider, _, err := parseProviderRepositoryURL(repoURL)
	if err != nil {
		return []string{repoURL}, nil
	}

	accounts, err := s.queries.ListProviderAccountsByUser(ctx, scan.UserID)
	if err != nil {
		return nil, fmt.Errorf("list provider accounts: %w", err)
	}

	targets := []string{repoURL}
	seen := map[string]struct{}{repoURL: {}}
	for _, account := range accounts {
		if account.ProviderType != provider || account.Status != db.ProviderAccountStatusCONNECTED {
			continue
		}
		token := strings.TrimSpace(account.AccessTokenEncrypted)
		if token == "" {
			continue
		}

		authenticatedURL, err := authenticatedRepositoryURL(repoURL, provider, token)
		if err != nil {
			continue
		}
		if _, exists := seen[authenticatedURL]; exists {
			continue
		}
		seen[authenticatedURL] = struct{}{}
		targets = append(targets, authenticatedURL)
	}

	return targets, nil
}

func shouldRetryCloneWithNextTarget(err error) bool {
	return errors.Is(err, gitscanner.ErrAuthRequired) || errors.Is(err, gitscanner.ErrRepoNotFound)
}

func parseProviderRepositoryURL(raw string) (db.ProviderTypeEnum, string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", "", err
	}

	host := strings.ToLower(strings.TrimSpace(parsed.Hostname()))
	segments := splitRepositoryPath(parsed.Path)
	if len(segments) < 2 {
		return "", "", errors.New("repository path is incomplete")
	}

	switch {
	case strings.HasSuffix(host, "github.com"):
		return db.ProviderTypeEnumGithub, joinRepositorySegments(segments[:2]), nil
	case strings.HasSuffix(host, "gitlab.com"):
		return db.ProviderTypeEnumGitlab, joinRepositorySegments(segments), nil
	default:
		return "", "", errors.New("unsupported repository provider")
	}
}

func authenticatedRepositoryURL(raw string, provider db.ProviderTypeEnum, token string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}

	token = strings.TrimSpace(token)
	if token == "" {
		return "", errors.New("token is required")
	}

	username := "oauth2"
	if provider == db.ProviderTypeEnumGithub {
		username = "x-access-token"
	}
	parsed.User = url.UserPassword(username, token)
	return parsed.String(), nil
}

func splitRepositoryPath(rawPath string) []string {
	rawPath = strings.TrimSpace(rawPath)
	if rawPath == "" {
		return nil
	}

	parts := strings.Split(strings.Trim(rawPath, "/"), "/")
	result := make([]string, 0, len(parts))
	for idx, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if idx == len(parts)-1 {
			part = strings.TrimSuffix(part, ".git")
		}
		if part == "" {
			continue
		}
		result = append(result, part)
	}
	return result
}

func joinRepositorySegments(parts []string) string {
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		result = append(result, part)
	}
	return strings.Join(result, "/")
}
