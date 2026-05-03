package git

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const defaultCloneTimeout = 2 * time.Minute

var (
	ErrRepoNotFound   = errors.New("repository not found")
	ErrBranchNotFound = errors.New("branch not found")
	ErrAuthRequired   = errors.New("repository authentication required")
	ErrCloneTimeout   = errors.New("git clone timed out")
)

func Clone(ctx context.Context, repoURL string, branch string, destDir string) error {
	timeout := cloneTimeoutFromEnv()
	cloneCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	args := []string{
		"clone",
		"--branch", strings.TrimSpace(branch),
		"--depth", "1",
		"--single-branch",
		strings.TrimSpace(repoURL),
		strings.TrimSpace(destDir),
	}

	cmd := exec.CommandContext(cloneCtx, "git", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return classifyCloneError(cloneCtx, stderr.String(), err)
	}
	return nil
}

func classifyCloneError(ctx context.Context, stderr string, err error) error {
	if errors.Is(ctx.Err(), context.Canceled) {
		return context.Canceled
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("%w: %s", ErrCloneTimeout, strings.TrimSpace(stderr))
	}

	clean := strings.ToLower(stderr)

	var ErrCloneFailed = errors.New("git clone failed")
	switch {
	case strings.Contains(clean, "not a valid branch"),
		strings.Contains(clean, "remote branch") && strings.Contains(clean, "not found"):
		return fmt.Errorf("%w: %s", ErrBranchNotFound, strings.TrimSpace(stderr))
	case strings.Contains(clean, "could not read"):
		return fmt.Errorf("%w: %s", ErrAuthRequired, strings.TrimSpace(stderr))
	case strings.Contains(clean, "not found"):
		return fmt.Errorf("%w: %s", ErrRepoNotFound, strings.TrimSpace(stderr))

	default:
		return fmt.Errorf("%w: %w\nstderr: %s", ErrCloneFailed, err, strings.TrimSpace(stderr))
	}
}

func cloneTimeoutFromEnv() time.Duration {
	raw := strings.TrimSpace(os.Getenv("GIT_CLONE_TIMEOUT"))
	if raw == "" {
		return defaultCloneTimeout
	}

	if parsed, err := time.ParseDuration(raw); err == nil && parsed > 0 {
		return parsed
	}
	if seconds, err := strconv.Atoi(raw); err == nil && seconds > 0 {
		return time.Duration(seconds) * time.Second
	}
	return defaultCloneTimeout
}
