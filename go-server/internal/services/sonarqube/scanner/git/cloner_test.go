package git

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

func TestClassifyCloneError(t *testing.T) {
	tests := []struct {
		name   string
		stderr string
		want   error
	}{
		{
			name:   "branch not found from remote branch message",
			stderr: "fatal: Remote branch feature-x not found in upstream origin",
			want:   ErrBranchNotFound,
		},
		{
			name:   "branch not found from valid branch message",
			stderr: "fatal: 'feature-x' is not a valid branch name",
			want:   ErrBranchNotFound,
		},
		{
			name:   "auth required",
			stderr: "fatal: could not read Username for 'https://github.com': terminal prompts disabled",
			want:   ErrAuthRequired,
		},
		{
			name:   "repo not found",
			stderr: "remote: Repository not found.",
			want:   ErrRepoNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := classifyCloneError(context.Background(), tt.stderr, errors.New("exit status 128"))
			if !errors.Is(err, tt.want) {
				t.Fatalf("expected %v, got %v", tt.want, err)
			}
		})
	}
}

func TestClassifyCloneErrorTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	<-ctx.Done()

	err := classifyCloneError(ctx, "clone still running", context.DeadlineExceeded)
	if !errors.Is(err, ErrCloneTimeout) {
		t.Fatalf("expected %v, got %v", ErrCloneTimeout, err)
	}
}

func TestCloneTimeoutFromEnv(t *testing.T) {
	t.Setenv("GIT_CLONE_TIMEOUT", "3s")
	if got := cloneTimeoutFromEnv(); got != 3*time.Second {
		t.Fatalf("duration env: expected 3s, got %s", got)
	}

	t.Setenv("GIT_CLONE_TIMEOUT", "7")
	if got := cloneTimeoutFromEnv(); got != 7*time.Second {
		t.Fatalf("seconds env: expected 7s, got %s", got)
	}

	t.Setenv("GIT_CLONE_TIMEOUT", "invalid")
	if got := cloneTimeoutFromEnv(); got != defaultCloneTimeout {
		t.Fatalf("invalid env: expected default %s, got %s", defaultCloneTimeout, got)
	}

	if err := os.Unsetenv("GIT_CLONE_TIMEOUT"); err != nil {
		t.Fatal(err)
	}
	if got := cloneTimeoutFromEnv(); got != defaultCloneTimeout {
		t.Fatalf("unset env: expected default %s, got %s", defaultCloneTimeout, got)
	}
}
