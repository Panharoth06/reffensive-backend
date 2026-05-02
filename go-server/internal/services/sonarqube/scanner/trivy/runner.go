package trivy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	scanlogging "go-server/internal/services/sonarqube/scanner/logging"

	"github.com/rs/zerolog"
)

const defaultTimeout = 20 * time.Minute

// Run executes Trivy scanner with automatic database update fallback.
// If database update fails (network issue), retries with --skip-update flag for offline mode.
func Run(ctx context.Context, sourceDir, outFile string) error {
	sourceDir = strings.TrimSpace(sourceDir)
	outFile = strings.TrimSpace(outFile)
	if sourceDir == "" {
		return errors.New("trivy source directory is required")
	}
	if outFile == "" {
		return errors.New("trivy output file is required")
	}

	runCtx, cancel := context.WithTimeout(ctx, timeoutFromEnv())
	defer cancel()

	// First attempt: try with database update (normal mode)
	cmd := exec.CommandContext(runCtx, "trivy", runnerArgs(sourceDir, outFile, false)...)
	stdout, stderr, waitErr := runCommand(runCtx, ctx, cmd, "trivy")
	err := waitErr
	if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("trivy timed out: %w", runCtx.Err())
	}

	// If database download failed, retry with --skip-update flag for offline mode
	if err != nil && (isDatabaseDownloadError(stderr.String()) || isDatabaseDownloadError(stdout.String())) {
		scanlogging.Warn(ctx, "Trivy database download failed; retrying in offline mode")
		return retryWithOfflineMode(runCtx, sourceDir, outFile)
	}

	if err == nil {
		return nil
	}
	return fmt.Errorf(
		"trivy failed with exit code %d: %w\nstdout: %s\nstderr: %s",
		exitCode(err),
		err,
		strings.TrimSpace(stdout.String()),
		strings.TrimSpace(stderr.String()),
	)
}

// retryWithOfflineMode retries Trivy scan in offline mode (skip-update) using cached database
func retryWithOfflineMode(ctx context.Context, sourceDir, outFile string) error {
	cmd := exec.CommandContext(ctx, "trivy", runnerArgs(sourceDir, outFile, true)...)
	stdout, stderr, err := runCommand(ctx, ctx, cmd, "trivy")
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("trivy timed out in offline mode: %w", ctx.Err())
	}
	if err == nil {
		return nil
	}
	return fmt.Errorf(
		"trivy failed in offline mode with exit code %d: %w\nstdout: %s\nstderr: %s",
		exitCode(err),
		err,
		strings.TrimSpace(stdout.String()),
		strings.TrimSpace(stderr.String()),
	)
}

// isDatabaseDownloadError checks if the error message indicates a database download failure
func isDatabaseDownloadError(output string) bool {
	if output == "" {
		return false
	}
	output = strings.ToLower(output)
	return strings.Contains(output, "could not download") ||
		strings.Contains(output, "database") ||
		strings.Contains(output, "failed to download") ||
		strings.Contains(output, "network") ||
		strings.Contains(output, "connection") ||
		strings.Contains(output, "offline")
}

func runnerArgs(sourceDir, outFile string, skipUpdate bool) []string {
	args := []string{
		"fs", sourceDir,
		"--format", "json",
		"--output", outFile,
		"--security-checks", "vuln,license",
		"--exit-code", "0",
	}
	if skipUpdate {
		args = append(args, "--skip-update")
	}
	return args
}

func timeoutFromEnv() time.Duration {
	raw := strings.TrimSpace(os.Getenv("TRIVY_TIMEOUT"))
	if raw == "" {
		return defaultTimeout
	}
	if parsed, err := time.ParseDuration(raw); err == nil && parsed > 0 {
		return parsed
	}

	if seconds, err := strconv.Atoi(raw); err == nil && seconds > 0 {
		return time.Duration(seconds) * time.Second
	}
	return defaultTimeout
}

func exitCode(err error) int {
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		return -1
	}
	if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
		return status.ExitStatus()
	}
	return exitErr.ExitCode()
}

func runCommand(runCtx, logCtx context.Context, cmd *exec.Cmd, name string) (bytes.Buffer, bytes.Buffer, error) {
	var stdoutBuf bytes.Buffer
	var stderrBuf bytes.Buffer

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return stdoutBuf, stderrBuf, fmt.Errorf("open %s stdout: %w", name, err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return stdoutBuf, stderrBuf, fmt.Errorf("open %s stderr: %w", name, err)
	}
	if err := cmd.Start(); err != nil {
		return stdoutBuf, stderrBuf, fmt.Errorf("start %s: %w", name, err)
	}

	log := zerolog.Ctx(logCtx)
	if log.GetLevel() == zerolog.Disabled {
		fallback := zerolog.New(os.Stdout).With().Timestamp().Logger()
		log = &fallback
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go pipeCommandOutput(logCtx, &wg, log, name, "stdout", io.TeeReader(stdout, &stdoutBuf))
	go pipeCommandOutput(logCtx, &wg, log, name, "stderr", io.TeeReader(stderr, &stderrBuf))

	err = cmd.Wait()
	wg.Wait()
	if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
		return stdoutBuf, stderrBuf, runCtx.Err()
	}
	return stdoutBuf, stderrBuf, err
}

func pipeCommandOutput(ctx context.Context, wg *sync.WaitGroup, log *zerolog.Logger, commandName, stream string, reader io.Reader) {
	defer wg.Done()

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()
		event := log.Info()
		if stream == "stderr" {
			scanlogging.Error(ctx, line)
			event = log.Error()
		} else {
			scanlogging.Info(ctx, line)
		}
		event.Str("command", commandName).Str("stream", stream).Msg(line)
	}
	if err := scanner.Err(); err != nil {
		if errors.Is(err, os.ErrClosed) || strings.Contains(strings.ToLower(err.Error()), "file already closed") {
			return
		}
		scanlogging.Error(ctx, fmt.Sprintf("failed to read %s %s: %v", commandName, stream, err))
		log.Error().Err(err).Str("command", commandName).Str("stream", stream).Msg("failed to read command output")
	}
}
