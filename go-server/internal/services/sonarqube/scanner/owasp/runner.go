package owasp

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

// defaultTimeout is the default scan timeout for OWASP Dependency-Check
// Set to 30 minutes as NVD database download can take a long time on first run
const defaultTimeout = 30 * time.Minute

// Run executes OWASP Dependency-Check with configurable timeout.
// If scan exceeds timeout, returns error to allow graceful failure rather than hanging.
func Run(ctx context.Context, sourceDir, projectKey, outDir string) error {
	sourceDir = strings.TrimSpace(sourceDir)
	projectKey = strings.TrimSpace(projectKey)
	outDir = strings.TrimSpace(outDir)
	if sourceDir == "" {
		return errors.New("owasp source directory is required")
	}
	if projectKey == "" {
		return errors.New("owasp project key is required")
	}
	if outDir == "" {
		return errors.New("owasp output directory is required")
	}

	runCtx, cancel := context.WithTimeout(ctx, timeoutFromEnv())
	defer cancel()

	cmd := exec.CommandContext(runCtx, "dependency-check.sh", runnerArgs(sourceDir, projectKey, outDir)...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("open dependency-check stdout: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("open dependency-check stderr: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start dependency-check: %w", err)
	}

	log := zerolog.Ctx(ctx)
	if log.GetLevel() == zerolog.Disabled {
		fallback := zerolog.New(os.Stdout).With().Timestamp().Logger()
		log = &fallback
	}

	var stdoutBuf bytes.Buffer
	var stderrBuf bytes.Buffer
	var wg sync.WaitGroup
	wg.Add(2)
	go pipeCommandOutput(ctx, &wg, log, "stdout", io.TeeReader(stdout, &stdoutBuf))
	go pipeCommandOutput(ctx, &wg, log, "stderr", io.TeeReader(stderr, &stderrBuf))

	err = cmd.Wait()
	wg.Wait()
	if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("dependency-check timed out after %v: %w\nConsider increasing OWASP_TIMEOUT environment variable for large projects", timeoutFromEnv(), runCtx.Err())
	}
	if err == nil || exitCode(err) == 1 {
		return nil
	}
	return fmt.Errorf(
		"dependency-check failed with exit code %d: %w\nstdout: %s\nstderr: %s",
		exitCode(err),
		err,
		strings.TrimSpace(stdoutBuf.String()),
		strings.TrimSpace(stderrBuf.String()),
	)
}

func runnerArgs(sourceDir, projectKey, outDir string) []string {
	// Use data directory from environment if set, otherwise use default
	dataDir := os.Getenv("OWASP_DATA_DIRECTORY")
	if dataDir == "" {
		dataDir = "/root/.m2/repository/org/owasp/dependency-check/data"
	}
	nvdAPIKey := firstEnv("OWASP_NVD_API_KEY", "NVD_API_KEY")

	args := []string{
		"--project", projectKey,
		"--scan", sourceDir,
		"--format", "JSON",
		"--out", outDir,
		"--data", dataDir,
		"--enableExperimental",
	}
	if nvdAPIKey != "" {
		args = append(args, "--nvdApiKey", nvdAPIKey)
	}

	// Add --updateonly flag only if update is explicitly disabled
	// By default, allow updates but with timeout protection
	return args
}

func firstEnv(keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(os.Getenv(key)); value != "" {
			return value
		}
	}
	return ""
}

func timeoutFromEnv() time.Duration {
	raw := strings.TrimSpace(os.Getenv("OWASP_TIMEOUT"))
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

func pipeCommandOutput(ctx context.Context, wg *sync.WaitGroup, log *zerolog.Logger, stream string, reader io.Reader) {
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
		event.Str("stream", stream).Msg(line)
	}
	if err := scanner.Err(); err != nil {
		if errors.Is(err, os.ErrClosed) || strings.Contains(strings.ToLower(err.Error()), "file already closed") {
			return
		}
		scanlogging.Error(ctx, fmt.Sprintf("failed to read dependency-check %s: %v", stream, err))
		log.Error().Err(err).Str("stream", stream).Msg("failed to read dependency-check output")
	}
}
