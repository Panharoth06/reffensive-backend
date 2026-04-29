package sonar

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
	"time"

	scanlogging "go-server/internal/services/sonarqube/scanner/logging"

	"github.com/rs/zerolog"
)

const (
	defaultScannerBin = "sonar-scanner"
	defaultTimeout    = 20 * time.Minute
)

type runnerConfig struct {
	scannerBin           string
	hostURL              string
	token                string
	timeout              time.Duration
	enableBranchAnalysis bool
	jsNodeMaxSpace       string
}

func Run(ctx context.Context, sourceDir, projectKey, branch string) error {
	cfg, err := runnerConfigFromEnv()
	if err != nil {
		return err
	}

	sourceDir = strings.TrimSpace(sourceDir)
	projectKey = strings.TrimSpace(projectKey)
	branch = strings.TrimSpace(branch)
	if sourceDir == "" {
		return errors.New("sonar source directory is required")
	}
	if projectKey == "" {
		return errors.New("sonar project key is required")
	}
	if branch == "" {
		return errors.New("sonar branch is required")
	}

	log := zerolog.Ctx(ctx)
	if log.GetLevel() == zerolog.Disabled {
		fallback := zerolog.New(os.Stdout).With().Timestamp().Logger()
		log = &fallback
	}

	err = runScannerAttempt(ctx, cfg, log, sourceDir, projectKey, branch, cfg.enableBranchAnalysis)
	if err == nil {
		return nil
	}

	if !cfg.enableBranchAnalysis || !branchAnalysisUnsupported(err) {
		return err
	}

	scanlogging.Warn(ctx, "SonarQube does not support branch analysis; retrying without sonar.branch.name")
	log.Warn().Str("branch", branch).Msg("SonarQube does not support branch analysis; retrying without sonar.branch.name")
	return runScannerAttempt(ctx, cfg, log, sourceDir, projectKey, branch, false)
}

func scannerArgs(sourceDir, projectKey, branch, hostURL, token string, includeBranch bool, jsNodeMaxSpace string) []string {
	args := []string{
		"-Dsonar.projectKey=" + projectKey,
		"-Dsonar.projectBaseDir=" + sourceDir,
		"-Dsonar.sources=" + sourceDir,
		"-Dsonar.working.directory=.scannerwork",
		"-Dsonar.host.url=" + hostURL,
		"-Dsonar.token=" + token,
	}
	if includeBranch && strings.TrimSpace(branch) != "" {
		args = append(args, "-Dsonar.branch.name="+branch)
	}
	if strings.TrimSpace(jsNodeMaxSpace) != "" {
		args = append(args, "-Dsonar.javascript.node.maxspace="+jsNodeMaxSpace)
	}
	return args
}

func runnerConfigFromEnv() (runnerConfig, error) {
	cfg := runnerConfig{
		scannerBin:           firstEnv(defaultScannerBin, "SONAR_SCANNER_BIN"),
		hostURL:              strings.TrimRight(firstEnv("", "SONAR_HOST_URL", "SONARQUBE_HOST", "SONARQUBE_BASE_URL"), "/"),
		token:                firstEnv("", "SONAR_TOKEN", "SONARQUBE_TOKEN"),
		timeout:              timeoutFromEnv(),
		enableBranchAnalysis: branchAnalysisEnabledFromEnv(),
		jsNodeMaxSpace:       jsNodeMaxSpaceFromEnv(),
	}
	if strings.TrimSpace(cfg.hostURL) == "" {
		return runnerConfig{}, errors.New("sonar host URL is required: set SONAR_HOST_URL or SONARQUBE_HOST")
	}
	if strings.TrimSpace(cfg.token) == "" {
		return runnerConfig{}, errors.New("sonar token is required: set SONAR_TOKEN or SONARQUBE_TOKEN")
	}
	return cfg, nil
}

func firstEnv(fallback string, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(os.Getenv(key)); value != "" {
			return value
		}
	}
	return fallback
}

func timeoutFromEnv() time.Duration {
	for _, key := range []string{"SONAR_TIMEOUT", "SONAR_TIMEOUT_SECONDS", "SONAR_SCAN_TIMEOUT_SECONDS"} {
		raw := strings.TrimSpace(os.Getenv(key))
		if raw == "" {
			continue
		}
		if parsed, err := time.ParseDuration(raw); err == nil && parsed > 0 {
			return parsed
		}
		if seconds, err := strconv.Atoi(raw); err == nil && seconds > 0 {
			return time.Duration(seconds) * time.Second
		}
	}
	return defaultTimeout
}

func branchAnalysisEnabledFromEnv() bool {
	raw := strings.TrimSpace(firstEnv("", "SONAR_ENABLE_BRANCH_ANALYSIS", "SONARQUBE_ENABLE_BRANCH_ANALYSIS"))
	if raw == "" {
		return false
	}
	enabled, err := strconv.ParseBool(raw)
	if err != nil {
		return false
	}
	return enabled
}

func jsNodeMaxSpaceFromEnv() string {
	raw := strings.TrimSpace(firstEnv("", "SONAR_JS_NODE_MAXSPACE", "SONAR_JAVASCRIPT_NODE_MAXSPACE"))
	if raw == "" {
		return "4096"
	}
	if _, err := strconv.Atoi(raw); err != nil {
		return "4096"
	}
	return raw
}

func runScannerAttempt(
	ctx context.Context,
	cfg runnerConfig,
	log *zerolog.Logger,
	sourceDir, projectKey, branch string,
	includeBranch bool,
) error {
	runCtx, cancel := context.WithTimeout(ctx, cfg.timeout)
	defer cancel()

	args := scannerArgs(sourceDir, projectKey, branch, cfg.hostURL, cfg.token, includeBranch, cfg.jsNodeMaxSpace)
	cmd := exec.CommandContext(runCtx, cfg.scannerBin, args...)
	cmd.Dir = sourceDir

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("open sonar-scanner stdout: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("open sonar-scanner stderr: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start sonar-scanner: %w", err)
	}

	var wg sync.WaitGroup
	var stdoutBuf bytes.Buffer
	var stderrBuf bytes.Buffer
	wg.Add(2)
	go pipeScannerOutput(ctx, &wg, log, "stdout", io.TeeReader(stdout, &stdoutBuf))
	go pipeScannerOutput(ctx, &wg, log, "stderr", io.TeeReader(stderr, &stderrBuf))

	waitErr := cmd.Wait()
	wg.Wait()

	if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("sonar-scanner timed out after %s", cfg.timeout)
	}
	if waitErr != nil {
		return fmt.Errorf(
			"sonar-scanner failed: %w\nstdout: %s\nstderr: %s",
			waitErr,
			strings.TrimSpace(stdoutBuf.String()),
			strings.TrimSpace(stderrBuf.String()),
		)
	}
	return nil
}

func branchAnalysisUnsupported(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "sonar.branch.name") &&
		strings.Contains(message, "developer edition or above is required")
}

func pipeScannerOutput(ctx context.Context, wg *sync.WaitGroup, log *zerolog.Logger, stream string, reader io.Reader) {
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
		scanlogging.Error(ctx, fmt.Sprintf("failed to read sonar-scanner %s: %v", stream, err))
		log.Error().Err(err).Str("stream", stream).Msg("failed to read sonar-scanner output")
	}
}
