package mediumscan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	dockerrunner "go-server/docker"
	mediumspb "go-server/gen/mediumscan"
	db "go-server/internal/database/sqlc"
	advancedscan "go-server/internal/services/scan_tools/advanced_scan"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

type parsedFinding struct {
	Severity    db.SeverityLevel
	Title       string
	Host        string
	Port        int32
	Fingerprint string
}

type stdoutJSONLResult struct {
	ExitCode   int
	ShadowRows []string
}

func (s *mediumScanServer) executeStepChain(chain []stepSpec) {
	if len(chain) == 0 {
		return
	}

	var pipedLines []string
	for idx, spec := range chain {
		stepID := spec.StepID
		jobID := spec.JobID
		toolName := spec.ToolRow.ToolName

		startedAt := time.Now().UTC()
		if !s.markStepRunning(stepID, jobID, spec.StepUUID, startedAt) {
			continue
		}
		s.publishLog(stepID, toolName, mediumspb.LogSource_LOG_SOURCE_SYSTEM, "starting docker container with gVisor runtime")

		prepared, planErr := buildMediumInvocationForStep(spec.ToolRow, spec.TargetValue, spec.Flags, pipedLines, spec.JobID, spec.StepID)
		if planErr != nil {
			s.finalizeStepFailure(stepID, jobID, toolName, spec.StepUUID, -1, "", fmt.Sprintf("failed to build medium invocation: %v", planErr))
			s.markRemainingSkipped(chain, idx+1, fmt.Sprintf("previous step %s failed", stepID))
			return
		}
		if prepared.Note != "" {
			s.publishLog(stepID, toolName, mediumspb.LogSource_LOG_SOURCE_SYSTEM, prepared.Note)
		}
		preparedShadow, shadowErr := advancedscan.PrepareShadowOutput(spec.ToolRow, jobID, stepID)
		if shadowErr != nil {
			s.finalizeStepFailure(stepID, jobID, toolName, spec.StepUUID, -1, "", fmt.Sprintf("failed to prepare shadow output: %v", shadowErr))
			s.markRemainingSkipped(chain, idx+1, fmt.Sprintf("previous step %s failed", stepID))
			return
		}
		if preparedShadow.Enabled {
			// Shadow args are appended after the validated plan so tool-specific output wiring
			// stays consistent across advanced and medium execution paths.
			prepared.Plan.Args = append(prepared.Plan.Args, preparedShadow.AddedArgs...)
		}

		timeout := spec.ExecutionTimeout
		if timeout <= 0 {
			timeout = s.resolveExecutionTimeout(0, 0, ToolConfig{})
		}
		execCtx, cancel := context.WithTimeout(context.Background(), timeout)
		switch advancedscan.ResolveToolOutputClass(spec.ToolRow) {
		case advancedscan.ToolOutputClassStdoutJSONL:
			streamResult, runErr := s.runStdoutJSONLStep(execCtx, spec, prepared.Plan, preparedShadow, timeout, prepared.Files)
			cancel()

			exitCode := int64(-1)
			if streamResult != nil {
				exitCode = int64(streamResult.ExitCode)
			}

			finalStatus := mediumspb.ScanStatus_SCAN_STATUS_COMPLETED
			finalErr := ""
			if runErr != nil {
				finalStatus = mediumspb.ScanStatus_SCAN_STATUS_FAILED
				finalErr = runErr.Error()
			} else if exitCode != 0 {
				finalStatus = mediumspb.ScanStatus_SCAN_STATUS_FAILED
				finalErr = fmt.Sprintf("tool exited with non-zero code: %d", exitCode)
			}

			finished := time.Now().UTC()
			s.mu.Lock()
			if step, ok := s.steps[stepID]; ok {
				step.Status = finalStatus
				step.FinishedAt = &finished
				step.ExitCode = exitCode
				step.Error = finalErr
				step.ArtifactPath = ""
			}
			s.recomputeJobStatusLocked(jobID)
			s.mu.Unlock()
			_ = s.syncStepTerminalStatusToDB(spec.StepUUID, finalStatus)
			go s.syncJobStatusToDB(jobID)

			var shadow *advancedscan.CapturedShadowOutput
			if streamResult != nil && len(streamResult.ShadowRows) > 0 {
				shadow = &advancedscan.CapturedShadowOutput{
					Format:        preparedShadow.Format,
					Parser:        preparedShadow.Parser,
					Transport:     preparedShadow.Transport,
					HostPath:      preparedShadow.HostPath,
					ContainerPath: preparedShadow.ContainerPath,
					Content:       []byte(strings.Join(streamResult.ShadowRows, "\n")),
				}
			}

			findingsCount, persistErr := s.persistStepResult(spec, finalStatus, startedAt, finished, prepared.Plan, nil, shadow, runErr)
			if persistErr != nil {
				s.publishLog(stepID, toolName, mediumspb.LogSource_LOG_SOURCE_SYSTEM, fmt.Sprintf("failed to persist step results: %v", persistErr))
			} else {
				s.mu.Lock()
				if step, ok := s.steps[stepID]; ok {
					step.Findings = findingsCount
				}
				s.mu.Unlock()
			}

			if finalStatus == mediumspb.ScanStatus_SCAN_STATUS_COMPLETED {
				shouldGenerate := false
				s.mu.RLock()
				if job, ok := s.jobs[jobID]; ok && job.Status == mediumspb.JobStatus_JOB_STATUS_COMPLETED {
					shouldGenerate = true
				}
				s.mu.RUnlock()
				if shouldGenerate {
					go s.generateSuggestionsForJob(spec.JobUUID)
				}
				s.publishLog(stepID, toolName, mediumspb.LogSource_LOG_SOURCE_SYSTEM, fmt.Sprintf("scan step completed (exit_code=%d)", exitCode))
				if shadow != nil {
					pipedLines = advancedscan.ExtractPipelineOutputs(spec.ToolRow, string(shadow.Content))
				} else {
					pipedLines = nil
				}
				continue
			}

			s.publishLog(stepID, toolName, mediumspb.LogSource_LOG_SOURCE_SYSTEM, fmt.Sprintf("scan step failed: %s", finalErr))
			s.markRemainingSkipped(chain, idx+1, fmt.Sprintf("previous step %s failed", stepID))
			return

		default:
			result, runErr := s.runner.Run(execCtx, dockerrunner.ToolConfig{
				Image:       prepared.Plan.ImageRef,
				Command:     prepared.Plan.Command,
				Args:        prepared.Plan.Args,
				Files:       prepared.Files,
				Volumes:     preparedShadow.Volumes,
				Timeout:     timeout,
				UseGVisor:   true,
				NetworkMode: "bridge",
				OnLog: func(source, line string) {
					switch source {
					case "stderr":
						s.publishLog(stepID, toolName, mediumspb.LogSource_LOG_SOURCE_STDERR, line)
					default:
						s.publishLog(stepID, toolName, mediumspb.LogSource_LOG_SOURCE_STDOUT, line)
					}
				},
			})
			cancel()

			exitCode := int64(-1)
			if result != nil {
				exitCode = int64(result.ExitCode)
			}

			capturedShadow, captureErr := advancedscan.CaptureShadowOutput(preparedShadow, "")
			if result != nil {
				capturedShadow, captureErr = advancedscan.CaptureShadowOutput(preparedShadow, result.Stdout)
			}
			if captureErr != nil {
				s.publishLog(stepID, toolName, mediumspb.LogSource_LOG_SOURCE_SYSTEM, fmt.Sprintf("failed to capture shadow output: %v", captureErr))
			}

			artifactPath, artifactErr := s.writeShadowArtifact(spec.JobID, spec.StepID, toolName, prepared.Plan, result, &capturedShadow, runErr)
			if artifactErr != nil {
				s.publishLog(stepID, toolName, mediumspb.LogSource_LOG_SOURCE_SYSTEM, fmt.Sprintf("failed to write shadow artifact: %v", artifactErr))
			} else {
				s.publishLog(stepID, toolName, mediumspb.LogSource_LOG_SOURCE_SYSTEM, fmt.Sprintf("shadow artifact saved: %s", artifactPath))
			}

			finalStatus := mediumspb.ScanStatus_SCAN_STATUS_COMPLETED
			finalErr := ""
			if runErr != nil {
				finalStatus = mediumspb.ScanStatus_SCAN_STATUS_FAILED
				finalErr = runErr.Error()
			} else if exitCode != 0 {
				finalStatus = mediumspb.ScanStatus_SCAN_STATUS_FAILED
				finalErr = fmt.Sprintf("tool exited with non-zero code: %d", exitCode)
			}

			finished := time.Now().UTC()
			s.mu.Lock()
			if step, ok := s.steps[stepID]; ok {
				step.Status = finalStatus
				step.FinishedAt = &finished
				step.ExitCode = exitCode
				step.Error = finalErr
				step.ArtifactPath = artifactPath
			}
			s.recomputeJobStatusLocked(jobID)
			s.mu.Unlock()
			_ = s.syncStepTerminalStatusToDB(spec.StepUUID, finalStatus)
			go s.syncJobStatusToDB(jobID)

			findingsCount, persistErr := s.persistStepResult(spec, finalStatus, startedAt, finished, prepared.Plan, result, &capturedShadow, runErr)
			if persistErr != nil {
				s.publishLog(stepID, toolName, mediumspb.LogSource_LOG_SOURCE_SYSTEM, fmt.Sprintf("failed to persist step results: %v", persistErr))
			} else {
				s.mu.Lock()
				if step, ok := s.steps[stepID]; ok {
					step.Findings = findingsCount
				}
				s.mu.Unlock()
			}

			if finalStatus == mediumspb.ScanStatus_SCAN_STATUS_COMPLETED {
				shouldGenerate := false
				s.mu.RLock()
				if job, ok := s.jobs[jobID]; ok && job.Status == mediumspb.JobStatus_JOB_STATUS_COMPLETED {
					shouldGenerate = true
				}
				s.mu.RUnlock()
				if shouldGenerate {
					go s.generateSuggestionsForJob(spec.JobUUID)
				}
				s.publishLog(stepID, toolName, mediumspb.LogSource_LOG_SOURCE_SYSTEM, fmt.Sprintf("scan step completed (exit_code=%d)", exitCode))
				pipedLines = advancedscan.ExtractPipelineOutputs(spec.ToolRow, advancedscan.CanonicalStepOutput(result, capturedShadow))
				continue
			}

			s.publishLog(stepID, toolName, mediumspb.LogSource_LOG_SOURCE_SYSTEM, fmt.Sprintf("scan step failed: %s", finalErr))
			s.markRemainingSkipped(chain, idx+1, fmt.Sprintf("previous step %s failed", stepID))
			return
		}
	}
}

func (s *mediumScanServer) resolveExecutionTimeout(stepTimeoutSeconds, requestTimeoutSeconds int32, cfg ToolConfig) time.Duration {
	timeout := durationFromSeconds(stepTimeoutSeconds)
	if timeout <= 0 {
		timeout = durationFromSeconds(requestTimeoutSeconds)
	}
	if timeout <= 0 {
		timeout = durationFromSeconds(cfg.ScanConfig.Medium.DefaultRuntimeTimeoutSeconds)
	}
	if timeout <= 0 {
		timeout = s.executionTimeout
	}
	if timeout <= 0 {
		timeout = 15 * time.Minute
	}
	if s.maxExecutionTimeout > 0 && timeout > s.maxExecutionTimeout {
		timeout = s.maxExecutionTimeout
	}
	return timeout
}

func (s *mediumScanServer) runStdoutJSONLStep(
	ctx context.Context,
	spec stepSpec,
	plan *invocationPlan,
	preparedShadow advancedscan.PreparedShadowOutput,
	timeout time.Duration,
	files []dockerrunner.ContainerFile,
) (*stdoutJSONLResult, error) {
	shadowRows := make([]string, 0, 128)
	exitCode, err := s.runner.RunStreamed(ctx, dockerrunner.ToolConfig{
		Image:       plan.ImageRef,
		Command:     plan.Command,
		Args:        plan.Args,
		Files:       files,
		Volumes:     preparedShadow.Volumes,
		Timeout:     timeout,
		UseGVisor:   true,
		NetworkMode: "bridge",
	}, dockerrunner.StreamedCallbacks{
		OnStdoutLine: func(line string) {
			trimmed := stringsTrim(line)
			if trimmed == "" {
				return
			}
			if strings.HasPrefix(trimmed, "{") {
				shadowRows = append(shadowRows, trimmed)
				formatted := advancedscan.FormatStructuredLogLine(trimmed, spec.ToolRow)
				if formatted == "" {
					formatted = trimmed
				}
				s.publishLog(spec.StepID, spec.ToolRow.ToolName, mediumspb.LogSource_LOG_SOURCE_STDOUT, formatted)
				return
			}
			s.publishLog(spec.StepID, spec.ToolRow.ToolName, mediumspb.LogSource_LOG_SOURCE_STDOUT, trimmed)
		},
		OnStderrLine: func(line string) {
			s.publishLog(spec.StepID, spec.ToolRow.ToolName, mediumspb.LogSource_LOG_SOURCE_STDERR, line)
		},
	})
	if len(shadowRows) == 0 && preparedShadow.FallbackToStdout {
		return &stdoutJSONLResult{ExitCode: exitCode}, err
	}
	return &stdoutJSONLResult{
		ExitCode:   exitCode,
		ShadowRows: shadowRows,
	}, err
}

func (s *mediumScanServer) writeShadowArtifact(jobID, stepID, toolName string, plan *invocationPlan, result *dockerrunner.ToolResult, shadow *advancedscan.CapturedShadowOutput, runErr error) (string, error) {
	if err := os.MkdirAll(s.artifactRoot, 0o755); err != nil {
		return "", err
	}
	filename := fmt.Sprintf("%s_%s_%d.json", jobID, stepID, time.Now().UTC().Unix())
	path := filepath.Join(s.artifactRoot, filename)

	artifact := map[string]any{
		"job_id":     jobID,
		"step_id":    stepID,
		"tool_name":  toolName,
		"image_ref":  plan.ImageRef,
		"command":    plan.Command,
		"args":       plan.Args,
		"created_at": time.Now().UTC().Format(time.RFC3339Nano),
	}
	if result != nil {
		artifact["exit_code"] = result.ExitCode
		artifact["stdout"] = result.Stdout
		artifact["stderr"] = result.Stderr
		artifact["duration_ms"] = result.Duration.Milliseconds()
	}
	if shadow != nil && (len(shadow.Content) > 0 || shadow.HostPath != "") {
		artifact["shadow_output"] = map[string]any{
			"format":               shadow.Format,
			"parser":               shadow.Parser,
			"transport":            shadow.Transport,
			"host_path":            shadow.HostPath,
			"container_path":       shadow.ContainerPath,
			"used_stdout_fallback": shadow.UsedStdoutFallback,
			"content":              string(shadow.Content),
		}
	}
	if runErr != nil {
		artifact["error"] = runErr.Error()
	}

	b, err := json.MarshalIndent(artifact, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		return "", err
	}
	return path, nil
}

func (s *mediumScanServer) finalizeStepFailure(stepID, jobID, toolName string, stepUUID uuid.UUID, exitCode int64, artifactPath, errorMessage string) {
	finished := time.Now().UTC()
	s.mu.Lock()
	if step, ok := s.steps[stepID]; ok {
		if step.StartedAt == nil {
			started := finished
			step.StartedAt = &started
		}
		step.Status = mediumspb.ScanStatus_SCAN_STATUS_FAILED
		step.FinishedAt = &finished
		step.ExitCode = exitCode
		step.Error = errorMessage
		step.ArtifactPath = artifactPath
	}
	s.recomputeJobStatusLocked(jobID)
	s.mu.Unlock()
	_ = s.syncStepTerminalStatusToDB(stepUUID, mediumspb.ScanStatus_SCAN_STATUS_FAILED)
	go s.syncJobStatusToDB(jobID)
	s.publishLog(stepID, toolName, mediumspb.LogSource_LOG_SOURCE_SYSTEM, fmt.Sprintf("scan step failed: %s", errorMessage))
}

func (s *mediumScanServer) markRemainingSkipped(chain []stepSpec, from int, reason string) {
	if from >= len(chain) {
		return
	}

	now := time.Now().UTC()
	type skippedStep struct {
		stepID   string
		toolName string
		stepUUID uuid.UUID
	}
	skipped := make([]skippedStep, 0, len(chain)-from)

	s.mu.Lock()
	for i := from; i < len(chain); i++ {
		spec := chain[i]
		step, ok := s.steps[spec.StepID]
		if !ok || isTerminalStepStatus(step.Status) {
			continue
		}
		step.Status = mediumspb.ScanStatus_SCAN_STATUS_SKIPPED
		step.FinishedAt = &now
		step.Error = reason
		skipped = append(skipped, skippedStep{
			stepID:   step.StepID,
			toolName: step.ToolName,
			stepUUID: spec.StepUUID,
		})
	}
	s.recomputeJobStatusLocked(chain[0].JobID)
	s.mu.Unlock()

	for _, step := range skipped {
		_ = s.syncStepTerminalStatusToDB(step.stepUUID, mediumspb.ScanStatus_SCAN_STATUS_SKIPPED)
	}
	go s.syncJobStatusToDB(chain[0].JobID)

	for _, step := range skipped {
		s.publishLog(step.stepID, step.toolName, mediumspb.LogSource_LOG_SOURCE_SYSTEM, fmt.Sprintf("step skipped: %s", reason))
	}
}

func (s *mediumScanServer) persistStepResult(
	spec stepSpec,
	stepStatus mediumspb.ScanStatus,
	startedAt, finishedAt time.Time,
	plan *invocationPlan,
	result *dockerrunner.ToolResult,
	shadow *advancedscan.CapturedShadowOutput,
	runErr error,
) (int32, error) {
	rawPayload := map[string]any{
		"job_id":     spec.JobID,
		"step_id":    spec.StepID,
		"tool_name":  spec.ToolRow.ToolName,
		"image_ref":  plan.ImageRef,
		"command":    plan.Command,
		"args":       plan.Args,
		"created_at": finishedAt.Format(time.RFC3339Nano),
	}
	rawForParsing := ""
	if result != nil {
		rawPayload["exit_code"] = result.ExitCode
		rawPayload["stdout"] = result.Stdout
		rawPayload["stderr"] = result.Stderr
		rawPayload["duration_ms"] = result.Duration.Milliseconds()
		rawForParsing = result.Stdout
	}
	if shadow != nil {
		rawForParsing = advancedscan.CanonicalStepOutput(result, *shadow)
		if len(shadow.Content) > 0 || shadow.HostPath != "" {
			rawPayload["shadow_output"] = map[string]any{
				"format":               shadow.Format,
				"parser":               shadow.Parser,
				"transport":            shadow.Transport,
				"host_path":            shadow.HostPath,
				"container_path":       shadow.ContainerPath,
				"used_stdout_fallback": shadow.UsedStdoutFallback,
				"content":              string(shadow.Content),
			}
		}
	}
	if runErr != nil {
		rawPayload["error"] = runErr.Error()
	}
	rawData, err := json.Marshal(rawPayload)
	if err != nil {
		return 0, err
	}

	rawLines := extractPipeLines(rawForParsing)
	parsedOutput := advancedscan.ParseToolOutput(spec.ToolRow, rawForParsing, rawLines)
	findings := convertParsedFindings(parsedOutput)
	fallbackLines := advancedscan.ExtractPipelineOutputs(spec.ToolRow, rawForParsing)
	if len(findings) == 0 {
		findings = parseFindingsFromStdout(spec.ToolRow.ToolName, fallbackLines)
	}
	if len(fallbackLines) == 0 {
		fallbackLines = normalizePipelineLines(rawLines)
	}

	parsedPayload := map[string]any{
		"line_count": len(rawLines),
		"lines":      fallbackLines,
	}
	if parsedOutput != nil {
		parsedPayload["tool_name"] = parsedOutput.ToolName
		parsedPayload["parse_method"] = parsedOutput.ParseMethod
		parsedPayload["line_count"] = parsedOutput.LineCount
		parsedPayload["findings_count"] = len(findings)
		if len(parsedOutput.StructuredData) > 0 {
			parsedPayload["data"] = parsedOutput.StructuredData
		}
	}
	parsedData, err := json.Marshal(parsedPayload)
	if err != nil {
		return 0, err
	}

	severity := db.NullSeverityLevel{Valid: false}
	if len(findings) > 0 {
		severityLevel := db.SeverityLevelInfo
		if parsedOutput != nil && len(parsedOutput.Findings) > 0 {
			severityLevel = advancedscan.HighestSeverity(parsedOutput.Findings)
		}
		severity = db.NullSeverityLevel{SeverityLevel: severityLevel, Valid: true}
	}
	resultRow, err := s.queries.CreateScanResult(context.Background(), db.CreateScanResultParams{
		StepID:     spec.StepUUID,
		JobID:      spec.JobUUID,
		ProjectID:  spec.ProjectUUID,
		TargetID:   spec.TargetUUID,
		ToolID:     spec.ToolRow.ToolID,
		RawData:    rawData,
		ParsedData: parsedData,
		Severity:   severity,
		Status: db.NullScanStepStatus{
			ScanStepStatus: protoStepStatusToDB(stepStatus),
			Valid:          true,
		},
		StartedAt:  pgtype.Timestamptz{Time: startedAt, Valid: true},
		FinishedAt: pgtype.Timestamptz{Time: finishedAt, Valid: true},
	})
	if err != nil {
		return 0, err
	}

	var upserted int32
	for _, f := range findings {
		title := pgtype.Text{}
		if f.Title != "" {
			title = pgtype.Text{String: f.Title, Valid: true}
		}
		host := pgtype.Text{}
		if f.Host != "" {
			host = pgtype.Text{String: f.Host, Valid: true}
		}
		port := pgtype.Int4{}
		if f.Port > 0 {
			port = pgtype.Int4{Int32: f.Port, Valid: true}
		}
		fp := pgtype.Text{String: f.Fingerprint, Valid: true}
		if _, err := s.queries.UpsertFinding(context.Background(), db.UpsertFindingParams{
			ProjectID:   spec.ProjectUUID,
			JobID:       spec.JobUUID,
			StepID:      spec.StepUUID,
			ToolID:      spec.ToolRow.ToolID,
			Severity:    db.NullSeverityLevel{SeverityLevel: f.Severity, Valid: true},
			Title:       title,
			Host:        host,
			Port:        port,
			Fingerprint: fp,
			RawResultID: pgtype.UUID{Bytes: resultRow.ResultID, Valid: true},
		}); err != nil {
			return upserted, err
		}
		upserted++
	}

	return upserted, nil
}

func convertParsedFindings(parsedOutput *advancedscan.ParsedOutput) []parsedFinding {
	if parsedOutput == nil || len(parsedOutput.Findings) == 0 {
		return nil
	}

	out := make([]parsedFinding, 0, len(parsedOutput.Findings))
	for _, finding := range parsedOutput.Findings {
		out = append(out, parsedFinding{
			Severity:    finding.Severity,
			Title:       finding.Title,
			Host:        finding.Host,
			Port:        finding.Port,
			Fingerprint: finding.Fingerprint,
		})
	}
	return out
}

func parseFindingsFromStdout(toolName string, lines []string) []parsedFinding {
	out := make([]parsedFinding, 0, len(lines))
	for _, line := range lines {
		host, port := parseHostPort(line)
		title := line
		if len(title) > 500 {
			title = title[:500]
		}
		sum := sha256.Sum256([]byte(strings.ToLower(stringsTrim(toolName)) + "|" + line))
		out = append(out, parsedFinding{
			Severity:    db.SeverityLevelInfo,
			Title:       title,
			Host:        host,
			Port:        port,
			Fingerprint: hex.EncodeToString(sum[:]),
		})
	}
	return out
}

func parseHostPort(line string) (string, int32) {
	trimmed := stringsTrim(line)
	if trimmed == "" {
		return "", 0
	}
	if u, err := url.Parse(trimmed); err == nil && u.Host != "" {
		host := u.Hostname()
		portText := u.Port()
		if portText == "" {
			return host, 0
		}
		port, err := strconv.Atoi(portText)
		if err != nil {
			return host, 0
		}
		return host, int32(port)
	}
	host, portText, err := net.SplitHostPort(trimmed)
	if err != nil {
		return trimmed, 0
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return host, 0
	}
	return host, int32(port)
}

func extractPipeLines(stdout string) []string {
	lines := strings.Split(stdout, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := stringsTrim(strings.TrimRight(line, "\r"))
		if trimmed == "" {
			continue
		}
		out = append(out, trimmed)
	}
	return out
}
