package advancedscan

import (
	"context"
	"fmt"
	"strings"
	"time"

	dockerrunner "go-server/docker"
	advancedpb "go-server/gen/advanced"

	"github.com/google/uuid"
)

func (s *advancedScanServer) executeStepChain(req *advancedpb.SubmitScanRequest, chain []chainStepSpec) {
	defer func() {
		if r := recover(); r != nil {
			if len(chain) > 0 {
				stepID := chain[0].StepID
				jobID := chain[0].JobID
				toolName := chain[0].ToolRow.ToolName
				s.publishLog(stepID, toolName, advancedpb.LogSource_LOG_SOURCE_SYSTEM, fmt.Sprintf("scan execution panicked: %v", r))
				s.finalizeStepFailure(stepID, jobID, toolName, chain[0].StepUUID, -1, "", fmt.Sprintf("scan execution panicked: %v", r))
				s.markRemainingSkipped(chain, 1, "previous step panicked")
			}
		}
	}()

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

		scanConfig, scanCfgErr := parseScanConfig(spec.ToolRow.ScanConfig)
		if scanCfgErr != nil {
			s.finalizeStepFailure(stepID, jobID, toolName, spec.StepUUID, -1, "", fmt.Sprintf("invalid scan_config for tool %q: %v", toolName, scanCfgErr))
			s.markRemainingSkipped(chain, idx+1, fmt.Sprintf("previous step %s failed", stepID))
			return
		}
		useGVisor, networkMode, privileged, runtimeCapabilities, runtimeErr := resolveToolRuntime(scanConfig, req.GetExecutionConfig())
		if runtimeErr != nil {
			s.finalizeStepFailure(stepID, jobID, toolName, spec.StepUUID, -1, "", fmt.Sprintf("runtime policy rejected request: %v", runtimeErr))
			s.markRemainingSkipped(chain, idx+1, fmt.Sprintf("previous step %s failed", stepID))
			return
		}
		runtimeLabel := "starting docker container"
		if useGVisor {
			runtimeLabel += " with gVisor runtime"
		}
		if networkMode != "" {
			runtimeLabel += fmt.Sprintf(" (network=%s)", networkMode)
		}
		s.publishLog(stepID, toolName, advancedpb.LogSource_LOG_SOURCE_SYSTEM, runtimeLabel)

		toolArgs := cloneStringMap(spec.ToolArgs)
		rawCustomFlags := append([]string(nil), spec.RawCustomFlags...)
		var pipelineInjectedArgs []string
		var pipelineFiles []dockerrunner.ContainerFile
		stepPipeLines := pipedLines
		if idx == 0 && spec.InputStepUUID != uuid.Nil {
			loadedPipeLines, loadErr := s.loadPipelineLinesFromStoredStep(spec.InputStepUUID)
			if loadErr != nil {
				s.finalizeStepFailure(stepID, jobID, toolName, spec.StepUUID, -1, "", fmt.Sprintf("failed to load suggested input step: %v", loadErr))
				s.markRemainingSkipped(chain, idx+1, fmt.Sprintf("previous step %s failed", stepID))
				return
			}
			stepPipeLines = loadedPipeLines
		}
		if idx > 0 || spec.InputStepUUID != uuid.Nil {
			if len(stepPipeLines) > 0 {
				s.publishLog(stepID, toolName, advancedpb.LogSource_LOG_SOURCE_SYSTEM, fmt.Sprintf("received %d piped lines from previous step", len(stepPipeLines)))
			}
			preparedInput, pipeErr := preparePipelineInput(spec.ToolRow, toolArgs, rawCustomFlags, stepPipeLines, jobID, stepID)
			if pipeErr != nil {
				s.finalizeStepFailure(stepID, jobID, toolName, spec.StepUUID, -1, "", fmt.Sprintf("failed to apply piped inputs: %v", pipeErr))
				s.markRemainingSkipped(chain, idx+1, fmt.Sprintf("previous step %s failed", stepID))
				return
			}
			toolArgs = preparedInput.ToolArgs
			rawCustomFlags = preparedInput.RawCustomFlags
			pipelineInjectedArgs = preparedInput.InjectedArgs
			pipelineFiles = preparedInput.Files
			if preparedInput.Note != "" {
				s.publishLog(stepID, toolName, advancedpb.LogSource_LOG_SOURCE_SYSTEM, preparedInput.Note)
			}
		}

		parsedFlags, flagsErr := ParseCustomFlagsFromRaw(rawCustomFlags)
		if flagsErr != nil {
			s.finalizeStepFailure(stepID, jobID, toolName, spec.StepUUID, -1, "", fmt.Sprintf("invalid custom flags: %v", flagsErr))
			s.markRemainingSkipped(chain, idx+1, fmt.Sprintf("previous step %s failed", stepID))
			return
		}

		targetForStep := ""
		if idx == 0 {
			targetForStep = req.GetTargetValue()
		}

		plan, planErr := buildAdvancedInvocation(spec.ToolRow, &advancedpb.SubmitScanRequest{
			ToolArgs:    toolArgs,
			CustomFlags: parsedFlags,
			TargetValue: targetForStep,
		}, pipelineInjectedArgs)
		if planErr != nil {
			s.finalizeStepFailure(stepID, jobID, toolName, spec.StepUUID, -1, "", fmt.Sprintf("advanced policy rejected request: %v", planErr))
			s.markRemainingSkipped(chain, idx+1, fmt.Sprintf("previous step %s failed", stepID))
			return
		}

		s.mu.Lock()
		if step, ok := s.steps[stepID]; ok {
			step.CommandPlan = plan
		}
		s.mu.Unlock()

		preparedShadow, shadowErr := prepareShadowOutput(spec.ToolRow, jobID, stepID)
		if shadowErr != nil {
			s.finalizeStepFailure(stepID, jobID, toolName, spec.StepUUID, -1, "", fmt.Sprintf("failed to prepare shadow output: %v", shadowErr))
			s.markRemainingSkipped(chain, idx+1, fmt.Sprintf("previous step %s failed", stepID))
			return
		}
		if preparedShadow.Enabled {
			plan.Args = append(plan.Args, preparedShadow.AddedArgs...)
		}
		if len(pipelineInjectedArgs) > 0 {
			plan.Args = append(plan.Args, pipelineInjectedArgs...)
		}

		timeout := 5 * time.Minute
		if req.GetExecutionConfig() != nil && req.GetExecutionConfig().GetTimeoutSeconds() > 0 {
			timeout = time.Duration(req.GetExecutionConfig().GetTimeoutSeconds()) * time.Second
		}
		execCtx, cancel := context.WithTimeout(context.Background(), timeout)

		memoryLimit := int64(0)
		cpuQuota := int64(0)
		if req.GetExecutionConfig() != nil && req.GetExecutionConfig().GetResourceLimits() != nil {
			rl := req.GetExecutionConfig().GetResourceLimits()
			memoryLimit = rl.GetMemoryLimitBytes()
			cpuQuota = nanoCPULimitToQuota(rl.GetCpuLimitNano())
		}

		// Determine how the tool delivers its structured output and dispatch the
		// appropriate execution path.
		switch resolveOutputClass(spec.ToolRow) {

		// ── ClassStdoutJSONL ────────────────────────────────────────────────
		// Tools that write JSONL on stdout (subfinder, httpx, nuclei, katana …).
		// We fan out each line to SSE + shadow buffer + pipe list in real time.
		// No shadow file on disk; no post-run buffering.
		case ClassStdoutJSONL:
			streamResult, streamErr := s.runStdoutJSONLStep(
				execCtx, spec, plan, preparedShadow,
				timeout, memoryLimit, cpuQuota,
				useGVisor, networkMode, privileged, runtimeCapabilities,
				pipelineFiles,
			)
			cancel()

			exitCode := int64(-1)
			if streamResult != nil {
				exitCode = int64(streamResult.ExitCode)
			}

			finalStatus := advancedpb.StepStatus_STEP_STATUS_COMPLETED
			finalErr := ""
			if streamErr != nil {
				finalStatus = advancedpb.StepStatus_STEP_STATUS_FAILED
				finalErr = streamErr.Error()
			} else if exitCode != 0 {
				finalStatus = advancedpb.StepStatus_STEP_STATUS_FAILED
				finalErr = fmt.Sprintf("tool exited with non-zero code: %d", exitCode)
			}

			finished := time.Now().UTC()
			s.mu.Lock()
			if step, ok := s.steps[stepID]; ok {
				step.Status = finalStatus
				step.FinishedAt = &finished
				step.ExitCode = exitCode
				step.Error = finalErr
			}
			s.recomputeJobStatusLocked(jobID)
			s.mu.Unlock()
			s.syncStepTerminalStatusToDB(spec.StepUUID, finalStatus)
			s.syncJobStatusToDB(jobID)

			// Persist structured rows collected during streaming.
			var shadowRows []string
			if streamResult != nil {
				shadowRows = streamResult.ShadowRows
			}
			findingsCount, persistErr := s.persistJSONLShadow(
				context.Background(), spec, finalStatus,
				startedAt, finished, plan,
				shadowRows, int(exitCode), streamErr,
			)
			if persistErr != nil {
				s.publishLog(stepID, toolName, advancedpb.LogSource_LOG_SOURCE_SYSTEM,
					fmt.Sprintf("failed to persist step results: %v", persistErr))
			} else {
				s.mu.Lock()
				if step, ok := s.steps[stepID]; ok {
					step.Findings = findingsCount
					step.HasParsedData = true
				}
				s.mu.Unlock()
			}

			if finalStatus == advancedpb.StepStatus_STEP_STATUS_COMPLETED {
				shouldGenerate := false
				s.mu.RLock()
				if job, ok := s.jobs[jobID]; ok && job.Status == advancedpb.JobStatus_JOB_STATUS_COMPLETED {
					shouldGenerate = true
				}
				s.mu.RUnlock()
				if shouldGenerate {
					go s.generateSuggestionsForJob(spec.JobUUID)
				}
				s.publishLog(stepID, toolName, advancedpb.LogSource_LOG_SOURCE_SYSTEM,
					fmt.Sprintf("scan step completed (exit_code=%d)", exitCode))
				// Pipe lines were already deduplicated during streaming.
				if streamResult != nil {
					pipedLines = streamResult.PipeLines
				} else {
					pipedLines = nil
				}
				continue
			}

			s.publishLog(stepID, toolName, advancedpb.LogSource_LOG_SOURCE_SYSTEM,
				fmt.Sprintf("scan step failed: %s", finalErr))
			s.markRemainingSkipped(chain, idx+1, fmt.Sprintf("previous step %s failed", stepID))
			return

		// ── ClassFileOnly ───────────────────────────────────────────────────
		// Tools that write structured output to a file flag (-oX, -oJ …).
		// Stdout is streamed to SSE as human log lines; structured data is
		// read from the bind-mounted shadow file after the container exits.
		default:
			fileResult, fileErr := s.runFileOnlyStep(
				execCtx, spec, plan, preparedShadow,
				timeout, memoryLimit, cpuQuota,
				useGVisor, networkMode, privileged, runtimeCapabilities,
				pipelineFiles,
			)
			cancel()

			var result *dockerrunner.ToolResult
			var capturedShadow capturedShadowOutput
			if fileResult != nil {
				result = fileResult.DockerResult
				capturedShadow = fileResult.Shadow
			}

			exitCode := int64(-1)
			if result != nil {
				exitCode = int64(result.ExitCode)
			}

			artifactPath, artifactErr := s.writeShadowArtifact(req.GetShadowConfig(), jobID, stepID, toolName, plan, result, capturedShadow, fileErr)
			if artifactErr != nil {
				s.publishLog(stepID, toolName, advancedpb.LogSource_LOG_SOURCE_SYSTEM,
					fmt.Sprintf("failed to write shadow artifact: %v", artifactErr))
			} else {
				s.publishLog(stepID, toolName, advancedpb.LogSource_LOG_SOURCE_SYSTEM,
					fmt.Sprintf("shadow artifact saved: %s", artifactPath))
			}

			finalStatus := advancedpb.StepStatus_STEP_STATUS_COMPLETED
			finalErr := ""
			if fileErr != nil {
				finalStatus = advancedpb.StepStatus_STEP_STATUS_FAILED
				finalErr = fileErr.Error()
			} else if exitCode != 0 {
				finalStatus = advancedpb.StepStatus_STEP_STATUS_FAILED
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
			s.syncStepTerminalStatusToDB(spec.StepUUID, finalStatus)
			s.syncJobStatusToDB(jobID)

			findingsCount, persistErr := s.persistStepResult(spec, finalStatus, startedAt, finished, plan, result, capturedShadow, fileErr)
			if persistErr != nil {
				s.publishLog(stepID, toolName, advancedpb.LogSource_LOG_SOURCE_SYSTEM,
					fmt.Sprintf("failed to persist step results: %v", persistErr))
			} else {
				s.mu.Lock()
				if step, ok := s.steps[stepID]; ok {
					step.Findings = findingsCount
					step.HasParsedData = true
				}
				s.mu.Unlock()
			}

			if finalStatus == advancedpb.StepStatus_STEP_STATUS_COMPLETED {
				shouldGenerate := false
				s.mu.RLock()
				if job, ok := s.jobs[jobID]; ok && job.Status == advancedpb.JobStatus_JOB_STATUS_COMPLETED {
					shouldGenerate = true
				}
				s.mu.RUnlock()
				if shouldGenerate {
					go s.generateSuggestionsForJob(spec.JobUUID)
				}
				s.publishLog(stepID, toolName, advancedpb.LogSource_LOG_SOURCE_SYSTEM,
					fmt.Sprintf("scan step completed (exit_code=%d)", exitCode))
				canonicalOutput := canonicalStepOutput(result, capturedShadow)
				if stringsTrim(canonicalOutput) == "" {
					pipedLines = nil
				} else {
					pipedLines = extractPipelineOutputs(spec.ToolRow, canonicalOutput)
				}
				continue
			}

			s.publishLog(stepID, toolName, advancedpb.LogSource_LOG_SOURCE_SYSTEM,
				fmt.Sprintf("scan step failed: %s", finalErr))
			s.markRemainingSkipped(chain, idx+1, fmt.Sprintf("previous step %s failed", stepID))
			return
		}
	}
}

func (s *advancedScanServer) markStepRunning(stepID, jobID string, stepUUID uuid.UUID, startedAt time.Time) bool {
	stepCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := s.queries.StartScanStep(stepCtx, stepUUID); err != nil {
		s.mu.RLock()
		toolName := ""
		if step, ok := s.steps[stepID]; ok {
			toolName = step.ToolName
		}
		s.mu.RUnlock()
		s.publishLog(stepID, toolName, advancedpb.LogSource_LOG_SOURCE_SYSTEM, fmt.Sprintf("warning: failed to mark step running in DB: %v", err))
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	step, ok := s.steps[stepID]
	if !ok {
		return false
	}
	if isTerminalStepStatus(step.Status) {
		return false
	}

	step.Status = advancedpb.StepStatus_STEP_STATUS_RUNNING
	step.StartedAt = &startedAt
	step.Error = ""
	s.recomputeJobStatusLocked(jobID)
	go s.syncJobStatusToDB(jobID)
	return true
}

func (s *advancedScanServer) finalizeStepFailure(stepID, jobID, toolName string, stepUUID uuid.UUID, exitCode int64, artifactPath, errorMessage string) {
	finished := time.Now().UTC()
	s.mu.Lock()
	if step, ok := s.steps[stepID]; ok {
		if step.StartedAt == nil {
			started := finished
			step.StartedAt = &started
		}
		step.Status = advancedpb.StepStatus_STEP_STATUS_FAILED
		step.FinishedAt = &finished
		step.ExitCode = exitCode
		step.Error = errorMessage
		step.ArtifactPath = artifactPath
	}
	s.recomputeJobStatusLocked(jobID)
	s.mu.Unlock()
	s.syncStepTerminalStatusToDB(stepUUID, advancedpb.StepStatus_STEP_STATUS_FAILED)
	s.syncJobStatusToDB(jobID)
	s.publishLog(stepID, toolName, advancedpb.LogSource_LOG_SOURCE_SYSTEM, fmt.Sprintf("scan step failed: %s", errorMessage))
}

func (s *advancedScanServer) markRemainingSkipped(chain []chainStepSpec, from int, reason string) {
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
		step.Status = advancedpb.StepStatus_STEP_STATUS_SKIPPED
		step.FinishedAt = &now
		step.Error = reason
		skipped = append(skipped, skippedStep{
			stepID:   step.StepID,
			toolName: step.ToolName,
			stepUUID: spec.StepUUID,
		})
	}
	if len(chain) > 0 {
		s.recomputeJobStatusLocked(chain[0].JobID)
	}
	s.mu.Unlock()
	for _, step := range skipped {
		_ = s.syncStepTerminalStatusToDB(step.stepUUID, advancedpb.StepStatus_STEP_STATUS_SKIPPED)
	}
	if len(chain) > 0 {
		s.syncJobStatusToDB(chain[0].JobID)
	}

	for _, item := range skipped {
		s.publishLog(item.stepID, item.toolName, advancedpb.LogSource_LOG_SOURCE_SYSTEM, fmt.Sprintf("step skipped: %s", reason))
	}
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
