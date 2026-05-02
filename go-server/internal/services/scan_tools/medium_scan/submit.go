package mediumscan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	mediumspb "go-server/gen/mediumscan"
	db "go-server/internal/database/sqlc"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (s *mediumScanServer) SubmitScan(ctx context.Context, req *mediumspb.MediumScanSubmitRequest) (*mediumspb.MediumScanSubmitResponse, error) {
	if stringsTrim(req.GetProjectId()) == "" {
		return nil, status.Error(codes.InvalidArgument, "project_id is required")
	}
	projectUUID, err := uuid.Parse(req.GetProjectId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid project_id: %v", err)
	}
	if stringsTrim(req.GetTargetId()) == "" && stringsTrim(req.GetTargetValue()) == "" {
		return nil, status.Error(codes.InvalidArgument, "target_value is required (or provide target_id)")
	}

	submittedSteps, err := normalizeSubmittedStepsForRequest(req)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid steps payload: %v", err)
	}
	if len(submittedSteps) == 0 {
		return nil, status.Error(codes.InvalidArgument, "at least one tool is required")
	}
	if stringsTrim(req.GetIdempotencyKey()) == "" {
		req.IdempotencyKey = uuid.NewString()
	}

	requestHash, err := idempotencyHashForRequest(req)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to hash idempotency payload: %v", err)
	}
	idempotencyKey := stringsTrim(req.GetIdempotencyKey())

	s.mu.Lock()
	if entry, ok := s.idempotent[idempotencyKey]; ok {
		if entry.RequestHash != requestHash {
			s.mu.Unlock()
			return nil, status.Error(codes.AlreadyExists, "idempotency_key already exists with different request payload")
		}
		if entry.Response == nil {
			s.mu.Unlock()
			return nil, status.Error(codes.Aborted, "request with this idempotency_key is in progress, retry shortly")
		}
		replay := cloneSubmitResponse(entry.Response)
		replay.IsIdempotentReplay = true
		replay.OriginalRequestId = entry.Response.StepId
		s.mu.Unlock()
		return replay, nil
	}
	s.idempotent[idempotencyKey] = &idempotencyEntry{RequestHash: requestHash}
	s.mu.Unlock()

	projectRow, err := s.queries.GetProjectByIDInternal(ctx, projectUUID)
	if err != nil {
		s.deleteIdempotency(idempotencyKey)
		return nil, status.Errorf(codes.NotFound, "project_id %q not found: %v", req.GetProjectId(), err)
	}

	if err := requireAuthorizedMediumProject(ctx, projectRow.ProjectID.String(), projectRow.UserID.String()); err != nil {
		s.deleteIdempotency(idempotencyKey)
		return nil, err
	}

	targetUUID, targetRow, err := s.resolveOrCreateTargetForProject(ctx, projectUUID, req.GetTargetId(), req.GetTargetValue())
	if err != nil {
		s.deleteIdempotency(idempotencyKey)
		return nil, err
	}
	apiKeyUUID, err := apiKeyUUIDFromContext(ctx)
	if err != nil {
		s.deleteIdempotency(idempotencyKey)
		return nil, err
	}

	targetValue := stringsTrim(targetRow.Name)

	chain := make([]stepSpec, 0, len(submittedSteps))
	for i, item := range submittedSteps {
		toolRow, resolveErr := s.resolveTool(ctx, item.ToolID, item.ToolName)
		if resolveErr != nil {
			s.deleteIdempotency(idempotencyKey)
			return nil, resolveErr
		}

		userOptions, decodeErr := decodeMediumOptionValues(item.ToolOptions)
		if decodeErr != nil {
			s.deleteIdempotency(idempotencyKey)
			return nil, status.Errorf(codes.InvalidArgument, "invalid tool_options for steps[%d]: %v", i, decodeErr)
		}
		cfg, cfgErr := decodeMediumToolConfig(toolRow.ScanConfig)
		if cfgErr != nil {
			s.deleteIdempotency(idempotencyKey)
			return nil, status.Errorf(codes.Internal, "invalid tool scan_config for steps[%d]: %v", i, cfgErr)
		}
		flags, flagsErr := BuildMediumScanFlags(cfg, userOptions)
		if flagsErr != nil {
			s.deleteIdempotency(idempotencyKey)
			return nil, status.Errorf(codes.InvalidArgument, "invalid medium options for steps[%d]: %v", i, flagsErr)
		}

		chain = append(chain, stepSpec{
			ToolRow:          toolRow,
			TargetValue:      targetValue,
			Flags:            append([]string(nil), flags...),
			ExecutionTimeout: s.resolveExecutionTimeout(item.RuntimeTimeoutSeconds, req.GetRuntimeTimeoutSeconds(), cfg),
		})
	}

	jobRow, err := s.queries.CreateScanJob(ctx, db.CreateScanJobParams{
		ProjectID: projectUUID,
		TargetID:  targetUUID,
		TriggeredBy: pgtype.UUID{
			Bytes: projectRow.UserID,
			Valid: true,
		},
		ApiKeyID: apiKeyUUID,
		ExecutionMode: db.NullExecutionMode{
			ExecutionMode: requestExecutionModeToDB(req.GetExecutionMode()),
			Valid:         true,
		},
	})
	if err != nil {
		s.deleteIdempotency(idempotencyKey)
		return nil, status.Errorf(codes.Internal, "failed to create scan job: %v", err)
	}

	now := time.Now().UTC()
	jobID := jobRow.JobID.String()

	var previousStepUUID pgtype.UUID
	for i := range chain {
		toolVersion := pgtype.Text{}
		if chain[i].ToolRow.VersionID != uuid.Nil {
			toolVersion = pgtype.Text{String: chain[i].ToolRow.VersionID.String(), Valid: true}
		}
		inputSource := db.InputSourceTypeTarget
		if i > 0 {
			inputSource = db.InputSourceTypeStep
		}
		stepRow, stepErr := s.queries.CreateScanStep(ctx, db.CreateScanStepParams{
			JobID:       jobRow.JobID,
			ToolID:      chain[i].ToolRow.ToolID,
			ToolVersion: toolVersion,
			InputSource: inputSource,
			InputStepID: previousStepUUID,
			StepKey:     buildStepKey(i+1, chain[i].ToolRow.ToolName),
			StepOrder:   int32(i + 1),
		})
		if stepErr != nil {
			s.deleteIdempotency(idempotencyKey)
			return nil, status.Errorf(codes.Internal, "failed to create scan step %d: %v", i+1, stepErr)
		}
		_, _ = s.queries.UpdateScanStepStatus(ctx, db.UpdateScanStepStatusParams{
			StepID: stepRow.StepID,
			Status: db.NullScanStepStatus{ScanStepStatus: db.ScanStepStatusPending, Valid: true},
		})

		chain[i].StepID = stepRow.StepID.String()
		chain[i].JobID = jobID
		chain[i].StepUUID = stepRow.StepID
		chain[i].JobUUID = jobRow.JobID
		chain[i].ProjectUUID = projectUUID
		chain[i].TargetUUID = targetUUID
		previousStepUUID = pgtype.UUID{Bytes: stepRow.StepID, Valid: true}
	}
	firstStepID := chain[0].StepID

	s.mu.Lock()
	s.jobs[jobID] = &jobRuntime{
		JobID:     jobID,
		ProjectID: req.GetProjectId(),
		Status:    mediumspb.JobStatus_JOB_STATUS_PENDING,
		CreatedAt: now,
		StepIDs:   make([]string, 0, len(chain)),
	}
	for _, spec := range chain {
		s.jobs[jobID].StepIDs = append(s.jobs[jobID].StepIDs, spec.StepID)
		s.steps[spec.StepID] = &stepRuntime{
			StepID:       spec.StepID,
			JobID:        jobID,
			ToolName:     spec.ToolRow.ToolName,
			TargetValue:  targetValue,
			Status:       mediumspb.ScanStatus_SCAN_STATUS_QUEUED,
			QueuedAt:     now,
			AppliedFlags: append([]string(nil), spec.Flags...),
			Logs:         make([]*mediumspb.LogChunk, 0, 128),
		}
	}
	resp := &mediumspb.MediumScanSubmitResponse{
		JobId:              jobID,
		StepId:             firstStepID,
		Status:             mediumspb.ScanStatus_SCAN_STATUS_QUEUED,
		IsIdempotentReplay: false,
		QueuedAt:           timestamppb.New(now),
	}
	if entry, ok := s.idempotent[idempotencyKey]; ok {
		entry.Response = cloneSubmitResponse(resp)
	}
	s.mu.Unlock()

	for i, spec := range chain {
		s.publishLog(spec.StepID, spec.ToolRow.ToolName, mediumspb.LogSource_LOG_SOURCE_SYSTEM, fmt.Sprintf("step queued (order=%d)", i+1))
	}

	go s.executeStepChain(chain)

	return resp, nil
}

func normalizeSubmittedStepsForRequest(req *mediumspb.MediumScanSubmitRequest) ([]submittedStepInput, error) {
	if req.GetRuntimeTimeoutSeconds() < 0 {
		return nil, fmt.Errorf("runtime_timeout_seconds must be positive")
	}

	steps := req.GetSteps()
	if len(steps) > 0 {
		if stringsTrim(req.GetToolId()) != "" || stringsTrim(req.GetToolName()) != "" || len(req.GetToolOptions()) > 0 {
			return nil, fmt.Errorf("use either steps or legacy tool fields, not both")
		}

		out := make([]submittedStepInput, 0, len(steps))
		for i, step := range steps {
			if step == nil {
				return nil, fmt.Errorf("steps[%d] is required", i)
			}
			if step.GetRuntimeTimeoutSeconds() < 0 {
				return nil, fmt.Errorf("steps[%d].runtime_timeout_seconds must be positive", i)
			}
			if stringsTrim(step.GetToolId()) == "" && stringsTrim(step.GetToolName()) == "" {
				return nil, fmt.Errorf("steps[%d] requires tool_name or tool_id", i)
			}
			out = append(out, submittedStepInput{
				ToolID:                step.GetToolId(),
				ToolName:              step.GetToolName(),
				ToolOptions:           cloneMediumOptionMap(step.GetToolOptions()),
				RuntimeTimeoutSeconds: step.GetRuntimeTimeoutSeconds(),
			})
		}
		return out, nil
	}

	if stringsTrim(req.GetToolName()) == "" && stringsTrim(req.GetToolId()) == "" {
		return nil, fmt.Errorf("tool_name is required (or provide tool_id)")
	}
	return []submittedStepInput{{
		ToolID:                req.GetToolId(),
		ToolName:              req.GetToolName(),
		ToolOptions:           cloneMediumOptionMap(req.GetToolOptions()),
		RuntimeTimeoutSeconds: req.GetRuntimeTimeoutSeconds(),
	}}, nil
}

func cloneSubmitResponse(src *mediumspb.MediumScanSubmitResponse) *mediumspb.MediumScanSubmitResponse {
	if src == nil {
		return nil
	}
	return &mediumspb.MediumScanSubmitResponse{
		JobId:              src.JobId,
		StepId:             src.StepId,
		Status:             src.Status,
		IsIdempotentReplay: src.IsIdempotentReplay,
		OriginalRequestId:  src.OriginalRequestId,
		QueuedAt:           src.QueuedAt,
	}
}

func idempotencyHashForRequest(req *mediumspb.MediumScanSubmitRequest) (string, error) {
	clone := proto.Clone(req).(*mediumspb.MediumScanSubmitRequest)
	clone.IdempotencyKey = ""
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(clone)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func (s *mediumScanServer) deleteIdempotency(key string) {
	s.mu.Lock()
	delete(s.idempotent, key)
	s.mu.Unlock()
}
