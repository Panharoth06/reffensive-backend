package advancedscan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	advancedpb "go-server/gen/advanced"
	db "go-server/internal/database/sqlc"
	redisutil "go-server/redis"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (s *advancedScanServer) SubmitScan(ctx context.Context, req *advancedpb.SubmitScanRequest) (*advancedpb.SubmitScanResponse, error) {
	if stringsTrim(req.GetProjectId()) == "" {
		return nil, status.Error(codes.InvalidArgument, "project_id is required")
	}
	if _, err := uuid.Parse(req.GetProjectId()); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid project_id: %v", err)
	}
	if stringsTrim(req.GetIdempotencyKey()) == "" {
		req.IdempotencyKey = uuid.NewString()
	}

	submittedSteps, derivedTargetValue, err := s.normalizeSubmittedStepsForRequest(ctx, req)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid tools payload: %v", err)
	}
	if err := validateAdvancedStepCount(len(submittedSteps)); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	if stringsTrim(req.GetTargetId()) == "" && stringsTrim(req.GetTargetValue()) == "" {
		if derivedTargetValue != "" {
			req.TargetValue = derivedTargetValue
		} else {
			return nil, status.Error(codes.InvalidArgument, "target_value is required (or provide target_id)")
		}
	}

	requestHash, err := idempotencyHashForRequest(req)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to process idempotency payload: %v", err)
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
	s.idempotent[idempotencyKey] = &idempotencyEntry{RequestHash: requestHash, CreatedAt: time.Now().UTC()}
	s.mu.Unlock()

	chain := make([]chainStepSpec, 0, len(submittedSteps))
	for i, item := range submittedSteps {
		toolRow, resolveErr := s.resolveTool(ctx, &advancedpb.SubmitScanRequest{
			ToolName: item.ToolName,
			ToolId:   item.ToolID,
		})
		if resolveErr != nil {
			s.mu.Lock()
			delete(s.idempotent, idempotencyKey)
			s.mu.Unlock()
			return nil, resolveErr
		}
		if _, parseErr := ParseCustomFlagsFromRaw(item.RawCustomFlags); parseErr != nil {
			s.mu.Lock()
			delete(s.idempotent, idempotencyKey)
			s.mu.Unlock()
			return nil, status.Errorf(codes.InvalidArgument, "invalid custom_flags for tools[%d]: %v", i, parseErr)
		}

		chain = append(chain, chainStepSpec{
			ToolRow:        toolRow,
			ToolArgs:       cloneStringMap(item.ToolArgs),
			RawCustomFlags: append([]string(nil), item.RawCustomFlags...),
		})
	}

	if stringsTrim(req.GetJobId()) != "" {
		if _, err := uuid.Parse(stringsTrim(req.GetJobId())); err != nil {
			s.mu.Lock()
			delete(s.idempotent, idempotencyKey)
			s.mu.Unlock()
			return nil, status.Errorf(codes.InvalidArgument, "invalid job_id: %v", err)
		}
	}
	if stringsTrim(req.GetStepId()) != "" {
		if _, err := uuid.Parse(stringsTrim(req.GetStepId())); err != nil {
			s.mu.Lock()
			delete(s.idempotent, idempotencyKey)
			s.mu.Unlock()
			return nil, status.Errorf(codes.InvalidArgument, "invalid step_id: %v", err)
		}
	}

	projectUUID, _ := uuid.Parse(req.GetProjectId())
	projectRow, err := s.queries.GetProjectByIDInternal(ctx, projectUUID)
	if err != nil {
		s.mu.Lock()
		delete(s.idempotent, idempotencyKey)
		s.mu.Unlock()
		return nil, status.Errorf(codes.NotFound, "project_id %q not found: %v", req.GetProjectId(), err)
	}
	if err := requireAuthorizedProject(ctx, projectRow.ProjectID, projectRow.UserID); err != nil {
		s.mu.Lock()
		delete(s.idempotent, idempotencyKey)
		s.mu.Unlock()
		return nil, err
	}
	targetUUID, _, err := s.resolveOrCreateTargetForProject(ctx, projectUUID, req)
	if err != nil {
		s.mu.Lock()
		delete(s.idempotent, idempotencyKey)
		s.mu.Unlock()
		return nil, err
	}
	apiKeyUUID, err := apiKeyUUIDFromContext(ctx)
	if err != nil {
		s.mu.Lock()
		delete(s.idempotent, idempotencyKey)
		s.mu.Unlock()
		return nil, err
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
		s.mu.Lock()
		delete(s.idempotent, idempotencyKey)
		s.mu.Unlock()
		return nil, status.Errorf(codes.Internal, "failed to create scan job: %v", err)
	}

	jobID := jobRow.JobID.String()
	var previousStepUUID pgtype.UUID
	for i := range chain {
		stepKey := buildStepKey(i+1, chain[i].ToolRow.ToolName)
		toolVersion := pgtype.Text{}
		if chain[i].ToolRow.VersionID != uuid.Nil {
			toolVersion = pgtype.Text{
				String: chain[i].ToolRow.VersionID.String(),
				Valid:  true,
			}
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
			StepKey:     stepKey,
			StepOrder:   int32(i + 1),
		})
		if stepErr != nil {
			s.mu.Lock()
			delete(s.idempotent, idempotencyKey)
			s.mu.Unlock()
			return nil, status.Errorf(codes.Internal, "failed to create scan step %d: %v", i+1, stepErr)
		}
		_, _ = s.queries.UpdateScanStepStatus(ctx, db.UpdateScanStepStatusParams{
			StepID: stepRow.StepID,
			Status: db.NullScanStepStatus{
				ScanStepStatus: db.ScanStepStatusPending,
				Valid:          true,
			},
		})

		chain[i].StepID = stepRow.StepID.String()
		chain[i].StepUUID = stepRow.StepID
		chain[i].JobID = jobID
		chain[i].JobUUID = jobRow.JobID
		chain[i].ProjectUUID = projectUUID
		chain[i].TargetUUID = targetUUID
		previousStepUUID = pgtype.UUID{Bytes: stepRow.StepID, Valid: true}
	}
	firstStepID := chain[0].StepID

	now := time.Now().UTC()
	resp := &advancedpb.SubmitScanResponse{
		JobId:              jobID,
		StepId:             firstStepID,
		Status:             advancedpb.StepStatus_STEP_STATUS_QUEUED,
		IsIdempotentReplay: false,
		QueuedAt:           timestamppb.New(now),
	}

	s.mu.Lock()
	j, ok := s.jobs[jobID]
	if !ok {
		j = &jobRuntime{
			JobID:     jobID,
			ProjectID: req.GetProjectId(),
			Status:    advancedpb.JobStatus_JOB_STATUS_PENDING,
			CreatedAt: now,
		}
		s.jobs[jobID] = j
	}
	for i := range chain {
		spec := chain[i]
		j.StepIDs = append(j.StepIDs, spec.StepID)
		s.steps[spec.StepID] = &stepRuntime{
			StepID:       spec.StepID,
			JobID:        jobID,
			ToolName:     spec.ToolRow.ToolName,
			Status:       advancedpb.StepStatus_STEP_STATUS_QUEUED,
			QueuedAt:     now,
			CommandPlan:  nil,
			Logs:         make([]*advancedpb.LogChunk, 0, 128),
			SequenceNum:  0,
			ArtifactPath: "",
		}
	}
	if entry, ok := s.idempotent[idempotencyKey]; ok {
		entry.Response = cloneSubmitResponse(resp)
	}
	s.mu.Unlock()

	for i, spec := range chain {
		s.publishLog(spec.StepID, spec.ToolRow.ToolName, advancedpb.LogSource_LOG_SOURCE_SYSTEM, fmt.Sprintf("step queued (order=%d)", i+1))
	}

	// Build queue payload
	queuePayload := &redisutil.ScanJobPayload{
		JobID:       jobID,
		JobUUID:     jobRow.JobID,
		ProjectID:   req.GetProjectId(),
		TargetUUID:  targetUUID.String(),
		TargetValue: req.GetTargetValue(),
		SubmittedAt: now,
		ServiceName: "advanced",
	}

	executionConfigJSON, err := marshalQueuedProtoMessage(req.GetExecutionConfig())
	if err != nil {
		s.mu.Lock()
		delete(s.idempotent, idempotencyKey)
		s.mu.Unlock()
		return nil, status.Errorf(codes.Internal, "failed to encode execution_config: %v", err)
	}
	shadowConfigJSON, err := marshalQueuedProtoMessage(req.GetShadowConfig())
	if err != nil {
		s.mu.Lock()
		delete(s.idempotent, idempotencyKey)
		s.mu.Unlock()
		return nil, status.Errorf(codes.Internal, "failed to encode shadow_config: %v", err)
	}
	queuePayload.ExecutionConfigJSON = executionConfigJSON
	queuePayload.ShadowConfigJSON = shadowConfigJSON

	for i := range chain {
		inputStepID := ""
		if i > 0 {
			inputStepID = chain[i-1].StepUUID.String()
		}
		queuePayload.Steps = append(queuePayload.Steps, redisutil.StepPayload{
			StepID:         chain[i].StepID,
			StepUUID:       chain[i].StepUUID.String(),
			InputStepID:    inputStepID,
			ToolName:       chain[i].ToolRow.ToolName,
			ToolID:         chain[i].ToolRow.ToolID.String(),
			ToolArgs:       chain[i].ToolArgs,
			RawCustomFlags: chain[i].RawCustomFlags,
			StepOrder:      i + 1,
		})
	}

	// Enqueue job (with capacity check) via the shared queue manager
	qm := redisutil.GetManager()
	if err := qm.EnqueueWithCapacityCheck(ctx, queuePayload); err != nil {
		// Check if the queue is full
		if errors.Is(err, redisutil.ErrQueueFull) {
			// Return a QUEUE_FULL response instead of an error
			resp.Status = advancedpb.StepStatus_STEP_STATUS_QUEUE_FULL
			// Suggest retry in 60 seconds
			resp.RetryAfterSeconds = 60
			return resp, nil
		}
		s.mu.Lock()
		delete(s.idempotent, idempotencyKey)
		s.mu.Unlock()
		return nil, status.Errorf(codes.Internal, "failed to enqueue scan job: %v", err)
	}

	// Update in-memory state to reflect queued status
	s.mu.Lock()
	if j, ok := s.jobs[jobID]; ok {
		j.Status = advancedpb.JobStatus_JOB_STATUS_QUEUED
	}
	for i := range chain {
		if step, ok := s.steps[chain[i].StepID]; ok {
			step.Status = advancedpb.StepStatus_STEP_STATUS_QUEUED
		}
	}
	s.mu.Unlock()

	return resp, nil
}

func (s *advancedScanServer) resolveOrCreateTargetForProject(ctx context.Context, projectUUID uuid.UUID, req *advancedpb.SubmitScanRequest) (uuid.UUID, db.Target, error) {
	targetIDText := stringsTrim(req.GetTargetId())
	targetValue := stringsTrim(req.GetTargetValue())
	if targetValue == "" && targetIDText != "" {
		if _, err := uuid.Parse(targetIDText); err != nil {
			// Backward-compatible fallback: treat non-UUID target_id as target value.
			targetValue = targetIDText
			targetIDText = ""
		}
	}

	if targetIDText != "" {
		targetUUID, err := uuid.Parse(targetIDText)
		if err != nil {
			return uuid.Nil, db.Target{}, status.Errorf(codes.InvalidArgument, "invalid target_id: %v", err)
		}
		targetRow, err := s.queries.GetTargetByID(ctx, targetUUID)
		if err != nil {
			return uuid.Nil, db.Target{}, status.Errorf(codes.NotFound, "target_id %q not found: %v", targetIDText, err)
		}
		if targetRow.ProjectID != projectUUID {
			return uuid.Nil, db.Target{}, status.Error(codes.InvalidArgument, "target_id does not belong to project_id")
		}
		return targetUUID, targetRow, nil
	}

	if targetValue == "" {
		return uuid.Nil, db.Target{}, status.Error(codes.InvalidArgument, "target_value is required")
	}

	targets, err := s.queries.ListTargetsByProject(ctx, projectUUID)
	if err != nil {
		return uuid.Nil, db.Target{}, status.Errorf(codes.Internal, "failed to list targets: %v", err)
	}
	incomingCmp := comparableTargetValue(targetValue)
	for _, existing := range targets {
		if comparableTargetValue(existing.Name) == incomingCmp {
			return existing.TargetID, existing, nil
		}
	}

	created, err := s.queries.CreateTarget(ctx, db.CreateTargetParams{
		ProjectID: projectUUID,
		Name:      targetValue,
		Type:      inferTargetType(targetValue),
		Description: pgtype.Text{
			Valid: false,
		},
	})
	if err != nil {
		return uuid.Nil, db.Target{}, status.Errorf(codes.Internal, "failed to create target: %v", err)
	}
	return created.TargetID, created, nil
}

func comparableTargetValue(v string) string {
	trimmed := strings.TrimSpace(v)
	trimmed = strings.TrimRight(trimmed, "/")
	return strings.ToLower(trimmed)
}

func inferTargetType(v string) string {
	trimmed := strings.TrimSpace(v)
	if trimmed == "" {
		return "domain"
	}
	if strings.Contains(trimmed, "://") {
		return "url"
	}
	if _, _, err := net.ParseCIDR(trimmed); err == nil {
		return "cidr"
	}
	if ip := net.ParseIP(trimmed); ip != nil {
		return "ip"
	}
	return "domain"
}

func cloneStringMap(src map[string]string) map[string]string {
	if len(src) == 0 {
		return map[string]string{}
	}
	out := make(map[string]string, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}
