package aisuggestion

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	suggestionpb "go-server/gen/suggestion"
	db "go-server/internal/database/sqlc"
	"go-server/internal/interceptor"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	defaultAISuggestionURL = "http://localhost:8000/internal/ai/suggest"
	selectSuggestionSQL    = `
SELECT id, job_id, mode, provider, model, content, output_json, input_tokens, output_tokens, feedback, is_suggested, created_at, updated_at
FROM ai_suggestions
WHERE job_id = $1 AND mode = $2
`
	selectSuggestionByIDSQL = `
SELECT id, job_id, mode, provider, model, content, output_json, input_tokens, output_tokens, feedback, is_suggested, created_at, updated_at
FROM ai_suggestions
WHERE id = $1
`
	upsertSuggestionSQL = `
INSERT INTO ai_suggestions (job_id, mode, provider, model, content, output_json, input_tokens, output_tokens, feedback, is_suggested, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, now())
ON CONFLICT (job_id, mode)
DO UPDATE SET
    provider = EXCLUDED.provider,
    model = EXCLUDED.model,
    content = EXCLUDED.content,
    output_json = EXCLUDED.output_json,
    input_tokens = EXCLUDED.input_tokens,
    output_tokens = EXCLUDED.output_tokens,
    feedback = CASE
        WHEN ai_suggestions.feedback <> '' THEN ai_suggestions.feedback
        ELSE EXCLUDED.feedback
    END,
    is_suggested = EXCLUDED.is_suggested,
    updated_at = now()
RETURNING id, job_id, mode, provider, model, content, output_json, input_tokens, output_tokens, feedback, is_suggested, created_at, updated_at
`
	updateFeedbackSQL = `
UPDATE ai_suggestions
SET feedback = $3, updated_at = now()
WHERE job_id = $1 AND mode = $2
RETURNING id, job_id, mode, provider, model, content, output_json, input_tokens, output_tokens, feedback, is_suggested, created_at, updated_at
`
)

type suggestionServer struct {
	suggestionpb.UnimplementedSuggestionServiceServer
	store          suggestionResultStore
	httpClient     *http.Client
	aiGatewayURL   string
	internalSecret string
}

type suggestionRecord struct {
	ID           uuid.UUID
	JobID        uuid.UUID
	Mode         string
	Provider     string
	Model        string
	Content      string
	OutputJSON   []byte
	InputTokens  int32
	OutputTokens int32
	Feedback     string
	IsSuggested  bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

type aiGatewayRequest struct {
	JobID   string         `json:"job_id"`
	Mode    string         `json:"mode"`
	Context AIContextInput `json:"context"`
}

type aiGatewayResponse struct {
	Mode     string          `json:"mode"`
	Provider string          `json:"provider"`
	Model    string          `json:"model"`
	Content  string          `json:"content"`
	Output   json.RawMessage `json:"output"`
	Usage    aiUsage         `json:"usage"`
}

type aiUsage struct {
	InputTokens  int32 `json:"input_tokens"`
	OutputTokens int32 `json:"output_tokens"`
}

func NewSuggestionServer() (suggestionpb.SuggestionServiceServer, error) {
	store, err := getSuggestionResultStore()
	if err != nil {
		return nil, err
	}

	return &suggestionServer{
		store: store,
		httpClient: &http.Client{
			Timeout: 90 * time.Second,
		},
		aiGatewayURL:   envOrDefault("AI_SUGGESTION_GATEWAY_URL", defaultAISuggestionURL),
		internalSecret: strings.TrimSpace(os.Getenv("AI_SUGGESTION_INTERNAL_SECRET")),
	}, nil
}

func GenerateForJob(ctx context.Context, jobUUID uuid.UUID, mode suggestionpb.SuggestionMode) error {
	store, err := getSuggestionResultStore()
	if err != nil {
		return err
	}

	svc := &suggestionServer{
		store: store,
		httpClient: &http.Client{
			Timeout: 90 * time.Second,
		},
		aiGatewayURL:   envOrDefault("AI_SUGGESTION_GATEWAY_URL", defaultAISuggestionURL),
		internalSecret: strings.TrimSpace(os.Getenv("AI_SUGGESTION_INTERNAL_SECRET")),
	}

	modeValue, err := modeToString(mode)
	if err != nil {
		return err
	}

	contextPayload, err := newAIContextBuilder(svc.store).Build(ctx, jobUUID)
	if err != nil {
		return fmt.Errorf("build suggestion context: %w", err)
	}

	aiResp, err := svc.callAIGateway(ctx, aiGatewayRequest{
		JobID:   jobUUID.String(),
		Mode:    modeValue,
		Context: contextPayload,
	})
	if err != nil {
		return err
	}

	if _, err := svc.upsertSuggestion(ctx, jobUUID, modeValue, aiResp); err != nil {
		return fmt.Errorf("save suggestion: %w", err)
	}

	return nil
}

func (s *suggestionServer) GenerateSuggestion(ctx context.Context, req *suggestionpb.GenerateSuggestionRequest) (*suggestionpb.SuggestionResponse, error) {
	jobUUID, mode, err := parseRequest(req.GetJobId(), req.GetMode())
	if err != nil {
		return nil, err
	}

	if _, err := s.authorizeJob(ctx, jobUUID); err != nil {
		return nil, err
	}

	contextPayload, err := newAIContextBuilder(s.store).Build(ctx, jobUUID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "build suggestion context: %v", err)
	}

	aiResp, err := s.callAIGateway(ctx, aiGatewayRequest{
		JobID:   jobUUID.String(),
		Mode:    mode,
		Context: contextPayload,
	})
	if err != nil {
		return nil, err
	}

	record, err := s.upsertSuggestion(ctx, jobUUID, mode, aiResp)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "save suggestion: %v", err)
	}

	return mapSuggestionRecord(record), nil
}

func (s *suggestionServer) GetSuggestion(ctx context.Context, req *suggestionpb.GetSuggestionRequest) (*suggestionpb.SuggestionResponse, error) {
	rawID := strings.TrimSpace(req.GetSuggestionId())
	if rawID == "" {
		return nil, status.Error(codes.InvalidArgument, "suggestion_id is required")
	}

	// Backward compatibility:
	// legacy clients may still send field #1 as job_id and field #2 as mode.
	if req.GetMode() != suggestionpb.SuggestionMode_SUGGESTION_MODE_UNSPECIFIED {
		jobUUID, mode, err := parseRequest(rawID, req.GetMode())
		if err != nil {
			return nil, err
		}
		if _, err := s.authorizeJob(ctx, jobUUID); err != nil {
			return nil, err
		}

		record, err := s.getSuggestion(ctx, jobUUID, mode)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, status.Error(codes.NotFound, "suggestion not found")
			}
			return nil, status.Errorf(codes.Internal, "load suggestion: %v", err)
		}
		return mapSuggestionRecord(record), nil
	}

	suggestionUUID, err := uuid.Parse(rawID)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid suggestion_id: %v", err)
	}

	record, err := s.getSuggestionByID(ctx, suggestionUUID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, status.Error(codes.NotFound, "suggestion not found")
		}
		return nil, status.Errorf(codes.Internal, "load suggestion: %v", err)
	}

	if _, err := s.authorizeJob(ctx, record.JobID); err != nil {
		return nil, err
	}
	return mapSuggestionRecord(record), nil
}

func (s *suggestionServer) UpdateSuggestionFeedback(ctx context.Context, req *suggestionpb.UpdateSuggestionFeedbackRequest) (*suggestionpb.SuggestionResponse, error) {
	jobUUID, mode, err := parseRequest(req.GetJobId(), req.GetMode())
	if err != nil {
		return nil, err
	}
	if _, err := s.authorizeJob(ctx, jobUUID); err != nil {
		return nil, err
	}

	record, err := s.updateFeedback(ctx, jobUUID, mode, strings.TrimSpace(req.GetFeedback()))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, status.Error(codes.NotFound, "suggestion not found")
		}
		return nil, status.Errorf(codes.Internal, "update feedback: %v", err)
	}
	return mapSuggestionRecord(record), nil
}

func parseRequest(jobID string, mode suggestionpb.SuggestionMode) (uuid.UUID, string, error) {
	jobUUID, err := uuid.Parse(strings.TrimSpace(jobID))
	if err != nil {
		return uuid.Nil, "", status.Errorf(codes.InvalidArgument, "invalid job_id: %v", err)
	}
	modeValue, err := modeToString(mode)
	if err != nil {
		return uuid.Nil, "", err
	}
	return jobUUID, modeValue, nil
}

func modeToString(mode suggestionpb.SuggestionMode) (string, error) {
	switch mode {
	case suggestionpb.SuggestionMode_SUGGESTION_MODE_NEXT_STEPS:
		return "next_steps", nil
	default:
		return "", status.Error(codes.InvalidArgument, "only next_steps mode is supported")
	}
}

func stringToMode(mode string) suggestionpb.SuggestionMode {
	switch strings.TrimSpace(strings.ToLower(mode)) {
	case "next_steps":
		return suggestionpb.SuggestionMode_SUGGESTION_MODE_NEXT_STEPS
	default:
		return suggestionpb.SuggestionMode_SUGGESTION_MODE_UNSPECIFIED
	}
}

func (s *suggestionServer) authorizeJob(ctx context.Context, jobUUID uuid.UUID) (db.ScanJob, error) {
	jobRow, err := s.store.GetQueries().GetScanJobByID(ctx, jobUUID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return db.ScanJob{}, status.Error(codes.NotFound, "scan job not found")
		}
		return db.ScanJob{}, status.Errorf(codes.Internal, "load scan job: %v", err)
	}

	if apiProjectID, ok := interceptor.GetAPIProjectID(ctx); ok && strings.TrimSpace(apiProjectID) != "" {
		projectUUID, err := uuid.Parse(strings.TrimSpace(apiProjectID))
		if err != nil {
			return db.ScanJob{}, status.Error(codes.PermissionDenied, "invalid api project scope")
		}
		if projectUUID != jobRow.ProjectID {
			return db.ScanJob{}, status.Error(codes.PermissionDenied, "job does not belong to API key project")
		}
		return jobRow, nil
	}

	userID, err := interceptor.RequireUserID(ctx)
	if err != nil {
		return db.ScanJob{}, err
	}
	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return db.ScanJob{}, status.Errorf(codes.InvalidArgument, "invalid user_id: %v", err)
	}

	projectRow, err := s.store.GetQueries().GetProjectByIDInternal(ctx, jobRow.ProjectID)
	if err != nil {
		return db.ScanJob{}, status.Errorf(codes.Internal, "load project: %v", err)
	}
	if projectRow.UserID != userUUID {
		return db.ScanJob{}, status.Error(codes.PermissionDenied, "job does not belong to current user")
	}

	return jobRow, nil
}

func (s *suggestionServer) callAIGateway(ctx context.Context, payload aiGatewayRequest) (aiGatewayResponse, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return aiGatewayResponse{}, status.Errorf(codes.Internal, "marshal gateway request: %v", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.aiGatewayURL, bytes.NewReader(body))
	if err != nil {
		return aiGatewayResponse{}, status.Errorf(codes.Internal, "build gateway request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if s.internalSecret != "" {
		req.Header.Set("X-Internal-Secret", s.internalSecret)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return aiGatewayResponse{}, status.Errorf(codes.Unavailable, "call AI gateway: %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if resp.StatusCode >= http.StatusBadRequest {
		detail := strings.TrimSpace(string(respBody))
		if detail == "" {
			detail = resp.Status
		}
		return aiGatewayResponse{}, status.Errorf(codes.Unavailable, "AI gateway error: %s", detail)
	}

	var out aiGatewayResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return aiGatewayResponse{}, status.Errorf(codes.Internal, "decode gateway response: %v", err)
	}
	if strings.TrimSpace(out.Mode) == "" {
		out.Mode = payload.Mode
	}
	if len(out.Output) == 0 {
		out.Output = json.RawMessage(`{}`)
	}
	out.Content = ""
	return out, nil
}

func (s *suggestionServer) getSuggestion(ctx context.Context, jobUUID uuid.UUID, mode string) (suggestionRecord, error) {
	var rec suggestionRecord
	err := s.store.GetDB().QueryRow(ctx, selectSuggestionSQL, jobUUID, mode).Scan(
		&rec.ID,
		&rec.JobID,
		&rec.Mode,
		&rec.Provider,
		&rec.Model,
		&rec.Content,
		&rec.OutputJSON,
		&rec.InputTokens,
		&rec.OutputTokens,
		&rec.Feedback,
		&rec.IsSuggested,
		&rec.CreatedAt,
		&rec.UpdatedAt,
	)
	return rec, err
}

func (s *suggestionServer) getSuggestionByID(ctx context.Context, suggestionUUID uuid.UUID) (suggestionRecord, error) {
	var rec suggestionRecord
	err := s.store.GetDB().QueryRow(ctx, selectSuggestionByIDSQL, suggestionUUID).Scan(
		&rec.ID,
		&rec.JobID,
		&rec.Mode,
		&rec.Provider,
		&rec.Model,
		&rec.Content,
		&rec.OutputJSON,
		&rec.InputTokens,
		&rec.OutputTokens,
		&rec.Feedback,
		&rec.IsSuggested,
		&rec.CreatedAt,
		&rec.UpdatedAt,
	)
	return rec, err
}

func (s *suggestionServer) upsertSuggestion(ctx context.Context, jobUUID uuid.UUID, mode string, aiResp aiGatewayResponse) (suggestionRecord, error) {
	var rec suggestionRecord
	err := s.store.GetDB().QueryRow(
		ctx,
		upsertSuggestionSQL,
		jobUUID,
		mode,
		strings.TrimSpace(aiResp.Provider),
		strings.TrimSpace(aiResp.Model),
		"",
		[]byte(aiResp.Output),
		aiResp.Usage.InputTokens,
		aiResp.Usage.OutputTokens,
		"",
		true,
	).Scan(
		&rec.ID,
		&rec.JobID,
		&rec.Mode,
		&rec.Provider,
		&rec.Model,
		&rec.Content,
		&rec.OutputJSON,
		&rec.InputTokens,
		&rec.OutputTokens,
		&rec.Feedback,
		&rec.IsSuggested,
		&rec.CreatedAt,
		&rec.UpdatedAt,
	)
	return rec, err
}

func (s *suggestionServer) updateFeedback(ctx context.Context, jobUUID uuid.UUID, mode, feedback string) (suggestionRecord, error) {
	var rec suggestionRecord
	err := s.store.GetDB().QueryRow(ctx, updateFeedbackSQL, jobUUID, mode, feedback).Scan(
		&rec.ID,
		&rec.JobID,
		&rec.Mode,
		&rec.Provider,
		&rec.Model,
		&rec.Content,
		&rec.OutputJSON,
		&rec.InputTokens,
		&rec.OutputTokens,
		&rec.Feedback,
		&rec.IsSuggested,
		&rec.CreatedAt,
		&rec.UpdatedAt,
	)
	return rec, err
}

func mapSuggestionRecord(rec suggestionRecord) *suggestionpb.SuggestionResponse {
	return &suggestionpb.SuggestionResponse{
		Id:           rec.ID.String(),
		JobId:        rec.JobID.String(),
		Mode:         stringToMode(rec.Mode),
		Provider:     rec.Provider,
		Model:        rec.Model,
		Content:      "",
		OutputJson:   string(rec.OutputJSON),
		InputTokens:  rec.InputTokens,
		OutputTokens: rec.OutputTokens,
		Feedback:     rec.Feedback,
		IsSuggested:  rec.IsSuggested,
		CreatedAt:    timestamppb.New(rec.CreatedAt),
		UpdatedAt:    timestamppb.New(rec.UpdatedAt),
	}
}

func normalizeSeverity(value db.NullSeverityLevel) string {
	if value.Valid && value.SeverityLevel != "" {
		return strings.ToLower(string(value.SeverityLevel))
	}
	return "info"
}

func normalizeJobStatus(value db.NullScanJobStatus) string {
	if value.Valid && value.ScanJobStatus != "" {
		return strings.ToLower(string(value.ScanJobStatus))
	}
	return "unknown"
}

func severityRank(value string) int {
	switch strings.ToLower(value) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	default:
		return 1
	}
}

func truncateUTF8(value string, limit int) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	return string(runes[:limit]) + "..."
}

func envOrDefault(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}
