package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	tool "go-server/gen/tool"
	db "go-server/internal/database/sqlc"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type toolServer struct {
	tool.UnimplementedToolServiceServer
	store toolResultStore
}

var (
	buildQueueMu sync.Mutex
	buildQueue   = newBuildJobQueue()
)

func NewToolServer() tool.ToolServiceServer {
	return &toolServer{}
}

func normalizeToolName(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func statusFromToolMutationError(err error, action string, requestedToolName string) error {
	if err == nil {
		return nil
	}

	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		if pgErr.Code == "23505" && pgErr.ConstraintName == "tools_tool_name_key" {
			if strings.TrimSpace(requestedToolName) != "" {
				return status.Errorf(codes.AlreadyExists, "failed to %s tool: tool_name %q already exists on another tool", action, requestedToolName)
			}
			return status.Errorf(codes.AlreadyExists, "failed to %s tool: tool_name already exists on another tool", action)
		}
	}

	return status.Errorf(codes.Internal, "failed to %s tool: %v", action, err)
}

// getToolStore returns a storeAdapter that wraps the singleton database.Store.
func getToolStore() (toolResultStore, error) {
	store, err := getStore()
	if err != nil {
		return nil, err
	}
	return &storeAdapter{store: store}, nil
}

// ─── CreateTool ───────────────────────────────────────────────────────────────

func (s *toolServer) CreateTool(ctx context.Context, req *tool.CreateToolRequest) (*tool.ToolResponse, error) {
	store, err := getToolStore()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "database unavailable: %v", err)
	}

	normalizedToolName := normalizeToolName(req.ToolName)
	normalizedInstallMethod := normalizeInstallMethod(req.InstallMethod, req.ImageRef)

	// Pull Docker image if ImageRef is provided and the source is registry-backed.
	if req.ImageRef != "" && shouldPullToolImage(normalizedInstallMethod, req.ImageSource) {
		dockerSvc, err := NewDockerService()
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to initialize docker service: %v", err)
		}
		if err := dockerSvc.PullImageIfNotExists(ctx, req.ImageRef); err != nil {
			return nil, status.Errorf(codes.Internal, "failed to pull docker image %s: %v", req.ImageRef, err)
		}
	}

	categoryID, err := getCategoryByName(ctx, store.GetDB(), req.CategoryName)
	if err != nil && req.CategoryName != "" {
		return nil, status.Errorf(codes.NotFound, "category %q not found: %v", req.CategoryName, err)
	}
	var catID pgtype.UUID
	if req.CategoryName != "" {
		catID = categoryID
	}

	versionID, err := getOrCreateVersion(ctx, store.GetDB(), req.Version)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "could not resolve version %q: %v", req.Version, err)
	}

	inputSchema, err := validateAndMarshalJSON(req.InputSchema, "input_schema")
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	outputSchema, err := validateAndMarshalJSON(req.OutputSchema, "output_schema")
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	scanConfig, err := validateAndMarshalJSON(req.ScanConfig, "scan_config")
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	buildConfigJSON, err := validateAndMarshalJSON(req.BuildConfigJson, "build_config_json")
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	examplesJSON, err := validateAndMarshalJSON(req.Examples, "examples")
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	if len(scanConfig) == 0 {
		scanConfig = []byte("{}")
	}
	if len(examplesJSON) == 0 {
		examplesJSON = []byte("[]")
	}

	// Marshal shadow_output_config if provided
	var shadowOutputConfig []byte
	if req.ShadowOutputConfig != nil {
		shadowOutputConfig, err = json.Marshal(req.ShadowOutputConfig)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid shadow_output_config: %v", err)
		}
	}

	// Marshal parser_config if provided (optional)
	var parserConfig []byte
	if req.ParserConfig != "" {
		if !json.Valid([]byte(req.ParserConfig)) {
			return nil, status.Errorf(codes.InvalidArgument, "parser_config must be valid JSON")
		}
		parserConfig = []byte(req.ParserConfig)
	}

	params := db.CreateToolParams{
		CategoryID:          catID,
		ToolName:            normalizedToolName,
		ToolDescription:     pgtype.Text{String: req.ToolDescription, Valid: req.ToolDescription != ""},
		ToolLongDescription: pgtype.Text{String: req.ToolLongDescription, Valid: req.ToolLongDescription != ""},
		Examples:            examplesJSON,
		InputSchema:         inputSchema,
		OutputSchema:        outputSchema,
		ScanConfig:          scanConfig,
		InstallMethod:       pgtype.Text{String: normalizedInstallMethod, Valid: normalizedInstallMethod != ""},
		VersionID:           versionID,
		ImageRef:            pgtype.Text{String: req.ImageRef, Valid: req.ImageRef != ""},
		ImageSource:         pgtype.Text{String: req.ImageSource, Valid: req.ImageSource != ""},
		DeniedOptions:       req.DeniedOptions,
		ShadowOutputConfig:  shadowOutputConfig,
		ParserConfig:        parserConfig,
	}

	created, err := store.GetQueries().CreateTool(ctx, params)
	if err != nil {
		return nil, statusFromToolMutationError(err, "create", normalizedToolName)
	}
	if shouldQueueToolBuild(normalizedInstallMethod, req.ImageRef, req.ImageSource) {
		queueToolBuild(
			created.ToolID.String(),
			normalizedToolName,
			normalizedInstallMethod,
			buildJobImageSource(normalizedInstallMethod, req.ImageRef, req.ImageSource),
			string(buildConfigJSON),
		)
	}
	return toolToProto(created), nil
}

// ─── GetTool ──────────────────────────────────────────────────────────────────

func (s *toolServer) GetTool(ctx context.Context, req *tool.GetToolRequest) (*tool.ToolResponse, error) {
	store, err := getToolStore()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "database unavailable: %v", err)
	}

	toolID, err := uuid.Parse(req.ToolId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid tool_id: %v", err)
	}

	t, err := store.GetQueries().GetToolByID(ctx, toolID)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "tool not found: %v", err)
	}
	return toolToProto(t), nil
}

// ─── ListTools ────────────────────────────────────────────────────────────────

func (s *toolServer) ListTools(ctx context.Context, req *tool.ListToolsRequest) (*tool.ListToolsResponse, error) {
	store, err := getToolStore()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "database unavailable: %v", err)
	}

	var tools []db.Tool

	switch {
	case req.CategoryName != "":
		catID, err := getCategoryByName(ctx, store.GetDB(), req.CategoryName)
		if err != nil {
			return nil, status.Errorf(codes.NotFound, "category %q not found: %v", req.CategoryName, err)
		}
		tools, err = store.GetQueries().ListToolsByCategory(ctx, catID)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "list tools by category: %v", err)
		}
	case req.ActiveOnly:
		tools, err = store.GetQueries().ListActiveTools(ctx)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "list active tools: %v", err)
		}
	default:
		tools, err = store.GetQueries().ListTools(ctx)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "list tools: %v", err)
		}
	}

	resp := &tool.ListToolsResponse{}
	for _, t := range tools {
		resp.Tools = append(resp.Tools, toolToProto(t))
	}
	return resp, nil
}

// ─── UpdateTool ───────────────────────────────────────────────────────────────

func (s *toolServer) UpdateTool(ctx context.Context, req *tool.UpdateToolRequest) (*tool.ToolResponse, error) {
	store, err := getToolStore()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "database unavailable: %v", err)
	}

	toolID, err := uuid.Parse(req.ToolId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid tool_id: %v", err)
	}

	normalizedToolName := normalizeToolName(req.ToolName)
	normalizedInstallMethod := normalizeInstallMethod(req.InstallMethod, req.ImageRef)

	// Pull Docker image if ImageRef is provided and being updated from a registry-backed source.
	if req.ImageRef != "" && shouldPullToolImage(normalizedInstallMethod, req.ImageSource) {
		dockerSvc, err := NewDockerService()
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to initialize docker service: %v", err)
		}
		if err := dockerSvc.PullImageIfNotExists(ctx, req.ImageRef); err != nil {
			return nil, status.Errorf(codes.Internal, "failed to pull docker image %s: %v", req.ImageRef, err)
		}
	}

	// Resolve optional category name
	var categoryID pgtype.UUID
	if req.CategoryName != "" {
		categoryID, err = getCategoryByName(ctx, store.GetDB(), req.CategoryName)
		if err != nil {
			return nil, status.Errorf(codes.NotFound, "category %q not found: %v", req.CategoryName, err)
		}
	}

	// Resolve optional version
	var versionID pgtype.UUID
	if req.Version != "" {
		vid, err := getOrCreateVersion(ctx, store.GetDB(), req.Version)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "could not resolve version: %v", err)
		}
		versionID = pgtype.UUID{Bytes: vid, Valid: true}
	}

	inputSchema, err := validateAndMarshalJSON(req.InputSchema, "input_schema")
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	outputSchema, err := validateAndMarshalJSON(req.OutputSchema, "output_schema")
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	scanConfig, err := validateAndMarshalJSON(req.ScanConfig, "scan_config")
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	if _, err := validateAndMarshalJSON(req.BuildConfigJson, "build_config_json"); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	var examplesJSON []byte
	if req.Examples != "" {
		examplesJSON, err = validateAndMarshalJSON(req.Examples, "examples")
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "%v", err)
		}
	}

	var deniedOptions []string
	if len(req.DeniedOptions) > 0 {
		deniedOptions = req.DeniedOptions
	}

	// Marshal shadow_output_config if provided
	var shadowOutputConfig []byte
	if req.ShadowOutputConfig != nil {
		shadowOutputConfig, err = json.Marshal(req.ShadowOutputConfig)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid shadow_output_config: %v", err)
		}
	}

	// Marshal parser_config if provided
	var parserConfig []byte
	if req.ParserConfig != "" {
		if !json.Valid([]byte(req.ParserConfig)) {
			return nil, status.Errorf(codes.InvalidArgument, "parser_config must be valid JSON")
		}
		parserConfig = []byte(req.ParserConfig)
	}

	params := db.UpdateToolParams{
		ToolID:              toolID,
		CategoryID:          pgtype.UUID{Bytes: categoryID.Bytes, Valid: categoryID.Valid},
		ToolName:            pgtype.Text{String: normalizedToolName, Valid: normalizedToolName != ""},
		ToolDescription:     pgtype.Text{String: req.ToolDescription, Valid: req.ToolDescription != ""},
		ToolLongDescription: pgtype.Text{String: req.ToolLongDescription, Valid: req.ToolLongDescription != ""},
		Examples:            examplesJSON,
		InputSchema:         inputSchema,
		OutputSchema:        outputSchema,
		ScanConfig:          scanConfig,
		InstallMethod:       pgtype.Text{String: normalizedInstallMethod, Valid: normalizedInstallMethod != ""},
		VersionID:           versionID,
		ImageRef:            pgtype.Text{String: req.ImageRef, Valid: req.ImageRef != ""},
		ImageSource:         pgtype.Text{String: req.ImageSource, Valid: req.ImageSource != ""},
		DeniedOptions:       deniedOptions,
		ShadowOutputConfig:  shadowOutputConfig,
		ParserConfig:        parserConfig,
		IsActive:            pgtype.Bool{}, // not modified here — use SetToolActive
	}

	updated, err := store.GetQueries().UpdateTool(ctx, params)
	if err != nil {
		return nil, statusFromToolMutationError(err, "update", normalizedToolName)
	}
	return toolToProto(updated), nil
}

func (s *toolServer) ListQueuedBuildJobs(ctx context.Context, req *tool.ListQueuedBuildJobsRequest) (*tool.ListQueuedBuildJobsResponse, error) {
	buildQueueMu.Lock()
	jobs := buildQueue.Claim(int(req.GetLimit()))
	buildQueueMu.Unlock()

	resp := &tool.ListQueuedBuildJobsResponse{
		Jobs: make([]*tool.BuildJob, 0, len(jobs)),
	}
	for _, job := range jobs {
		resp.Jobs = append(resp.Jobs, buildJobToProto(job))
	}
	return resp, nil
}

func (s *toolServer) UpdateBuildJobStatus(ctx context.Context, req *tool.UpdateBuildJobStatusRequest) (*tool.BuildJob, error) {
	buildQueueMu.Lock()
	job, ok := buildQueue.UpdateStatus(req.GetId(), req.GetStatus())
	buildQueueMu.Unlock()
	if !ok {
		return nil, status.Errorf(codes.NotFound, "build job %q not found", req.GetId())
	}
	return buildJobToProto(job), nil
}

func (s *toolServer) FinishBuildJob(ctx context.Context, req *tool.FinishBuildJobRequest) (*tool.BuildJob, error) {
	buildQueueMu.Lock()
	job, ok := buildQueue.Finish(req.GetId(), req.GetStatus(), req.GetError())
	buildQueueMu.Unlock()
	if !ok {
		return nil, status.Errorf(codes.NotFound, "build job %q not found", req.GetId())
	}
	return buildJobToProto(job), nil
}

func (s *toolServer) UpdateToolImageRef(ctx context.Context, req *tool.UpdateToolImageRefRequest) (*tool.ToolResponse, error) {
	store, err := getToolStore()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "database unavailable: %v", err)
	}

	toolID, err := uuid.Parse(req.Id)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid tool_id: %v", err)
	}

	updated, err := store.GetQueries().UpdateTool(ctx, db.UpdateToolParams{
		ToolID:   toolID,
		ImageRef: pgtype.Text{String: req.GetImageRef(), Valid: strings.TrimSpace(req.GetImageRef()) != ""},
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to update tool image_ref: %v", err)
	}
	return toolToProto(updated), nil
}

// ─── SetToolActive (soft delete / reactivate) ─────────────────────────────────

func (s *toolServer) SetToolActive(ctx context.Context, req *tool.SetToolActiveRequest) (*tool.SetToolActiveResponse, error) {
	store, err := getToolStore()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "database unavailable: %v", err)
	}

	toolID, err := uuid.Parse(req.ToolId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid tool_id: %v", err)
	}

	// Use UpdateTool with only is_active set; COALESCE preserves all other fields.
	params := db.UpdateToolParams{
		ToolID:   toolID,
		IsActive: pgtype.Bool{Bool: req.IsActive, Valid: true},
		// All other fields left at zero → pgtype.Text{Valid:false} / nil → COALESCE preserves
	}

	updated, err := store.GetQueries().UpdateTool(ctx, params)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to update tool active status: %v", err)
	}
	return &tool.SetToolActiveResponse{
		ToolId:   updated.ToolID.String(),
		IsActive: updated.IsActive.Bool,
	}, nil
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// toolToProto maps db.Tool → proto ToolResponse.
func toolToProto(t db.Tool) *tool.ToolResponse {
	resp := &tool.ToolResponse{
		ToolId:              t.ToolID.String(),
		ToolName:            t.ToolName,
		ToolDescription:     t.ToolDescription.String,
		ToolLongDescription: t.ToolLongDescription.String,
		InstallMethod:       t.InstallMethod.String,
		ImageRef:            t.ImageRef.String,
		ImageSource:         t.ImageSource.String,
		IsActive:            t.IsActive.Bool,
		DeniedOptions:       t.DeniedOptions,
	}
	if len(t.Examples) > 0 {
		resp.Examples = string(t.Examples)
	}

	
	if t.CategoryID.Valid {
		cStore, _ := dbStore.Queries.GetToolCategoryByID(context.Background(), t.CategoryID.Bytes)
		resp.CategoryName = cStore.Name
	}
	if len(t.InputSchema) > 0 {
		resp.InputSchema = string(t.InputSchema)
	}
	if len(t.OutputSchema) > 0 {
		resp.OutputSchema = string(t.OutputSchema)
	}
	if len(t.ScanConfig) > 0 {
		resp.ScanConfig = string(t.ScanConfig)
	}
	if len(t.ShadowOutputConfig) > 0 {
		var shadowConfig tool.ShadowOutputConfig
		if err := json.Unmarshal(t.ShadowOutputConfig, &shadowConfig); err == nil {
			resp.ShadowOutputConfig = &shadowConfig
		}
	}
	if len(t.ParserConfig) > 0 {
		resp.ParserConfig = string(t.ParserConfig)
	}
	if t.CreatedAt.Valid {
		resp.CreatedAt = timestamppb.New(t.CreatedAt.Time)
	}
	if t.UpdatedAt.Valid {
		resp.UpdatedAt = timestamppb.New(t.UpdatedAt.Time)
	}
	return resp
}

// validateAndMarshalJSON returns nil for empty input, or raw bytes after JSON validation.
func validateAndMarshalJSON(raw, field string) ([]byte, error) {
	if raw == "" {
		return nil, nil
	}
	if !json.Valid([]byte(raw)) {
		return nil, fmt.Errorf("%s must be valid JSON", field)
	}
	return []byte(raw), nil
}

func shouldPullToolImage(installMethod, source string) bool {
	switch normalizeInstallMethod(installMethod, "") {
	case "custom_build":
		return false
	case "official_image":
		return true
	}
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "custom", "local":
		return false
	default:
		return true
	}
}

func shouldQueueToolBuild(installMethod, imageRef, imageSource string) bool {
	switch normalizeInstallMethod(installMethod, imageRef) {
	case "official_image":
		return strings.TrimSpace(imageRef) != ""
	case "custom_build":
		return strings.TrimSpace(imageSource) != ""
	default:
		return false
	}
}

func buildJobImageSource(installMethod, imageRef, imageSource string) string {
	switch normalizeInstallMethod(installMethod, imageRef) {
	case "official_image":
		if strings.TrimSpace(imageRef) != "" {
			return strings.TrimSpace(imageRef)
		}
		return strings.TrimSpace(imageSource)
	case "custom_build":
		return strings.TrimSpace(imageSource)
	default:
		return strings.TrimSpace(imageSource)
	}
}

func queueToolBuild(toolID, toolName, installMethod, imageSource, buildConfigJSON string) {
	buildQueueMu.Lock()
	defer buildQueueMu.Unlock()
	buildQueue.Enqueue(toolID, installMethod, imageSource, enrichBuildConfigJSON(buildConfigJSON, toolID, toolName))
}

func enrichBuildConfigJSON(buildConfigJSON, toolID, toolName string) string {
	trimmed := strings.TrimSpace(buildConfigJSON)
	payload := map[string]any{}
	if trimmed != "" {
		if err := json.Unmarshal([]byte(trimmed), &payload); err != nil {
			return buildConfigJSON
		}
	}
	if strings.TrimSpace(toolID) != "" {
		if _, exists := payload["tool_id"]; !exists {
			payload["tool_id"] = toolID
		}
	}
	if strings.TrimSpace(toolName) != "" {
		if _, exists := payload["tool_name"]; !exists {
			payload["tool_name"] = toolName
		}
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return buildConfigJSON
	}
	return string(encoded)
}

func normalizeInstallMethod(value, imageRef string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	switch normalized {
	case "", "docker", "official", "official_image", "registry", "image":
		if strings.TrimSpace(imageRef) != "" || normalized != "" {
			return "official_image"
		}
		return ""
	case "custom", "custom_build", "source", "binary":
		return "custom_build"
	default:
		return normalized
	}
}
