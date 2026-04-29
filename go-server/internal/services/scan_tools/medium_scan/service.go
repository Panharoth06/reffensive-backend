package mediumscan

import (
	"context"
	"fmt"
	"sync"
	"time"

	dockerrunner "go-server/docker"
	mediumspb "go-server/gen/mediumscan"
	suggestionpb "go-server/gen/suggestion"
	"go-server/internal/database"
	db "go-server/internal/database/sqlc"
	aisuggestion "go-server/internal/services/ai_suggestion"
	redisutil "go-server/redis"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	redis "github.com/redis/go-redis/v9"
)

type stepRuntime struct {
	StepID       string
	JobID        string
	ToolName     string
	TargetValue  string
	Status       mediumspb.ScanStatus
	QueuedAt     time.Time
	StartedAt    *time.Time
	FinishedAt   *time.Time
	ExitCode     int64
	Findings     int32
	Error        string
	ArtifactPath string
	AppliedFlags []string
	SequenceNum  int64
	Logs         []*mediumspb.LogChunk
}

type jobRuntime struct {
	JobID      string
	ProjectID  string
	Status     mediumspb.JobStatus
	CreatedAt  time.Time
	StartedAt  *time.Time
	FinishedAt *time.Time
	StepIDs    []string
}

type idempotencyEntry struct {
	RequestHash string
	Response    *mediumspb.MediumScanSubmitResponse
}

type submittedStepInput struct {
	ToolID                string
	ToolName              string
	ToolOptions           map[string]*mediumspb.MediumOptionValue
	RuntimeTimeoutSeconds int32
}

type stepSpec struct {
	StepID           string
	JobID            string
	StepUUID         uuid.UUID
	JobUUID          uuid.UUID
	ProjectUUID      uuid.UUID
	TargetUUID       uuid.UUID
	ToolRow          db.Tool
	TargetValue      string
	Flags            []string
	ExecutionTimeout time.Duration
}

type mediumScanServer struct {
	mediumspb.UnimplementedMediumScanServiceServer

	queries *db.Queries
	pool    *pgxpool.Pool
	runner  *dockerrunner.Runner

	redisClient         *redis.Client
	redisChannelPrefix  string
	artifactRoot        string
	executionTimeout    time.Duration
	maxExecutionTimeout time.Duration
	startedAt           time.Time

	mu         sync.RWMutex
	idempotent map[string]*idempotencyEntry
	jobs       map[string]*jobRuntime
	steps      map[string]*stepRuntime
}

func NewMediumScanServer() (mediumspb.MediumScanServiceServer, error) {
	store, err := database.ConnectAndMigrate()
	if err != nil {
		return nil, err
	}

	runner, err := dockerrunner.NewRunner()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize docker runner: %w", err)
	}

	redisAddr := envOrDefault("REDIS_ADDR", "localhost:6379")
	redisClient := redisutil.NewClient(redisAddr)
	pingCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := redisClient.Ping(pingCtx).Err(); err != nil {
		return nil, fmt.Errorf("redis unavailable at %s: %w", redisAddr, err)
	}

	return &mediumScanServer{
		pool:                store.Pool,
		queries:             store.Queries,
		runner:              runner,
		redisClient:         redisClient,
		redisChannelPrefix:  envOrDefault("REDIS_SCAN_LOG_PREFIX", "scan:logs"),
		artifactRoot:        envOrDefault("SHADOW_OUTPUT_ROOT", "/tmp/shadow"),
		executionTimeout:    envDurationSecondsOrDefault("MEDIUM_SCAN_TIMEOUT_SECONDS", 15*time.Minute),
		maxExecutionTimeout: envDurationSecondsOrDefault("MEDIUM_SCAN_MAX_TIMEOUT_SECONDS", 2*time.Hour),
		startedAt:           time.Now().UTC(),
		idempotent:          make(map[string]*idempotencyEntry),
		jobs:                make(map[string]*jobRuntime),
		steps:               make(map[string]*stepRuntime),
	}, nil
}

func (s *mediumScanServer) generateSuggestionsForJob(jobUUID uuid.UUID) {
	if s == nil || s.pool == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = aisuggestion.GenerateForJob(ctx, jobUUID, suggestionpb.SuggestionMode_SUGGESTION_MODE_NEXT_STEPS)
}
