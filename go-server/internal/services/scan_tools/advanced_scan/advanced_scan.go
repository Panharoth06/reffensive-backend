package advancedscan

import (
	"context"
	"fmt"
	"sync"
	"time"

	dockerrunner "go-server/docker"
	advancedpb "go-server/gen/advanced"
	suggestionpb "go-server/gen/suggestion"
	"go-server/internal/database"
	db "go-server/internal/database/sqlc"
	aisuggestion "go-server/internal/services/ai_suggestion"
	redisutil "go-server/redis"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

type stepRuntime struct {
	StepID        string
	JobID         string
	ToolName      string
	Status        advancedpb.StepStatus
	QueuedAt      time.Time
	StartedAt     *time.Time
	FinishedAt    *time.Time
	ExitCode      int64
	Findings      int32
	HasParsedData bool
	Error         string
	ArtifactPath  string
	CommandPlan   *InvocationPlan
	SequenceNum   int64
	Logs          []*advancedpb.LogChunk
}

type jobRuntime struct {
	JobID      string
	ProjectID  string
	Status     advancedpb.JobStatus
	CreatedAt  time.Time
	StartedAt  *time.Time
	FinishedAt *time.Time
	StepIDs    []string
}

type idempotencyEntry struct {
	RequestHash string
	Response    *advancedpb.SubmitScanResponse
	CreatedAt   time.Time
}

type chainStepSpec struct {
	StepID         string
	JobID          string
	ToolRow        db.Tool
	ToolArgs       map[string]string
	RawCustomFlags []string
	InputStepUUID  uuid.UUID
	StepUUID       uuid.UUID
	JobUUID        uuid.UUID
	ProjectUUID    uuid.UUID
	TargetUUID     uuid.UUID
}

type submittedStepInput struct {
	ToolName       string
	ToolID         string
	ToolArgs       map[string]string
	RawCustomFlags []string
}

type advancedScanServer struct {
	advancedpb.UnimplementedAdvancedScanServiceServer

	queries *db.Queries
	pool    *pgxpool.Pool
	runner  *dockerrunner.Runner

	redisClient        *redis.Client
	redisChannelPrefix string
	artifactRoot       string

	mu sync.RWMutex
	// idempotency_key -> payload hash + response
	idempotent map[string]*idempotencyEntry
	jobs       map[string]*jobRuntime
	steps      map[string]*stepRuntime
}

func NewAdvancedScanServer() (advancedpb.AdvancedScanServiceServer, error) {
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

	srv := &advancedScanServer{
		pool:               store.Pool,
		queries:            store.Queries,
		runner:             runner,
		redisClient:        redisClient,
		redisChannelPrefix: envOrDefault("REDIS_SCAN_LOG_PREFIX", "scan:logs"),
		artifactRoot:       envOrDefault("SHADOW_OUTPUT_ROOT", "/tmp/shadow"),
		idempotent:         make(map[string]*idempotencyEntry),
		jobs:               make(map[string]*jobRuntime),
		steps:              make(map[string]*stepRuntime),
	}

	// Register this service as a handler with the shared queue manager.
	// Workers are started globally by queue.InitManager().
	qm := redisutil.GetManager()
	qm.RegisterHandler("advanced", srv, "advanced-scan-worker")

	go srv.startBackgroundCleanup()
	return srv, nil
}

func (s *advancedScanServer) generateSuggestionsForJob(jobUUID uuid.UUID) {
	if s == nil || s.pool == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = aisuggestion.GenerateForJob(ctx, jobUUID, suggestionpb.SuggestionMode_SUGGESTION_MODE_NEXT_STEPS)
}

func (s *advancedScanServer) startBackgroundCleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		s.mu.Lock()
		now := time.Now().UTC()

		for k, v := range s.idempotent {
			if now.Sub(v.CreatedAt) > 24*time.Hour {
				delete(s.idempotent, k)
			}
		}

		for k, v := range s.jobs {
			if isTerminalJobStatus(v.Status) && v.FinishedAt != nil && now.Sub(*v.FinishedAt) > time.Hour {
				delete(s.jobs, k)
			}
		}

		for k, v := range s.steps {
			if isTerminalStepStatus(v.Status) && v.FinishedAt != nil && now.Sub(*v.FinishedAt) > time.Hour {
				delete(s.steps, k)
			}
		}

		s.mu.Unlock()
	}
}
