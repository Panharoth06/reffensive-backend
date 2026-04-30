package service

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "go-server/gen/sonarqube"
	db "go-server/internal/database/sqlc"
	"go-server/internal/interceptor"
	sonarqubequeue "go-server/internal/services/sonarqube/queue"
	"go-server/internal/services/sonarqube/scanner/dependency"
	"go-server/internal/services/sonarqube/scanner/dependency/lang"
	"go-server/internal/services/sonarqube/scanner/repository"
	"go-server/internal/services/sonarqube/scanner/sonar"
	appconfig "go-server/pkg/config"
	redisutil "go-server/redis"
)

const (
	scanStatusPending     = "PENDING"
	scanStatusRunning     = "IN_PROGRESS"
	scanStatusSuccess     = "SUCCESS"
	scanStatusFailed      = "FAILED"
	scanStatusPartial     = "PARTIAL"
	phaseStatusPending    = "PENDING"
	phaseStatusRunning    = "IN_PROGRESS"
	phaseStatusDone       = "SUCCESS"
	phaseStatusFailed     = "FAILED"
	defaultScanTmpRoot    = "/tmp/aof-scans"
	defaultDependencyPage = 100
)

type ScannerServer struct {
	pb.UnimplementedSonarqubeServiceServer

	queries             *db.Queries
	scanRepo            *repository.ScanRepository
	sonarRepo           *repository.SonarRepository
	depRepo             *repository.DependencyRepository
	depRunner           *dependency.Runner
	queueClient         *sonarqubequeue.Client
	progressPub         *sonarqubequeue.ProgressPublisher
	sonarClient         *sonar.Client
	redisClient         *redis.Client
	logger              zerolog.Logger
	scanLogPrefix       string
	scanLogHistoryLimit int64
	scanLogTTL          time.Duration
	tmpRoot             string
	logMu               sync.Mutex
}

type scanRequest struct {
	RepoURL    string
	ProjectKey string
	Branch     string
}

type userScopedScanListRequest interface {
	GetProjectKey() string
	GetPage() int32
	GetPageSize() int32
}

// NewScannerServer creates ScannerServer with necessary dependencies.
func NewScannerServer(queries *db.Queries) (*ScannerServer, error) {
	sonarClient, err := sonar.NewClient(queries)
	if err != nil {
		return nil, fmt.Errorf("initialize sonar client: %w", err)
	}
	tmpRoot := strings.TrimSpace(os.Getenv("SCAN_TMP_DIR"))
	if tmpRoot == "" {
		tmpRoot = defaultScanTmpRoot
	}
	redisAddr := os.Getenv("REDIS_ADDR")
	serviceLogger := zerolog.New(os.Stdout).With().Timestamp().Str("service", "sonarqube-scanner").Logger()
	depRunner := dependency.NewRunner(serviceLogger, appconfig.Config{})
	if err := depRunner.RegisterScanners(map[string]dependency.ScannerFunc{
		"go":     lang.ScanGo,
		"python": lang.ScanPython,
		"node":   lang.ScanNode,
		"java":   lang.ScanJava,
		"kotlin": lang.ScanJava,
		"php":    lang.ScanPHP,
		"rust":   lang.ScanRust,
		"ruby":   lang.ScanRuby,
		"dotnet": lang.ScanDotNet,
		"swift":  lang.ScanSwift,
		"dart":   lang.ScanDart,
	}); err != nil {
		return nil, fmt.Errorf("register dependency scanners: %w", err)
	}
	return &ScannerServer{
		queries:             queries,
		scanRepo:            repository.NewScanRepository(queries),
		sonarRepo:           repository.NewSonarRepository(queries),
		depRepo:             repository.NewDependencyRepository(queries),
		depRunner:           depRunner,
		queueClient:         sonarqubequeue.NewClient(redisAddr),
		progressPub:         sonarqubequeue.NewProgressPublisher(redisAddr, os.Getenv("SONARQUBE_PROGRESS_CHANNEL_PREFIX")),
		sonarClient:         sonarClient,
		redisClient:         redisutil.NewClient(redisAddr),
		logger:              serviceLogger,
		scanLogPrefix:       scanLogPrefixFromEnv(),
		scanLogHistoryLimit: scanLogHistoryLimitFromEnv(),
		scanLogTTL:          scanLogTTLFromEnv(),
		tmpRoot:             tmpRoot,
	}, nil
}

// TriggerScan initiates a new scan and delegates execution to the runner.
func (s *ScannerServer) TriggerScan(ctx context.Context, req *pb.TriggerScanRequest) (*pb.TriggerScanResponse, error) {
	repoURL := strings.TrimSpace(req.GetRepoUrl())
	if err := validateHTTPRepoURL(repoURL); err != nil {
		return nil, err
	}

	projectKey := strings.TrimSpace(req.GetProjectKey())
	if projectKey == "" {
		return nil, status.Error(codes.InvalidArgument, "project_key is required")
	}

	userIDText, err := interceptor.RequireUserID(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "user_id is required")
	}
	userID, err := uuid.Parse(userIDText)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid user_id: %v", err)
	}

	scanID := uuid.New()
	tmpDir := filepath.Join(s.tmpRoot, scanID.String(), "source")
	branch := strings.TrimSpace(req.GetBranch())

	scan, err := s.scanRepo.Create(ctx, &repository.Scan{
		ProjectKey:    projectKey,
		RepositoryURL: repoURL,
		SourceDir:     tmpDir,
		Branch:        branch,
		UserID:        userID,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "create scan record: %v", err)
	}

	if err := s.queueClient.EnqueueScan(ctx, sonarqubequeue.ScanTaskPayload{
		ScanID:     scan.ID,
		RepoURL:    repoURL,
		ProjectKey: projectKey,
		Branch:     branch,
	}); err != nil {
		_ = s.scanRepo.UpdateStatus(ctx, scan.ID, scanStatusFailed, fmt.Sprintf("queue scan job: %v", err))
		return nil, status.Errorf(codes.Internal, "queue scan job: %v", err)
	}

	return &pb.TriggerScanResponse{
		ScanId:    scan.ID,
		Status:    pb.ScanStatus_SCAN_STATUS_PENDING,
		CreatedAt: timestamppb.New(scan.CreatedAt),
	}, nil
}

// ListTriggeredScans returns all scans triggered for a project.
func (s *ScannerServer) ListTriggeredScans(ctx context.Context, req *pb.ProjectScansRequest) (*pb.ProjectScansResponse, error) {
	return s.listScansForCurrentUser(ctx, req)
}

// ListUserScans returns the current user's scans, optionally filtered by project.
func (s *ScannerServer) ListUserScans(ctx context.Context, req *pb.UserScansRequest) (*pb.ProjectScansResponse, error) {
	return s.listScansForCurrentUser(ctx, req)
}

func (s *ScannerServer) listScansForCurrentUser(ctx context.Context, req userScopedScanListRequest) (*pb.ProjectScansResponse, error) {
	userID, err := requireCurrentUserUUID(ctx)
	if err != nil {
		return nil, err
	}

	projectKey := strings.TrimSpace(req.GetProjectKey())
	page, pageSize := normalizePage(req.GetPage(), req.GetPageSize())
	scans, total, err := s.scanRepo.ListByUser(ctx, userID, projectKey, page, pageSize)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list user scans: %v", err)
	}

	return buildProjectScansResponse(scans, page, pageSize, total), nil
}

func buildProjectScansResponse(scans []*repository.Scan, page, pageSize, total int32) *pb.ProjectScansResponse {
	resp := &pb.ProjectScansResponse{
		Scans:    make([]*pb.ProjectScan, 0, len(scans)),
		Page:     page,
		PageSize: pageSize,
		Total:    total,
	}

	for _, scan := range scans {
		resp.Scans = append(resp.Scans, &pb.ProjectScan{
			ScanId:       scan.ID,
			ProjectKey:   scan.ProjectKey,
			Branch:       scan.Branch,
			Status:       scanStatus(scan.Status),
			Progress:     scan.Progress,
			CreatedAt:    timestamppbOrNil(scan.CreatedAt),
			StartedAt:    timestamppbOrNil(scan.StartedAt),
			FinishedAt:   timestamppbOrNil(scan.FinishedAt),
			ErrorMessage: scan.ErrorMessage,
		})
	}

	return resp
}

func validateHTTPRepoURL(raw string) error {
	parsed, err := url.ParseRequestURI(raw)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "repo_url must be a valid URL: %v", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return status.Error(codes.InvalidArgument, "repo_url must use http or https")
	}
	if parsed.Host == "" {
		return status.Error(codes.InvalidArgument, "repo_url host is required")
	}
	return nil
}

func requireCurrentUserUUID(ctx context.Context) (uuid.UUID, error) {
	userIDText, err := interceptor.RequireUserID(ctx)
	if err != nil {
		return uuid.Nil, status.Error(codes.Unauthenticated, "user_id is required")
	}
	userID, err := uuid.Parse(userIDText)
	if err != nil {
		return uuid.Nil, status.Errorf(codes.InvalidArgument, "invalid user_id: %v", err)
	}
	return userID, nil
}

func textValue(value string) pgtype.Text {
	value = strings.TrimSpace(value)
	return pgtype.Text{String: value, Valid: value != ""}
}

func text(value pgtype.Text) string {
	if !value.Valid {
		return ""
	}
	return value.String
}

func timestamp(value pgtype.Timestamptz) *timestamppb.Timestamp {
	if !value.Valid {
		return nil
	}
	return timestamppb.New(value.Time)
}

func timestamppbOrNil(value time.Time) *timestamppb.Timestamp {
	if value.IsZero() {
		return nil
	}
	return timestamppb.New(value)
}
