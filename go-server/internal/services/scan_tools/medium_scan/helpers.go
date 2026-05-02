package mediumscan

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	mediumspb "go-server/gen/mediumscan"
	"go-server/internal/interceptor"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func buildStepKey(order int, toolName string) string {
	base := strings.ToLower(stringsTrim(toolName))
	if base == "" {
		base = "step"
	}
	var b strings.Builder
	lastDash := false
	for _, r := range base {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			b.WriteByte('-')
			lastDash = true
		}
	}
	clean := strings.Trim(b.String(), "-")
	if clean == "" {
		clean = "step"
	}
	if len(clean) > 40 {
		clean = clean[:40]
	}
	return fmt.Sprintf("%02d_%s", order, clean)
}

func stringsTrim(v string) string {
	return strings.TrimSpace(v)
}

func toProtoTS(t *time.Time) *timestamppb.Timestamp {
	if t == nil {
		return nil
	}
	return timestamppb.New(*t)
}

func envOrDefault(key, fallback string) string {
	v := stringsTrim(os.Getenv(key))
	if v == "" {
		return fallback
	}
	return v
}

func envDurationSecondsOrDefault(key string, fallback time.Duration) time.Duration {
	v := stringsTrim(os.Getenv(key))
	if v == "" {
		return fallback
	}

	seconds, err := strconv.Atoi(v)
	if err != nil || seconds <= 0 {
		return fallback
	}

	return time.Duration(seconds) * time.Second
}

func durationFromSeconds(seconds int32) time.Duration {
	if seconds <= 0 {
		return 0
	}
	return time.Duration(seconds) * time.Second
}

func cloneMediumOptionMap(src map[string]*mediumspb.MediumOptionValue) map[string]*mediumspb.MediumOptionValue {
	if len(src) == 0 {
		return map[string]*mediumspb.MediumOptionValue{}
	}
	out := make(map[string]*mediumspb.MediumOptionValue, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

func requireAuthorizedMediumProject(ctx context.Context, projectID, ownerUserID string) error {
	if apiProjectID, ok := interceptor.GetAPIProjectID(ctx); ok && stringsTrim(apiProjectID) != "" {
		apiProjectUUID, err := uuid.Parse(stringsTrim(apiProjectID))
		if err != nil {
			return status.Errorf(codes.InvalidArgument, "invalid api project_id: %v", err)
		}
		projectUUID, err := uuid.Parse(stringsTrim(projectID))
		if err != nil {
			return status.Errorf(codes.Internal, "invalid project_id on job context: %v", err)
		}
		if apiProjectUUID != projectUUID {
			return status.Error(codes.PermissionDenied, "api key does not allow access to this project")
		}
		return nil
	}

	userID, err := interceptor.RequireUserID(ctx)
	if err != nil {
		return err
	}
	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "invalid user_id: %v", err)
	}
	ownerUUID, err := uuid.Parse(ownerUserID)
	if err != nil {
		return status.Errorf(codes.Internal, "invalid project owner user_id: %v", err)
	}
	if ownerUUID != userUUID {
		return status.Error(codes.PermissionDenied, "scan does not belong to authenticated user")
	}
	return nil
}

func apiKeyUUIDFromContext(ctx context.Context) (pgtype.UUID, error) {
	apiKeyID, ok := interceptor.GetAPIKeyID(ctx)
	if !ok || stringsTrim(apiKeyID) == "" {
		return pgtype.UUID{Valid: false}, nil
	}
	parsed, err := uuid.Parse(stringsTrim(apiKeyID))
	if err != nil {
		return pgtype.UUID{}, status.Errorf(codes.InvalidArgument, "invalid api_key_id: %v", err)
	}
	return pgtype.UUID{Bytes: parsed, Valid: true}, nil
}

func (s *mediumScanServer) requireOwnedMediumStep(ctx context.Context, stepID string) (*stepRuntime, *jobRuntime, error) {
	s.mu.RLock()
	step, ok := s.steps[stepID]
	if !ok {
		s.mu.RUnlock()
		return nil, nil, status.Error(codes.NotFound, "step not found")
	}
	job, jobOK := s.jobs[step.JobID]
	if !jobOK {
		s.mu.RUnlock()
		return nil, nil, status.Error(codes.NotFound, "job not found for step")
	}
	s.mu.RUnlock()

	projectRow, err := s.queries.GetProjectByIDInternal(ctx, uuid.MustParse(job.ProjectID))
	if err != nil {
		return nil, nil, status.Errorf(codes.NotFound, "project for job_id %q not found: %v", job.ProjectID, err)
	}
	if err := requireAuthorizedMediumProject(ctx, job.ProjectID, projectRow.UserID.String()); err != nil {
		return nil, nil, err
	}
	return step, job, nil
}

func (s *mediumScanServer) requireOwnedMediumJob(ctx context.Context, jobID string) (*jobRuntime, error) {
	s.mu.RLock()
	job, ok := s.jobs[jobID]
	if !ok {
		s.mu.RUnlock()
		return nil, status.Error(codes.NotFound, "job not found")
	}
	s.mu.RUnlock()

	projectRow, err := s.queries.GetProjectByIDInternal(ctx, uuid.MustParse(job.ProjectID))
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "project for job_id %q not found: %v", job.ProjectID, err)
	}
	if err := requireAuthorizedMediumProject(ctx, job.ProjectID, projectRow.UserID.String()); err != nil {
		return nil, err
	}
	return job, nil
}
