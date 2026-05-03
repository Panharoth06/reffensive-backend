package service

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "go-server/gen/sonarqube"
	db "go-server/internal/database/sqlc"
	sonarqubequeue "go-server/internal/services/sonarqube/queue"
	"go-server/internal/services/sonarqube/scanner/repository"
)

// GetScanStatus returns current scan status, phase status, and progress.
func (s *ScannerServer) GetScanStatus(ctx context.Context, req *pb.ScanStatusRequest) (*pb.ScanStatusResponse, error) {
	scan, err := s.getScan(ctx, req.GetScanId())
	if err != nil {
		return nil, err
	}
	return scanStatusResponse(scan), nil
}

// StreamScanStatus streams scan status updates until the scan reaches a terminal state.
func (s *ScannerServer) StreamScanStatus(req *pb.ScanStatusRequest, stream pb.SonarqubeService_StreamScanStatusServer) error {
	scanID, err := uuid.Parse(strings.TrimSpace(req.GetScanId()))
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "invalid scan_id: %v", err)
	}
	if _, err := s.getScan(stream.Context(), req.GetScanId()); err != nil {
		return err
	}

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		scan, err := s.scanRepo.RawByUUID(stream.Context(), scanID)
		if err != nil {
			return status.Errorf(codes.Internal, "read scan: %v", err)
		}
		if err := stream.Send(scanStatusResponse(scan)); err != nil {
			return err
		}
		if isTerminalStatus(scan.Status) {
			return nil
		}
		select {
		case <-stream.Context().Done():
			return stream.Context().Err()
		case <-ticker.C:
		}
	}
}

func (s *ScannerServer) getScan(ctx context.Context, rawID string) (db.Scan, error) {
	scanID, err := parseScanID(rawID)
	if err != nil {
		return db.Scan{}, err
	}
	userID, err := requireCurrentUserUUID(ctx)
	if err != nil {
		return db.Scan{}, err
	}
	scan, err := s.scanRepo.RawByUUID(ctx, scanID)
	if err != nil {
		if repository.IsNotFound(err) || errors.Is(err, pgx.ErrNoRows) {
			return db.Scan{}, status.Error(codes.NotFound, "scan not found")
		}
		return db.Scan{}, status.Errorf(codes.Internal, "read scan: %v", err)
	}
	if scan.UserID != userID {
		return db.Scan{}, status.Error(codes.NotFound, "scan not found")
	}
	return scan, nil
}

func (s *ScannerServer) updateProgress(ctx context.Context, scanID uuid.UUID, progress int32) {
	if err := s.scanRepo.UpdateProgress(ctx, scanID.String(), progress); err == nil {
		s.publishProgress(ctx, sonarqubequeue.ProgressEvent{
			ScanID:   scanID.String(),
			Type:     "progress",
			Progress: progress,
		})
	}
}

func (s *ScannerServer) updateStatus(ctx context.Context, scanID uuid.UUID, scanStatus, message string) {
	if err := s.scanRepo.UpdateStatus(ctx, scanID.String(), scanStatus, message); err == nil {
		s.publishProgress(ctx, sonarqubequeue.ProgressEvent{
			ScanID:       scanID.String(),
			Type:         "status",
			Status:       scanStatus,
			ErrorMessage: message,
		})
	}
}

func (s *ScannerServer) updatePhase(ctx context.Context, scanID uuid.UUID, phase, phaseStatus, message string) {
	if err := s.scanRepo.UpdatePhase(ctx, scanID.String(), phase, phaseStatus, message); err == nil {
		s.publishProgress(ctx, sonarqubequeue.ProgressEvent{
			ScanID:       scanID.String(),
			Type:         "phase",
			Phase:        phase,
			Status:       phaseStatus,
			ErrorMessage: message,
		})
	}
}

func (s *ScannerServer) publishProgress(ctx context.Context, event sonarqubequeue.ProgressEvent) {
	if s.progressPub == nil {
		return
	}
	_ = s.progressPub.Publish(ctx, event)
}

func parseScanID(raw string) (uuid.UUID, error) {
	scanID, err := uuid.Parse(strings.TrimSpace(raw))
	if err != nil {
		return uuid.Nil, status.Errorf(codes.InvalidArgument, "invalid scan_id: %v", err)
	}
	return scanID, nil
}

func normalizePage(page, pageSize int32) (int32, int32) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = defaultDependencyPage
	}
	if pageSize > 500 {
		pageSize = 500
	}
	return page, pageSize
}

func scanStatusResponse(scan db.Scan) *pb.ScanStatusResponse {
	return &pb.ScanStatusResponse{
		ScanId:       scan.ID.String(),
		Status:       scanStatus(scan.Status),
		Progress:     scan.Progress,
		StartedAt:    timestamp(scan.StartedAt),
		FinishedAt:   timestamp(scan.FinishedAt),
		ErrorMessage: text(scan.ErrorMessage),
		Phases: []*pb.ScanPhase{
			phase("clone", scan.CloneStatus, scan.CloneError),
			phase("sonarqube", scan.SonarqubeStatus, scan.SonarqubeError),
			phase("dependency", scan.OwaspStatus, scan.OwaspError),
		},
	}
}

func phase(key, value string, errText pgtype.Text) *pb.ScanPhase {
	return &pb.ScanPhase{
		Key:          key,
		Status:       phaseResponseStatus(value),
		ErrorMessage: text(errText),
	}
}

func phaseResponseStatus(value string) string {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case phaseStatusRunning:
		return "RUNNING"
	case phaseStatusDone:
		return "DONE"
	case phaseStatusFailed:
		return "FAILED"
	case "SKIPPED":
		return "SKIPPED"
	default:
		return "PENDING"
	}
}

func scanStatus(value string) pb.ScanStatus {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case scanStatusPending:
		return pb.ScanStatus_SCAN_STATUS_PENDING
	case scanStatusRunning:
		return pb.ScanStatus_SCAN_STATUS_IN_PROGRESS
	case scanStatusSuccess:
		return pb.ScanStatus_SCAN_STATUS_SUCCESS
	case scanStatusFailed:
		return pb.ScanStatus_SCAN_STATUS_FAILED
	case scanStatusPartial:
		return pb.ScanStatus_SCAN_STATUS_PARTIAL
	case scanStatusCancelled:
		return pb.ScanStatus_SCAN_STATUS_CANCELLED
	default:
		return pb.ScanStatus_SCAN_STATUS_UNSPECIFIED
	}
}

func isTerminalStatus(value string) bool {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case scanStatusSuccess, scanStatusFailed, scanStatusPartial, scanStatusCancelled:
		return true
	default:
		return false
	}
}
