package service

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "go-server/gen/sonarqube"
	db "go-server/internal/database/sqlc"
	"go-server/internal/services/sonarqube/scanner/repository"
)

const scanCancelledMessage = "scan cancelled by user"

func (s *ScannerServer) GetScanDetail(ctx context.Context, req *pb.ScanStatusRequest) (*pb.ScanDetailResponse, error) {
	scan, err := s.getScan(ctx, req.GetScanId())
	if err != nil {
		return nil, err
	}
	return scanDetailResponse(scan), nil
}

func (s *ScannerServer) StopScan(ctx context.Context, req *pb.ScanStatusRequest) (*pb.StopScanResponse, error) {
	scan, err := s.getScan(ctx, req.GetScanId())
	if err != nil {
		return nil, err
	}

	statusText := strings.ToUpper(strings.TrimSpace(scan.Status))
	switch statusText {
	case scanStatusCancelled:
		return &pb.StopScanResponse{
			ScanId:  scan.ID.String(),
			Status:  pb.ScanStatus_SCAN_STATUS_CANCELLED,
			Message: "scan already cancelled",
		}, nil
	case scanStatusPending:
		s.updateProgress(ctx, scan.ID, 100)
		s.updateStatus(ctx, scan.ID, scanStatusCancelled, scanCancelledMessage)
		_ = s.scanRepo.SetFinishedAt(ctx, scan.ID.String(), time.Now())
		s.completeScanLog(scan.ID, scanStatusCancelled, scanCancelledMessage)
	case scanStatusRunning:
		s.updateProgress(ctx, scan.ID, 100)
		s.updateStatus(ctx, scan.ID, scanStatusCancelled, scanCancelledMessage)
		s.cancelRunningScan(scan.ID.String())
	default:
		if isTerminalStatus(statusText) {
			return nil, status.Error(codes.FailedPrecondition, "scan is already finished")
		}
		return nil, status.Errorf(codes.FailedPrecondition, "scan cannot be stopped from status %s", statusText)
	}

	return &pb.StopScanResponse{
		ScanId:  scan.ID.String(),
		Status:  pb.ScanStatus_SCAN_STATUS_CANCELLED,
		Message: scanCancelledMessage,
	}, nil
}

func (s *ScannerServer) RetryScan(ctx context.Context, req *pb.ScanStatusRequest) (*pb.RetryScanResponse, error) {
	scan, err := s.getScan(ctx, req.GetScanId())
	if err != nil {
		return nil, err
	}
	if !isTerminalStatus(scan.Status) {
		return nil, status.Error(codes.FailedPrecondition, "scan must be finished before retry")
	}

	repoURL := strings.TrimSpace(text(scan.RepositoryUrl))
	if err := validateHTTPRepoURL(repoURL); err != nil {
		return nil, status.Error(codes.FailedPrecondition, "scan cannot be retried because repo_url is invalid")
	}

	retryReq := &pb.TriggerScanRequest{
		ProjectKey: strings.TrimSpace(scan.ProjectKey),
		Branch:     strings.TrimSpace(text(scan.Branch)),
		RepoUrl:    repoURL,
	}
	triggerResp, err := s.TriggerScan(ctx, retryReq)
	if err != nil {
		return nil, err
	}

	return &pb.RetryScanResponse{
		SourceScanId: scan.ID.String(),
		ScanId:       triggerResp.GetScanId(),
		Status:       triggerResp.GetStatus(),
		CreatedAt:    triggerResp.GetCreatedAt(),
	}, nil
}

func (s *ScannerServer) DeleteScan(ctx context.Context, req *pb.ScanStatusRequest) (*pb.DeleteScanResponse, error) {
	scan, err := s.getScan(ctx, req.GetScanId())
	if err != nil {
		return nil, err
	}
	if !isTerminalStatus(scan.Status) {
		return nil, status.Error(codes.FailedPrecondition, "running scans must be stopped before delete")
	}

	deleted, err := s.scanRepo.Delete(ctx, scan.ID.String())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "delete scan: %v", err)
	}
	if deleted == 0 {
		return nil, status.Error(codes.NotFound, "scan not found")
	}
	s.cancelRunningScan(scan.ID.String())
	s.deleteScanLogs(ctx, scan.ID.String())

	return &pb.DeleteScanResponse{
		ScanId:  scan.ID.String(),
		Deleted: true,
	}, nil
}

func scanDetailResponse(scan db.Scan) *pb.ScanDetailResponse {
	return &pb.ScanDetailResponse{
		ScanId:          scan.ID.String(),
		ProjectKey:      scan.ProjectKey,
		SonarProjectKey: text(scan.SonarProjectKey),
		RepoUrl:         text(scan.RepositoryUrl),
		Branch:          text(scan.Branch),
		Status:          scanStatus(scan.Status),
		Progress:        scan.Progress,
		CreatedAt:       timestamp(scan.CreatedAt),
		StartedAt:       timestamp(scan.StartedAt),
		FinishedAt:      timestamp(scan.FinishedAt),
		ErrorMessage:    text(scan.ErrorMessage),
		Phases: []*pb.ScanPhase{
			phase("clone", scan.CloneStatus, scan.CloneError),
			phase("sonarqube", scan.SonarqubeStatus, scan.SonarqubeError),
			phase("dependency", scan.OwaspStatus, scan.OwaspError),
		},
	}
}

func (s *ScannerServer) registerRunningScan(scanID string, cancel context.CancelFunc) {
	if cancel == nil {
		return
	}
	s.runningScanMu.Lock()
	defer s.runningScanMu.Unlock()
	s.runningScanCancels[scanID] = cancel
}

func (s *ScannerServer) unregisterRunningScan(scanID string) {
	s.runningScanMu.Lock()
	defer s.runningScanMu.Unlock()
	delete(s.runningScanCancels, scanID)
}

func (s *ScannerServer) cancelRunningScan(scanID string) {
	s.runningScanMu.Lock()
	cancel := s.runningScanCancels[scanID]
	s.runningScanMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (s *ScannerServer) monitorScanCancellation(ctx context.Context, scanID uuid.UUID, cancel context.CancelFunc) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			scan, err := s.scanRepo.RawByUUID(context.Background(), scanID)
			if err != nil {
				if repository.IsNotFound(err) || errors.Is(err, pgx.ErrNoRows) {
					cancel()
					return
				}
				continue
			}
			if strings.EqualFold(scan.Status, scanStatusCancelled) {
				cancel()
				return
			}
		}
	}
}

func (s *ScannerServer) scanMarkedCancelled(ctx context.Context, scanID uuid.UUID) bool {
	scan, err := s.scanRepo.RawByUUID(ctx, scanID)
	if err != nil {
		return false
	}
	return strings.EqualFold(scan.Status, scanStatusCancelled)
}

func (s *ScannerServer) finalizeCancelledScan(ctx context.Context, scanID uuid.UUID) {
	s.updateProgress(ctx, scanID, 100)
	s.updateStatus(ctx, scanID, scanStatusCancelled, scanCancelledMessage)
	_ = s.scanRepo.SetFinishedAt(ctx, scanID.String(), time.Now())
	s.completeScanLog(scanID, scanStatusCancelled, scanCancelledMessage)
}

func (s *ScannerServer) deleteScanLogs(ctx context.Context, scanID string) {
	if s.redisClient == nil {
		return
	}
	_, _ = s.redisClient.Del(ctx, s.scanLogHistoryKey(scanID), s.scanLogSequenceKey(scanID)).Result()
}
