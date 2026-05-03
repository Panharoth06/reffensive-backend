package handler

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "go-server/gen/sonarqube"
	"go-server/internal/services/sonarqube/service"
)

// ScannerHandler implements SonarqubeServiceServer.
type ScannerHandler struct {
	pb.UnimplementedSonarqubeServiceServer
	scannerService *service.ScannerServer
}

// NewScannerHandler creates a new gRPC handler for scanner service.
func NewScannerHandler(scannerService *service.ScannerServer) *ScannerHandler {
	return &ScannerHandler{
		scannerService: scannerService,
	}
}

// TriggerScan initiates a new scan.
func (h *ScannerHandler) TriggerScan(ctx context.Context, req *pb.TriggerScanRequest) (*pb.TriggerScanResponse, error) {
	resp, err := h.scannerService.TriggerScan(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// GetScanDetail retrieves metadata and phase state for a scan.
func (h *ScannerHandler) GetScanDetail(ctx context.Context, req *pb.ScanStatusRequest) (*pb.ScanDetailResponse, error) {
	if req.GetScanId() == "" {
		return nil, status.Error(codes.InvalidArgument, "scan_id is required")
	}

	resp, err := h.scannerService.GetScanDetail(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// GetScanStatus retrieves the status of a scan.
func (h *ScannerHandler) GetScanStatus(ctx context.Context, req *pb.ScanStatusRequest) (*pb.ScanStatusResponse, error) {
	if req.GetScanId() == "" {
		return nil, status.Error(codes.InvalidArgument, "scan_id is required")
	}

	resp, err := h.scannerService.GetScanStatus(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// StopScan cancels a queued or running scan.
func (h *ScannerHandler) StopScan(ctx context.Context, req *pb.ScanStatusRequest) (*pb.StopScanResponse, error) {
	if req.GetScanId() == "" {
		return nil, status.Error(codes.InvalidArgument, "scan_id is required")
	}

	resp, err := h.scannerService.StopScan(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// RetryScan re-queues a finished scan using the same input.
func (h *ScannerHandler) RetryScan(ctx context.Context, req *pb.ScanStatusRequest) (*pb.RetryScanResponse, error) {
	if req.GetScanId() == "" {
		return nil, status.Error(codes.InvalidArgument, "scan_id is required")
	}

	resp, err := h.scannerService.RetryScan(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// DeleteScan removes a finished scan and its persisted logs.
func (h *ScannerHandler) DeleteScan(ctx context.Context, req *pb.ScanStatusRequest) (*pb.DeleteScanResponse, error) {
	if req.GetScanId() == "" {
		return nil, status.Error(codes.InvalidArgument, "scan_id is required")
	}

	resp, err := h.scannerService.DeleteScan(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// GetScanLogs retrieves buffered logs for a scan.
func (h *ScannerHandler) GetScanLogs(ctx context.Context, req *pb.ScanLogsRequest) (*pb.ScanLogsResponse, error) {
	if req.GetScanId() == "" {
		return nil, status.Error(codes.InvalidArgument, "scan_id is required")
	}

	resp, err := h.scannerService.GetScanLogs(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// StreamScanStatus streams the status of a scan.
func (h *ScannerHandler) StreamScanStatus(req *pb.ScanStatusRequest, stream pb.SonarqubeService_StreamScanStatusServer) error {
	if req.GetScanId() == "" {
		return status.Error(codes.InvalidArgument, "scan_id is required")
	}

	return h.scannerService.StreamScanStatus(req, stream)
}

// StreamScanLogs streams live logs for a scan.
func (h *ScannerHandler) StreamScanLogs(req *pb.StreamScanLogsRequest, stream pb.SonarqubeService_StreamScanLogsServer) error {
	if req.GetScanId() == "" {
		return status.Error(codes.InvalidArgument, "scan_id is required")
	}

	return h.scannerService.StreamScanLogs(req, stream)
}

// GetScanSummary retrieves the summary of a scan.
func (h *ScannerHandler) GetScanSummary(ctx context.Context, req *pb.ScanSummaryRequest) (*pb.ScanSummaryResponse, error) {
	if req.GetScanId() == "" {
		return nil, status.Error(codes.InvalidArgument, "scan_id is required")
	}

	resp, err := h.scannerService.GetScanSummary(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// ListIssues retrieves issues from a scan.
func (h *ScannerHandler) ListIssues(ctx context.Context, req *pb.ListIssuesRequest) (*pb.ListIssuesResponse, error) {
	if req.GetScanId() == "" {
		return nil, status.Error(codes.InvalidArgument, "scan_id is required")
	}

	resp, err := h.scannerService.ListIssues(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// GetIssueDetail retrieves detailed information about a specific issue.
func (h *ScannerHandler) GetIssueDetail(ctx context.Context, req *pb.IssueDetailRequest) (*pb.IssueDetailResponse, error) {
	if req.GetScanId() == "" {
		return nil, status.Error(codes.InvalidArgument, "scan_id is required")
	}
	if req.GetIssueKey() == "" {
		return nil, status.Error(codes.InvalidArgument, "issue_key is required")
	}

	resp, err := h.scannerService.GetIssueDetail(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// GetFileIssues retrieves issues in a specific file.
func (h *ScannerHandler) GetFileIssues(ctx context.Context, req *pb.FileIssuesRequest) (*pb.FileIssuesResponse, error) {
	if req.GetScanId() == "" {
		return nil, status.Error(codes.InvalidArgument, "scan_id is required")
	}
	if req.GetFilePath() == "" {
		return nil, status.Error(codes.InvalidArgument, "file_path is required")
	}

	resp, err := h.scannerService.GetFileIssues(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// ListDependencies retrieves dependency findings from a scan.
func (h *ScannerHandler) ListDependencies(ctx context.Context, req *pb.ListDependenciesRequest) (*pb.ListDependenciesResponse, error) {
	if req.GetScanId() == "" {
		return nil, status.Error(codes.InvalidArgument, "scan_id is required")
	}

	resp, err := h.scannerService.ListDependencies(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// GetDependencySummary retrieves a summary of dependencies in a scan.
func (h *ScannerHandler) GetDependencySummary(ctx context.Context, req *pb.ScanSummaryRequest) (*pb.DependencySummaryResponse, error) {
	if req.GetScanId() == "" {
		return nil, status.Error(codes.InvalidArgument, "scan_id is required")
	}

	resp, err := h.scannerService.GetDependencySummary(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// ListProjectScans retrieves all scans for a project.
func (h *ScannerHandler) ListProjectScans(ctx context.Context, req *pb.ProjectScansRequest) (*pb.ProjectScansResponse, error) {
	if req.GetProjectKey() == "" {
		return nil, status.Error(codes.InvalidArgument, "project_key is required")
	}

	resp, err := h.scannerService.ListProjectScans(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// ListUserScans retrieves scans owned by the current user.
func (h *ScannerHandler) ListUserScans(ctx context.Context, req *pb.UserScansRequest) (*pb.ProjectScansResponse, error) {
	resp, err := h.scannerService.ListUserScans(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}
