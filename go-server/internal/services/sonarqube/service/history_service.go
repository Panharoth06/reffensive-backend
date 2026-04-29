package service

import (
	"context"

	pb "go-server/gen/sonarqube"
)

// ListProjectScans returns scan history for a project.
func (s *ScannerServer) ListProjectScans(ctx context.Context, req *pb.ProjectScansRequest) (*pb.ProjectScansResponse, error) {
	return s.ListTriggeredScans(ctx, req)
}
