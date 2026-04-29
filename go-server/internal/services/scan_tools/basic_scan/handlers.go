package basicscan

import (
	"context"

	basicpb "go-server/gen/basic"
)

func (s *basicScanServer) GetStepStatus(ctx context.Context, req *basicpb.GetStepStatusRequest) (*basicpb.GetStepStatusResponse, error) {
	return s.getStepStatusFromDelegate(ctx, req)
}

func (s *basicScanServer) GetJobStatus(ctx context.Context, req *basicpb.GetJobStatusRequest) (*basicpb.GetJobStatusResponse, error) {
	return s.getJobStatusFromDelegate(ctx, req)
}
