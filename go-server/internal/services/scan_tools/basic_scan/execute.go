package basicscan

import (
	"context"

	basicpb "go-server/gen/basic"
)

func (s *basicScanServer) submitToDelegate(ctx context.Context, req *basicpb.SubmitScanRequest) (*basicpb.SubmitScanResponse, error) {
	return s.delegate.SubmitScan(ctx, req)
}

func (s *basicScanServer) getStepStatusFromDelegate(ctx context.Context, req *basicpb.GetStepStatusRequest) (*basicpb.GetStepStatusResponse, error) {
	return s.delegate.GetStepStatus(ctx, req)
}

func (s *basicScanServer) getJobStatusFromDelegate(ctx context.Context, req *basicpb.GetJobStatusRequest) (*basicpb.GetJobStatusResponse, error) {
	return s.delegate.GetJobStatus(ctx, req)
}

func (s *basicScanServer) getResultsFromDelegate(ctx context.Context, req *basicpb.GetResultsRequest) (*basicpb.GetResultsResponse, error) {
	return s.delegate.GetResults(ctx, req)
}
