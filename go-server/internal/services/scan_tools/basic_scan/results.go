package basicscan

import (
	"context"

	basicpb "go-server/gen/basic"
)

func (s *basicScanServer) GetResults(ctx context.Context, req *basicpb.GetResultsRequest) (*basicpb.GetResultsResponse, error) {
	if req == nil {
		req = &basicpb.GetResultsRequest{}
	}
	return s.getResultsFromDelegate(ctx, req)
}
