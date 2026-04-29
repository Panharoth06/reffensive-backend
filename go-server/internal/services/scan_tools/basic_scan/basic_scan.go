package basicscan

import (
	"context"
	basicpb "go-server/gen/basic"

	emptypb "google.golang.org/protobuf/types/known/emptypb"
)

type basicScanServer struct {
	basicpb.UnimplementedBasicScanServiceServer
	delegate basicpb.BasicScanServiceServer
}

func NewBasicScanServer(delegate basicpb.BasicScanServiceServer) basicpb.BasicScanServiceServer {
	return &basicScanServer{delegate: delegate}
}

func (s *basicScanServer) HealthCheck(ctx context.Context, _ *emptypb.Empty) (*basicpb.HealthCheckResponse, error) {
	return s.delegate.HealthCheck(ctx, &emptypb.Empty{})
}
