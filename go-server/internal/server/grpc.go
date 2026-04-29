package server

import (
	"fmt"

	advgen "go-server/gen/advanced"
	apikeygenerated "go-server/gen/apikey"
	basicgen "go-server/gen/basic"
	catgen "go-server/gen/category"
	mediumpb "go-server/gen/mediumscan"
	projgen "go-server/gen/projectpb"
	sonarqubepb "go-server/gen/sonarqube"
	toolgen "go-server/gen/tool"
	userpb "go-server/gen/user"
	"go-server/internal/database"
	"go-server/internal/interceptor"
	apikeyservices "go-server/internal/services/apikey"
	categoryservices "go-server/internal/services/category"
	projectservices "go-server/internal/services/project"
	advancedscan "go-server/internal/services/scan_tools/advanced_scan"
	basicscan "go-server/internal/services/scan_tools/basic_scan"
	mediumscan "go-server/internal/services/scan_tools/medium_scan"
	sonarqubeservice "go-server/internal/services/sonarqube/service"
	toolservices "go-server/internal/services/tools"
	user_service "go-server/internal/services/user"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

func NewGRPCServer(store *database.Store) (*grpc.Server, error) {
	grpcServer := grpc.NewServer(
		grpc.UnaryInterceptor(interceptor.UserIDUnaryInterceptor),
		grpc.StreamInterceptor(interceptor.UserIDStreamInterceptor),
	)

	projgen.RegisterProjectServiceServer(grpcServer, projectservices.NewProjectServer())
	toolgen.RegisterToolServiceServer(grpcServer, toolservices.NewToolServer())
	catgen.RegisterCategoryServiceServer(grpcServer, categoryservices.NewCategoryServer())

	advancedScanServer, err := advancedscan.NewAdvancedScanServer()
	if err != nil {
		return nil, fmt.Errorf("initialize advanced scan server: %w", err)
	}
	mediumScanServer, err := mediumscan.NewMediumScanServer()
	if err != nil {
		return nil, fmt.Errorf("initialize medium scan server: %w", err)
	}
	mediumpb.RegisterMediumScanServiceServer(grpcServer, mediumScanServer)
	advgen.RegisterAdvancedScanServiceServer(grpcServer, advancedScanServer)
	basicDelegate := basicscan.New(advancedScanServer)
	basicScanServer := basicscan.NewBasicScanServer(basicDelegate)
	basicgen.RegisterBasicScanServiceServer(grpcServer, basicScanServer)
	sonarqubeServer, err := sonarqubeservice.NewScannerServer(store.Queries)
	if err != nil {
		return nil, fmt.Errorf("initialize sonarqube scan server: %w", err)
	}
	sonarqubepb.RegisterSonarqubeServiceServer(grpcServer, sonarqubeServer)
	userpb.RegisterUserServiceServer(grpcServer, user_service.NewServer(store.Queries))
	apikeygenerated.RegisterAPIKeyServiceServer(grpcServer, apikeyservices.NewAPIKeyServer(store.Queries))

	reflection.Register(grpcServer)
	return grpcServer, nil
}
