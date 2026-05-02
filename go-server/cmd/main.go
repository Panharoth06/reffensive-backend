package main

import (
	"log"
	"net"
	"os"
	"strings"

	advgen "go-server/gen/advanced"
	apikeygenerated "go-server/gen/apikey"
	basicgen "go-server/gen/basic"
	catgen "go-server/gen/category"
	mediumpb "go-server/gen/mediumscan"
	projgen "go-server/gen/projectpb"
	targetgen "go-server/gen/target"
	suggestiongen "go-server/gen/suggestion"
	sonarpb "go-server/gen/sonarqube"
	toolgen "go-server/gen/tool"
	userpb "go-server/gen/user"
	"go-server/internal/database"
	"go-server/internal/interceptor"
	aisuggestion "go-server/internal/services/ai_suggestion"
	apikeyservices "go-server/internal/services/apikey"
	categoryservices "go-server/internal/services/category"
	projectservices "go-server/internal/services/project"
	advancedscan "go-server/internal/services/scan_tools/advanced_scan"
	basicscan "go-server/internal/services/scan_tools/basic_scan"
	mediumscan "go-server/internal/services/scan_tools/medium_scan"
	targetservices "go-server/internal/services/target"
	sonarqubehandler "go-server/internal/services/sonarqube/handler"
	sonarqubeservice "go-server/internal/services/sonarqube/service"
	toolservices "go-server/internal/services/tools"
	user_service "go-server/internal/services/user"
	redisutil "go-server/redis"

	"google.golang.org/grpc"
)

func main() {
	store, err := database.ConnectAndMigrate()
	if err != nil {
		log.Fatalf("failed to initialize database: %v", err)
	}

	// Initialize the shared queue manager (singleton for ALL scan services).
	// Basic and medium scan services will register their handlers with this same manager.
	redisAddr := envOrDefault("REDIS_ADDR", "localhost:6379")
	queueCfg := redisutil.ConfigFromEnv()
	if err := redisutil.InitManager(redisAddr, queueCfg); err != nil {
		log.Fatalf("failed to initialize queue manager: %v", err)
	}
	log.Printf("queue manager initialized (maxConcurrent=%d, maxQueueCapacity=%d)",
		queueCfg.MaxConcurrent, queueCfg.MaxQueueCapacity)

	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	grpcServer := grpc.NewServer(
		grpc.UnaryInterceptor(interceptor.UserIDUnaryInterceptor),
		grpc.StreamInterceptor(interceptor.UserIDStreamInterceptor),
	)

	projgen.RegisterProjectServiceServer(grpcServer, projectservices.NewProjectServer())
	toolgen.RegisterToolServiceServer(grpcServer, toolservices.NewToolServer())
	catgen.RegisterCategoryServiceServer(grpcServer, categoryservices.NewCategoryServer())
	advancedScanServer, err := advancedscan.NewAdvancedScanServer()
	if err != nil {
		log.Fatalf("failed to initialize advanced scan server: %v", err)
	}
	mediumScanServer, err := mediumscan.NewMediumScanServer()
	if err != nil {
		log.Fatalf("failed to initialize medium scan server: %v", err)
	}
	mediumpb.RegisterMediumScanServiceServer(grpcServer, mediumScanServer)
	advgen.RegisterAdvancedScanServiceServer(grpcServer, advancedScanServer)
	suggestionServer, err := aisuggestion.NewSuggestionServer()
	if err != nil {
		log.Fatalf("failed to initialize suggestion server: %v", err)
	}
	suggestiongen.RegisterSuggestionServiceServer(grpcServer, suggestionServer)
	basicDelegate := basicscan.New(advancedScanServer)
	basicScanServer := basicscan.NewBasicScanServer(basicDelegate)
	basicgen.RegisterBasicScanServiceServer(grpcServer, basicScanServer)
	// 3. Register our service implementation
	userpb.RegisterUserServiceServer(grpcServer, user_service.NewServer(store.Queries))

	// Register new API Key service
	apikeygenerated.RegisterAPIKeyServiceServer(grpcServer, apikeyservices.NewAPIKeyServer(store.Queries))

	// Register Target service
	targetgen.RegisterTargetServiceServer(grpcServer, targetservices.NewTargetServer())
	// Register SonarQube Scanner service
	scannerService, err := sonarqubeservice.NewScannerServer(store.Queries)
	if err != nil {
		log.Fatalf("failed to initialize sonarqube scanner service: %v", err)
	}
	scannerHandler := sonarqubehandler.NewScannerHandler(scannerService)
	sonarpb.RegisterSonarqubeServiceServer(grpcServer, scannerHandler)

	log.Printf("gRPC server listening at %v", lis.Addr())

	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}

func envOrDefault(key, fallback string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	return v
}
