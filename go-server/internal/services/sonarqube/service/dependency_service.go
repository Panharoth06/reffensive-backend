package service

import (
	"context"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "go-server/gen/sonarqube"
	"go-server/internal/services/sonarqube/scanner/owasp"
	"go-server/internal/services/sonarqube/scanner/repository"
	"go-server/internal/services/sonarqube/scanner/trivy"
)

// ListDependencies returns paginated dependency scan results with filters.
func (s *ScannerServer) ListDependencies(ctx context.Context, req *pb.ListDependenciesRequest) (*pb.ListDependenciesResponse, error) {
	scanID, err := parseScanID(req.GetScanId())
	if err != nil {
		return nil, err
	}
	page, pageSize := normalizePage(req.GetPage(), req.GetPageSize())

	items, total, err := s.depRepo.ListFindings(ctx, scanID.String(), repository.DependencyFilters{
		Tool:           req.GetTool(),
		Severity:       req.GetSeverity(),
		Ecosystems:     req.GetEcosystems(),
		OutdatedOnly:   req.GetOutdatedOnly(),
		VulnerableOnly: req.GetVulnerableOnly(),
		Page:           page,
		PageSize:       pageSize,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list dependencies: %v", err)
	}
	return &pb.ListDependenciesResponse{
		Dependencies: dependencyRows(items),
		Page:         page,
		PageSize:     pageSize,
		Total:        total,
	}, nil
}

// GetDependencySummary returns aggregated dependency scan metrics.
func (s *ScannerServer) GetDependencySummary(ctx context.Context, req *pb.ScanSummaryRequest) (*pb.DependencySummaryResponse, error) {
	scanID, err := parseScanID(req.GetScanId())
	if err != nil {
		return nil, err
	}
	return s.dependencySummary(ctx, scanID)
}

func (s *ScannerServer) dependencySummary(ctx context.Context, scanID uuid.UUID) (*pb.DependencySummaryResponse, error) {
	summary, err := s.depRepo.GetSummary(ctx, scanID.String())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read dependency summary: %v", err)
	}
	resp := &pb.DependencySummaryResponse{
		ScanId:        summary.ScanID,
		Total:         summary.Total,
		Vulnerable:    summary.Vulnerable,
		Outdated:      summary.Outdated,
		LicenseIssues: summary.LicenseIssues,
		Critical:      summary.Critical,
		High:          summary.High,
		Medium:        summary.Medium,
		Low:           summary.Low,
		ByEcosystem:   make([]*pb.EcosystemSummary, 0, len(summary.ByEcosystem)),
	}
	for _, item := range summary.ByEcosystem {
		resp.ByEcosystem = append(resp.ByEcosystem, &pb.EcosystemSummary{
			Ecosystem: item.Ecosystem,
			Total:     item.Total,
		})
	}
	return resp, nil
}

func (s *ScannerServer) saveOWASPFindings(ctx context.Context, scanID uuid.UUID, findings []*owasp.Dependency) error {
	dependencies := make([]*repository.Dependency, 0, len(findings))
	for _, finding := range findings {
		if finding == nil {
			continue
		}
		dependencies = append(dependencies, &repository.Dependency{
			PackageName:      finding.PackageName,
			InstalledVersion: finding.InstalledVersion,
			CVEID:            finding.CVEID,
			Severity:         finding.Severity,
			License:          finding.License,
			Description:      finding.Description,
			IsVulnerable:     finding.IsVulnerable,
			IsOutdated:       finding.IsOutdated,
			Ecosystem:        finding.Ecosystem,
		})
	}
	return s.depRepo.SaveFindings(ctx, scanID.String(), "OWASP", dependencies)
}

func (s *ScannerServer) saveTrivyFindings(ctx context.Context, scanID uuid.UUID, findings []*trivy.Dependency) error {
	dependencies := make([]*repository.Dependency, 0, len(findings))
	for _, finding := range findings {
		if finding == nil {
			continue
		}
		dependencies = append(dependencies, &repository.Dependency{
			PackageName:      finding.PackageName,
			InstalledVersion: finding.InstalledVersion,
			FixedVersion:     finding.FixedVersion,
			LatestVersion:    finding.LatestVersion,
			CVEID:            finding.CVEID,
			Severity:         finding.Severity,
			License:          finding.License,
			Description:      finding.Description,
			IsVulnerable:     finding.IsVulnerable,
			IsOutdated:       finding.IsOutdated,
			HasLicenseIssue:  finding.HasLicenseIssue,
			Ecosystem:        finding.Ecosystem,
		})
	}
	return s.depRepo.SaveFindings(ctx, scanID.String(), "TRIVY", dependencies)
}

func dependencyRows(items []*repository.Dependency) []*pb.Dependency {
	result := make([]*pb.Dependency, 0, len(items))
	for _, item := range items {
		result = append(result, &pb.Dependency{
			PackageName:      item.PackageName,
			Ecosystem:        item.Ecosystem,
			InstalledVersion: item.InstalledVersion,
			FixedVersion:     item.FixedVersion,
			LatestVersion:    item.LatestVersion,
			CveId:            item.CVEID,
			Severity:         item.Severity,
			License:          item.License,
			IsOutdated:       item.IsOutdated,
			IsVulnerable:     item.IsVulnerable,
			HasLicenseIssue:  item.HasLicenseIssue,
			Description:      item.Description,
			Tool:             item.Tool,
		})
	}
	return result
}
