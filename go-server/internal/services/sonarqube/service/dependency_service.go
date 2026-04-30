package service

import (
	"context"
	"strings"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "go-server/gen/sonarqube"
	"go-server/internal/services/sonarqube/scanner/dependency"
	"go-server/internal/services/sonarqube/scanner/repository"
)

func (s *ScannerServer) ListDependencies(ctx context.Context, req *pb.ListDependenciesRequest) (*pb.ListDependenciesResponse, error) {
	scanID, err := parseScanID(req.GetScanId())
	if err != nil {
		return nil, err
	}
	page, pageSize := normalizePage(req.GetPage(), req.GetPageSize())

	items, total, err := s.depRepo.ListFindings(ctx, scanID.String(), repository.DependencyFilters{
		Tool:           dependencyToolFilter(req.GetTool()),
		Severity:       req.GetSeverity(),
		Ecosystems:     nil,
		Languages:      dependencyLanguages(req.GetLanguages()),
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
		ByLanguage:    make([]*pb.LanguageSummary, 0, len(summary.ByLanguage)),
	}
	for _, item := range summary.ByLanguage {
		resp.ByLanguage = append(resp.ByLanguage, &pb.LanguageSummary{
			Language:               languageEnum(item.Language),
			TotalDependencies:      item.Total,
			VulnerableDependencies: item.Vulnerable,
			OutdatedDependencies:   item.Outdated,
			LicenseIssues:          item.LicenseIssues,
		})
	}
	return resp, nil
}

func (s *ScannerServer) saveDependencyFindings(ctx context.Context, scanID uuid.UUID, findings []*dependency.Finding) error {
	if len(findings) == 0 {
		return nil
	}
	return s.depRepo.SaveFindings(ctx, scanID.String(), normalizeDependencyFindings(findings))
}

func dependencyRows(items []*repository.Dependency) []*pb.Dependency {
	result := make([]*pb.Dependency, 0, len(items))
	for _, item := range items {
		if item == nil {
			continue
		}
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
			Tool:             dependencyToolEnum(item.Tool),
			Language:         languageEnum(item.Language),
		})
	}
	return result
}

func normalizeDependencyFindings(findings []*dependency.Finding) []*dependency.Finding {
	result := make([]*dependency.Finding, 0, len(findings))
	for _, finding := range findings {
		if finding == nil {
			continue
		}
		if strings.TrimSpace(finding.Tool) == "" {
			finding.Tool = "dependency"
		}
		result = append(result, finding)
	}
	return result
}

func dependencyToolFilter(tool pb.DependencyTool) string {
	switch tool {
	case pb.DependencyTool_DEPENDENCY_TOOL_GOVULNCHECK:
		return "GOVULNCHECK"
	case pb.DependencyTool_DEPENDENCY_TOOL_PIP_AUDIT:
		return "PIP-AUDIT"
	case pb.DependencyTool_DEPENDENCY_TOOL_NPM_AUDIT:
		return "NPM-AUDIT"
	case pb.DependencyTool_DEPENDENCY_TOOL_MVN_DEPENDENCY_CHECK:
		return "MVN-DEPENDENCY-CHECK"
	case pb.DependencyTool_DEPENDENCY_TOOL_GRADLE_DEPENDENCY_CHECK:
		return "GRADLE-DEPENDENCY-CHECK"
	case pb.DependencyTool_DEPENDENCY_TOOL_COMPOSER_AUDIT:
		return "COMPOSER-AUDIT"
	case pb.DependencyTool_DEPENDENCY_TOOL_CARGO_AUDIT:
		return "CARGO-AUDIT"
	case pb.DependencyTool_DEPENDENCY_TOOL_BUNDLER_AUDIT:
		return "BUNDLER-AUDIT"
	case pb.DependencyTool_DEPENDENCY_TOOL_DOTNET_AUDIT:
		return "DOTNET-AUDIT"
	case pb.DependencyTool_DEPENDENCY_TOOL_SWIFT_AUDIT:
		return "SWIFT-AUDIT"
	case pb.DependencyTool_DEPENDENCY_TOOL_DART_PUB_AUDIT:
		return "DART-PUB-AUDIT"
	case pb.DependencyTool_DEPENDENCY_TOOL_ALL, pb.DependencyTool_DEPENDENCY_TOOL_UNSPECIFIED:
		return ""
	default:
		return ""
	}
}

func dependencyToolEnum(tool string) pb.DependencyTool {
	switch strings.ToUpper(strings.TrimSpace(tool)) {
	case "GOVULNCHECK":
		return pb.DependencyTool_DEPENDENCY_TOOL_GOVULNCHECK
	case "PIP-AUDIT":
		return pb.DependencyTool_DEPENDENCY_TOOL_PIP_AUDIT
	case "NPM-AUDIT":
		return pb.DependencyTool_DEPENDENCY_TOOL_NPM_AUDIT
	case "MVN-DEPENDENCY-CHECK":
		return pb.DependencyTool_DEPENDENCY_TOOL_MVN_DEPENDENCY_CHECK
	case "GRADLE-DEPENDENCY-CHECK":
		return pb.DependencyTool_DEPENDENCY_TOOL_GRADLE_DEPENDENCY_CHECK
	case "COMPOSER-AUDIT":
		return pb.DependencyTool_DEPENDENCY_TOOL_COMPOSER_AUDIT
	case "CARGO-AUDIT":
		return pb.DependencyTool_DEPENDENCY_TOOL_CARGO_AUDIT
	case "BUNDLER-AUDIT":
		return pb.DependencyTool_DEPENDENCY_TOOL_BUNDLER_AUDIT
	case "DOTNET-AUDIT":
		return pb.DependencyTool_DEPENDENCY_TOOL_DOTNET_AUDIT
	case "SWIFT-AUDIT":
		return pb.DependencyTool_DEPENDENCY_TOOL_SWIFT_AUDIT
	case "DART-PUB-AUDIT":
		return pb.DependencyTool_DEPENDENCY_TOOL_DART_PUB_AUDIT
	default:
		return pb.DependencyTool_DEPENDENCY_TOOL_UNSPECIFIED
	}
}

func dependencyLanguages(languages []pb.Language) []string {
	result := make([]string, 0, len(languages))
	for _, language := range languages {
		switch language {
		case pb.Language_LANGUAGE_GO:
			result = append(result, "GO")
		case pb.Language_LANGUAGE_PYTHON:
			result = append(result, "PYTHON")
		case pb.Language_LANGUAGE_NODE:
			result = append(result, "NODE")
		case pb.Language_LANGUAGE_JAVA:
			result = append(result, "JAVA")
		case pb.Language_LANGUAGE_KOTLIN:
			result = append(result, "KOTLIN")
		case pb.Language_LANGUAGE_PHP:
			result = append(result, "PHP")
		case pb.Language_LANGUAGE_RUST:
			result = append(result, "RUST")
		case pb.Language_LANGUAGE_RUBY:
			result = append(result, "RUBY")
		case pb.Language_LANGUAGE_DOTNET:
			result = append(result, "DOTNET")
		case pb.Language_LANGUAGE_SWIFT:
			result = append(result, "SWIFT")
		case pb.Language_LANGUAGE_DART:
			result = append(result, "DART")
		}
	}
	return result
}

func languageEnum(language string) pb.Language {
	switch strings.ToUpper(strings.TrimSpace(language)) {
	case "GO":
		return pb.Language_LANGUAGE_GO
	case "PYTHON":
		return pb.Language_LANGUAGE_PYTHON
	case "NODE":
		return pb.Language_LANGUAGE_NODE
	case "JAVA":
		return pb.Language_LANGUAGE_JAVA
	case "KOTLIN":
		return pb.Language_LANGUAGE_KOTLIN
	case "PHP":
		return pb.Language_LANGUAGE_PHP
	case "RUST":
		return pb.Language_LANGUAGE_RUST
	case "RUBY":
		return pb.Language_LANGUAGE_RUBY
	case "DOTNET":
		return pb.Language_LANGUAGE_DOTNET
	case "SWIFT":
		return pb.Language_LANGUAGE_SWIFT
	case "DART":
		return pb.Language_LANGUAGE_DART
	default:
		return pb.Language_LANGUAGE_UNSPECIFIED
	}
}
