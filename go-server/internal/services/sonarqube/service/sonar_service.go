package service

import (
	"context"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "go-server/gen/sonarqube"
	"go-server/internal/services/sonarqube/scanner/sonar"
)

// GetScanSummary returns SonarQube quality gate data with dependency summary.
func (s *ScannerServer) GetScanSummary(ctx context.Context, req *pb.ScanSummaryRequest) (*pb.ScanSummaryResponse, error) {
	scan, err := s.getScan(ctx, req.GetScanId())
	if err != nil {
		return nil, err
	}
	scanID := scan.ID

	sonarResult, err := s.sonarRepo.GetResult(ctx, scanID.String())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read sonar summary: %v", err)
	}
	depSummary, err := s.dependencySummary(ctx, scanID)
	if err != nil {
		return nil, err
	}

	return &pb.ScanSummaryResponse{
		ScanId:            scanID.String(),
		QualityGate:       qualityGateStatus(sonarResult.QualityGate),
		Bugs:              sonarResult.Bugs,
		Vulnerabilities:   sonarResult.Vulnerabilities,
		CodeSmells:        sonarResult.CodeSmells,
		Coverage:          sonarResult.Coverage,
		Duplications:      sonarResult.Duplications,
		SecurityHotspots:  sonarResult.SecurityHotspots,
		DependencySummary: depSummary,
	}, nil
}

// ListIssues returns a paginated list of SonarQube issues for a scan.
func (s *ScannerServer) ListIssues(ctx context.Context, req *pb.ListIssuesRequest) (*pb.ListIssuesResponse, error) {
	scan, err := s.getScan(ctx, req.GetScanId())
	if err != nil {
		return nil, err
	}
	sonarProjectKey := strings.TrimSpace(text(scan.SonarProjectKey))
	if sonarProjectKey == "" {
		sonarProjectKey = sonar.GenerateSonarProjectKey(scan.ProjectKey, scan.ID.String())
	}
	page, pageSize := normalizePage(req.GetPage(), req.GetPageSize())
	filters := sonar.IssueFilters{}
	if req.TypeFilter != nil && strings.TrimSpace(req.GetTypeFilter()) != "" {
		filters["types"] = strings.TrimSpace(req.GetTypeFilter())
	}
	if req.SeverityFilter != nil && strings.TrimSpace(req.GetSeverityFilter()) != "" {
		filters["severities"] = strings.TrimSpace(req.GetSeverityFilter())
	}
	issues, total, err := s.sonarClient.FetchIssues(ctx, sonarProjectKey, filters, int(page), int(pageSize))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "fetch sonar issues: %v", err)
	}
	return &pb.ListIssuesResponse{
		Issues:   sonarIssues(issues),
		Page:     page,
		PageSize: pageSize,
		Total:    int32(total),
	}, nil
}

// GetIssueDetail returns detailed information about a SonarQube issue.
func (s *ScannerServer) GetIssueDetail(ctx context.Context, req *pb.IssueDetailRequest) (*pb.IssueDetailResponse, error) {
	if _, err := s.getScan(ctx, req.GetScanId()); err != nil {
		return nil, err
	}
	detail, err := s.sonarClient.FetchIssueDetail(ctx, req.GetIssueKey())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "fetch sonar issue detail: %v", err)
	}
	return issueDetailResponse(detail), nil
}

// GetFileIssues returns SonarQube issues associated with a specific file.
func (s *ScannerServer) GetFileIssues(ctx context.Context, req *pb.FileIssuesRequest) (*pb.FileIssuesResponse, error) {
	scan, err := s.getScan(ctx, req.GetScanId())
	if err != nil {
		return nil, err
	}
	sonarProjectKey := strings.TrimSpace(text(scan.SonarProjectKey))
	if sonarProjectKey == "" {
		sonarProjectKey = sonar.GenerateSonarProjectKey(scan.ProjectKey, scan.ID.String())
	}
	filePath := strings.TrimSpace(req.GetFilePath())
	if filePath == "" {
		return nil, status.Error(codes.InvalidArgument, "file_path is required")
	}
	issues, _, err := s.sonarClient.FetchIssues(ctx, sonarProjectKey, sonar.IssueFilters{"files": filePath}, 1, 500)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "fetch sonar file issues: %v", err)
	}
	return &pb.FileIssuesResponse{Issues: sonarIssues(issues)}, nil
}

func qualityGateStatus(value string) pb.QualityGateStatus {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "OK":
		return pb.QualityGateStatus_QUALITY_GATE_STATUS_OK
	case "WARN":
		return pb.QualityGateStatus_QUALITY_GATE_STATUS_WARN
	case "ERROR":
		return pb.QualityGateStatus_QUALITY_GATE_STATUS_ERROR
	default:
		return pb.QualityGateStatus_QUALITY_GATE_STATUS_UNSPECIFIED
	}
}

func sonarIssues(items []*sonar.Issue) []*pb.Issue {
	result := make([]*pb.Issue, 0, len(items))
	for _, item := range items {
		if item == nil {
			continue
		}
		result = append(result, &pb.Issue{
			Key:      item.Key,
			Type:     item.Type,
			Severity: item.Severity,
			RuleKey:  item.RuleKey,
			Message:  item.Message,
			FilePath: item.FilePath,
			Line:     item.Line,
			Status:   item.Status,
			Tags:     item.Tags,
		})
	}
	return result
}

func issueDetailResponse(detail *sonar.IssueDetail) *pb.IssueDetailResponse {
	if detail == nil {
		return &pb.IssueDetailResponse{}
	}
	return &pb.IssueDetailResponse{
		WhereIsIssue: &pb.IssueWhere{
			ComponentKey: detail.WhereIsIssue.ComponentKey,
			FilePath:     detail.WhereIsIssue.FilePath,
			Line:         detail.WhereIsIssue.Line,
			TextRange: &pb.TextRange{
				StartLine:   detail.WhereIsIssue.TextRange.StartLine,
				EndLine:     detail.WhereIsIssue.TextRange.EndLine,
				StartOffset: detail.WhereIsIssue.TextRange.StartOffset,
				EndOffset:   detail.WhereIsIssue.TextRange.EndOffset,
			},
			CodeSnippet: detail.WhereIsIssue.CodeSnippet,
		},
		WhyIsIssue: &pb.IssueWhy{
			IssueMessage: detail.WhyIsIssue.IssueMessage,
			Severity:     detail.WhyIsIssue.Severity,
			Status:       detail.WhyIsIssue.Status,
			Tags:         detail.WhyIsIssue.Tags,
			RuleKey:      detail.WhyIsIssue.RuleKey,
			RuleName:     detail.WhyIsIssue.RuleName,
			HtmlDesc:     detail.WhyIsIssue.HTMLDesc,
		},
		Activity: &pb.IssueActivity{
			Comments:  activityComments(detail.Activity.Comments),
			Changelog: activityChanges(detail.Activity.Changelog),
		},
		MoreInfo: &pb.IssueMoreInfo{
			DocumentationUrl:    detail.MoreInfo.DocumentationURL,
			DescriptionSections: descriptionSections(detail.MoreInfo.DescriptionSections),
		},
	}
}

func activityComments(items []sonar.ActivityComment) []*pb.ActivityComment {
	result := make([]*pb.ActivityComment, 0, len(items))
	for _, item := range items {
		result = append(result, &pb.ActivityComment{
			Key:       item.Key,
			Login:     item.Login,
			HtmlText:  item.HTMLText,
			CreatedAt: item.CreatedAt,
		})
	}
	return result
}

func activityChanges(items []sonar.ActivityChange) []*pb.ActivityChange {
	result := make([]*pb.ActivityChange, 0, len(items))
	for _, item := range items {
		result = append(result, &pb.ActivityChange{
			CreatedAt: item.CreatedAt,
			User:      item.User,
			Diffs:     activityDiffs(item.Diffs),
		})
	}
	return result
}

func activityDiffs(items []sonar.ActivityDiff) []*pb.ActivityDiff {
	result := make([]*pb.ActivityDiff, 0, len(items))
	for _, item := range items {
		result = append(result, &pb.ActivityDiff{
			Key:      item.Key,
			OldValue: item.OldValue,
			NewValue: item.NewValue,
		})
	}
	return result
}

func descriptionSections(items []sonar.DescriptionSection) []*pb.DescriptionSection {
	result := make([]*pb.DescriptionSection, 0, len(items))
	for _, item := range items {
		result = append(result, &pb.DescriptionSection{Key: item.Key, Content: item.Content})
	}
	return result
}
