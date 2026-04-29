package repository

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/google/uuid"

	db "go-server/internal/database/sqlc"
)

type Dependency struct {
	PackageName      string `json:"package_name"`
	Ecosystem        string `json:"ecosystem"`
	InstalledVersion string `json:"installed_version"`
	FixedVersion     string `json:"fixed_version"`
	LatestVersion    string `json:"latest_version"`
	CVEID            string `json:"cve_id"`
	Severity         string `json:"severity"`
	License          string `json:"license"`
	IsOutdated       bool   `json:"is_outdated"`
	IsVulnerable     bool   `json:"is_vulnerable"`
	HasLicenseIssue  bool   `json:"has_license_issue"`
	Description      string `json:"description"`
	Tool             string `json:"tool"`
}

type DependencyFilters struct {
	Tool           string
	Severity       string
	Ecosystems     []string
	OutdatedOnly   bool
	VulnerableOnly bool
	Page           int32
	PageSize       int32
}

type DependencySummary struct {
	ScanID        string
	Total         int32
	Vulnerable    int32
	Outdated      int32
	LicenseIssues int32
	Critical      int32
	High          int32
	Medium        int32
	Low           int32
	ByEcosystem   []EcosystemSummary
}

type EcosystemSummary struct {
	Ecosystem string
	Total     int32
}

type DependencyRepository struct {
	queries *db.Queries
}

func NewDependencyRepository(queries *db.Queries) *DependencyRepository {
	return &DependencyRepository{queries: queries}
}

func (r *DependencyRepository) SaveFindings(ctx context.Context, scanID, tool string, findings []*Dependency) error {
	id, err := uuid.Parse(scanID)
	if err != nil {
		return err
	}
	tool = strings.ToUpper(strings.TrimSpace(tool))
	for _, finding := range findings {
		if finding == nil {
			continue
		}
		if _, err := r.queries.UpsertScanDependencyResult(ctx, dependencyParams(id, tool, finding)); err != nil {
			return err
		}
	}
	return nil
}

func (r *DependencyRepository) ListFindings(ctx context.Context, scanID string, filters DependencyFilters) ([]*Dependency, int32, error) {
	id, err := uuid.Parse(scanID)
	if err != nil {
		return nil, 0, err
	}
	page, pageSize := normalizePage(filters.Page, filters.PageSize)
	args := db.ListScanDependencyResultsParams{
		ScanID:  id,
		Column2: strings.ToUpper(strings.TrimSpace(filters.Tool)),
		Column3: strings.ToUpper(strings.TrimSpace(filters.Severity)),
		Column4: upperStrings(filters.Ecosystems),
		Column5: filters.OutdatedOnly,
		Column6: filters.VulnerableOnly,
		Limit:   pageSize,
		Offset:  (page - 1) * pageSize,
	}
	rows, err := r.queries.ListScanDependencyResults(ctx, args)
	if err != nil {
		return nil, 0, err
	}
	total, err := r.queries.CountScanDependencyResults(ctx, db.CountScanDependencyResultsParams{
		ScanID:  args.ScanID,
		Column2: args.Column2,
		Column3: args.Column3,
		Column4: args.Column4,
		Column5: args.Column5,
		Column6: args.Column6,
	})
	if err != nil {
		return nil, 0, err
	}
	return dependenciesFromDB(rows), int32(total), nil
}

func (r *DependencyRepository) GetSummary(ctx context.Context, scanID string) (*DependencySummary, error) {
	id, err := uuid.Parse(scanID)
	if err != nil {
		return nil, err
	}
	summary, err := r.queries.GetScanDependencySummary(ctx, id)
	if err != nil {
		return nil, err
	}
	byEcosystem, err := r.queries.GetScanDependencySummaryByEcosystem(ctx, id)
	if err != nil {
		return nil, err
	}
	resp := &DependencySummary{
		ScanID:        scanID,
		Total:         summary.Total,
		Vulnerable:    summary.Vulnerable,
		Outdated:      summary.Outdated,
		LicenseIssues: summary.LicenseIssues,
		Critical:      summary.Critical,
		High:          summary.High,
		Medium:        summary.Medium,
		Low:           summary.Low,
		ByEcosystem:   make([]EcosystemSummary, 0, len(byEcosystem)),
	}
	for _, item := range byEcosystem {
		resp.ByEcosystem = append(resp.ByEcosystem, EcosystemSummary{
			Ecosystem: item.Ecosystem,
			Total:     item.Total,
		})
	}
	return resp, nil
}

func dependencyParams(scanID uuid.UUID, tool string, finding *Dependency) db.UpsertScanDependencyResultParams {
	raw, _ := json.Marshal(finding)
	return db.UpsertScanDependencyResultParams{
		ScanID:           scanID,
		Tool:             tool,
		FindingKey:       dependencyFindingKey(tool, finding),
		PackageName:      firstNonEmpty(finding.PackageName, "unknown"),
		Ecosystem:        textValue(firstNonEmpty(strings.ToUpper(strings.TrimSpace(finding.Ecosystem)), "OTHER")),
		InstalledVersion: textValue(finding.InstalledVersion),
		FixedVersion:     textValue(finding.FixedVersion),
		LatestVersion:    textValue(finding.LatestVersion),
		CveID:            textValue(finding.CVEID),
		CveSeverity:      textValue(normalizeSeverity(finding.Severity)),
		License:          textValue(finding.License),
		IsOutdated:       finding.IsOutdated,
		IsVulnerable:     finding.IsVulnerable,
		HasLicenseIssue:  finding.HasLicenseIssue,
		Description:      textValue(finding.Description),
		RawFinding:       raw,
	}
}

func dependencyFindingKey(tool string, finding *Dependency) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		tool,
		finding.PackageName,
		finding.InstalledVersion,
		finding.CVEID,
		finding.License,
		finding.Description,
	}, "|")))
	return hex.EncodeToString(sum[:])
}

func dependenciesFromDB(items []db.ScanDependencyResult) []*Dependency {
	result := make([]*Dependency, 0, len(items))
	for _, item := range items {
		result = append(result, &Dependency{
			PackageName:      item.PackageName,
			Ecosystem:        text(item.Ecosystem),
			InstalledVersion: text(item.InstalledVersion),
			FixedVersion:     text(item.FixedVersion),
			LatestVersion:    text(item.LatestVersion),
			CVEID:            text(item.CveID),
			Severity:         text(item.CveSeverity),
			License:          text(item.License),
			IsOutdated:       item.IsOutdated,
			IsVulnerable:     item.IsVulnerable,
			HasLicenseIssue:  item.HasLicenseIssue,
			Description:      text(item.Description),
			Tool:             item.Tool,
		})
	}
	return result
}

func normalizePage(page, pageSize int32) (int32, int32) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 100
	}
	if pageSize > 500 {
		pageSize = 500
	}
	return page, pageSize
}

func normalizeSeverity(value string) string {
	value = strings.ToUpper(strings.TrimSpace(value))
	switch value {
	case "UNKNOWN", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL":
		return value
	default:
		return "UNKNOWN"
	}
}

func upperStrings(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToUpper(strings.TrimSpace(value))
		if value != "" {
			result = append(result, value)
		}
	}
	return result
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
