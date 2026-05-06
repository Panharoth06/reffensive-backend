package repository

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	db "go-server/internal/database/sqlc"
)

type Scan struct {
	ID              string
	ProjectKey      string
	SonarProjectKey string
	RepositoryURL   string
	SourceDir       string
	Branch          string
	UserID          uuid.UUID
	Status          string
	Progress        int32
	ErrorMessage    string
	StartedAt       time.Time
	FinishedAt      time.Time
	CreatedAt       time.Time

	CloneStatus      string
	CloneError       string
	SonarqubeStatus  string
	SonarqubeError   string
	DependencyStatus string
	DependencyError  string

	raw db.Scan
}

type ScanRepository struct {
	queries *db.Queries
}

func NewScanRepository(queries *db.Queries) *ScanRepository {
	return &ScanRepository{queries: queries}
}

func (r *ScanRepository) Create(ctx context.Context, scan *Scan) (*Scan, error) {
	row, err := r.queries.CreateUnifiedScan(ctx, db.CreateUnifiedScanParams{
		ProjectKey:    scan.ProjectKey,
		RepositoryUrl: textValue(scan.RepositoryURL),
		SourceDir:     scan.SourceDir,
		Branch:        textValue(scan.Branch),
		UserID:        scan.UserID,
	})
	if err != nil {
		return nil, err
	}
	return scanFromDB(row), nil
}

func (r *ScanRepository) FindByID(ctx context.Context, id string) (*Scan, error) {
	scanID, err := uuid.Parse(id)
	if err != nil {
		return nil, err
	}
	row, err := r.queries.GetUnifiedScan(ctx, scanID)
	if err != nil {
		return nil, err
	}
	return scanFromDB(row), nil
}

func (r *ScanRepository) UpdateStatus(ctx context.Context, id, status, errorMsg string) error {
	scanID, err := uuid.Parse(id)
	if err != nil {
		return err
	}
	_, err = r.queries.UpdateUnifiedScanStatus(ctx, db.UpdateUnifiedScanStatusParams{
		ID:           scanID,
		Status:       status,
		ErrorMessage: textValue(errorMsg),
	})
	return err
}

func (r *ScanRepository) UpdateSonarProjectKey(ctx context.Context, id, projectKey string) error {
	scanID, err := uuid.Parse(id)
	if err != nil {
		return err
	}
	_, err = r.queries.UpdateUnifiedScanSonarProjectKey(ctx, db.UpdateUnifiedScanSonarProjectKeyParams{
		ID:              scanID,
		SonarProjectKey: textValue(projectKey),
	})
	return err
}

func (r *ScanRepository) UpdatePhase(ctx context.Context, id, phase, status, errorMsg string) error {
	scanID, err := uuid.Parse(id)
	if err != nil {
		return err
	}
	switch phase {
	case "clone":
		_, err = r.queries.UpdateUnifiedScanClonePhase(ctx, db.UpdateUnifiedScanClonePhaseParams{
			ID: scanID, CloneStatus: status, CloneError: textValue(errorMsg),
		})
	case "sonarqube":
		_, err = r.queries.UpdateUnifiedScanSonarqubePhase(ctx, db.UpdateUnifiedScanSonarqubePhaseParams{
			ID: scanID, SonarqubeStatus: status, SonarqubeError: textValue(errorMsg),
		})
	case "dependency":
		_, err = r.queries.UpdateUnifiedScanOwaspPhase(ctx, db.UpdateUnifiedScanOwaspPhaseParams{
			ID: scanID, OwaspStatus: status, OwaspError: textValue(errorMsg),
		})
	default:
		err = errors.New("unknown scan phase")
	}
	return err
}

func (r *ScanRepository) UpdateProgress(ctx context.Context, id string, progress int32) error {
	scanID, err := uuid.Parse(id)
	if err != nil {
		return err
	}
	_, err = r.queries.UpdateUnifiedScanProgress(ctx, db.UpdateUnifiedScanProgressParams{ID: scanID, Progress: progress})
	return err
}

func (r *ScanRepository) SetStartedAt(ctx context.Context, id string, _ time.Time) error {
	scanID, err := uuid.Parse(id)
	if err != nil {
		return err
	}
	_, err = r.queries.MarkUnifiedScanStarted(ctx, scanID)
	return err
}

func (r *ScanRepository) SetFinishedAt(ctx context.Context, id string, _ time.Time) error {
	scanID, err := uuid.Parse(id)
	if err != nil {
		return err
	}
	_, err = r.queries.MarkUnifiedScanFinished(ctx, scanID)
	return err
}

func (r *ScanRepository) ListByProject(ctx context.Context, projectKey string, page, pageSize int32) ([]*Scan, int32, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 100
	}
	offset := (page - 1) * pageSize
	rows, err := r.queries.ListUnifiedProjectScans(ctx, db.ListUnifiedProjectScansParams{
		ProjectKey: projectKey,
		Limit:      pageSize,
		Offset:     offset,
	})
	if err != nil {
		return nil, 0, err
	}
	total, err := r.queries.CountUnifiedProjectScans(ctx, projectKey)
	if err != nil {
		return nil, 0, err
	}
	scans := make([]*Scan, 0, len(rows))
	for _, row := range rows {
		scans = append(scans, scanFromDB(row))
	}
	return scans, int32(total), nil
}

func (r *ScanRepository) ListByUser(ctx context.Context, userID uuid.UUID, projectKey string, page, pageSize int32) ([]*Scan, int32, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 100
	}
	offset := (page - 1) * pageSize
	projectKey = strings.TrimSpace(projectKey)

	rows, err := r.queries.ListUnifiedUserScans(ctx, db.ListUnifiedUserScansParams{
		UserID:  userID,
		Column2: projectKey,
		Limit:   pageSize,
		Offset:  offset,
	})
	if err != nil {
		return nil, 0, err
	}
	total, err := r.queries.CountUnifiedUserScans(ctx, db.CountUnifiedUserScansParams{
		UserID:  userID,
		Column2: projectKey,
	})
	if err != nil {
		return nil, 0, err
	}
	scans := make([]*Scan, 0, len(rows))
	for _, row := range rows {
		scans = append(scans, scanFromDB(row))
	}
	return scans, int32(total), nil
}

func (r *ScanRepository) RawByID(ctx context.Context, id string) (db.Scan, error) {
	scanID, err := uuid.Parse(id)
	if err != nil {
		return db.Scan{}, err
	}
	return r.queries.GetUnifiedScan(ctx, scanID)
}

func (r *ScanRepository) RawByUUID(ctx context.Context, id uuid.UUID) (db.Scan, error) {
	return r.queries.GetUnifiedScan(ctx, id)
}

func (r *ScanRepository) Delete(ctx context.Context, id string) (int64, error) {
	scanID, err := uuid.Parse(id)
	if err != nil {
		return 0, err
	}
	if err := r.queries.DeleteScanPhasesByScan(ctx, scanID); err != nil {
		return 0, err
	}
	if err := r.queries.DeleteScanDependencyResultsByScan(ctx, scanID); err != nil {
		return 0, err
	}
	if err := r.queries.DeleteScanSonarResultsByScan(ctx, scanID); err != nil {
		return 0, err
	}
	return r.queries.DeleteUnifiedScan(ctx, scanID)
}

func scanFromDB(scan db.Scan) *Scan {
	result := &Scan{
		ID:               scan.ID.String(),
		ProjectKey:       scan.ProjectKey,
		SonarProjectKey:  text(scan.SonarProjectKey),
		RepositoryURL:    text(scan.RepositoryUrl),
		SourceDir:        scan.SourceDir,
		Branch:           text(scan.Branch),
		UserID:           scan.UserID,
		Status:           scan.Status,
		Progress:         scan.Progress,
		ErrorMessage:     text(scan.ErrorMessage),
		CloneStatus:      scan.CloneStatus,
		CloneError:       text(scan.CloneError),
		SonarqubeStatus:  scan.SonarqubeStatus,
		SonarqubeError:   text(scan.SonarqubeError),
		DependencyStatus: scan.OwaspStatus,
		DependencyError:  text(scan.OwaspError),
		raw:              scan,
	}
	if scan.StartedAt.Valid {
		result.StartedAt = scan.StartedAt.Time
	}
	if scan.FinishedAt.Valid {
		result.FinishedAt = scan.FinishedAt.Time
	}
	if scan.CreatedAt.Valid {
		result.CreatedAt = scan.CreatedAt.Time
	}
	return result
}

func textValue(value string) pgtype.Text {
	return pgtype.Text{String: value, Valid: value != ""}
}

func text(value pgtype.Text) string {
	if !value.Valid {
		return ""
	}
	return value.String
}

func IsNotFound(err error) bool {
	return errors.Is(err, pgx.ErrNoRows)
}
