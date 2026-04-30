package repository

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"

	db "go-server/internal/database/sqlc"
)

type SonarResult struct {
	AnalysisID       string
	QualityGate      string
	Bugs             int32
	Vulnerabilities  int32
	CodeSmells       int32
	Coverage         float64
	Duplications     float64
	SecurityHotspots int32
	RawResponse      json.RawMessage
}

type SonarRepository struct {
	queries *db.Queries
}

func NewSonarRepository(queries *db.Queries) *SonarRepository {
	return &SonarRepository{queries: queries}
}

func (r *SonarRepository) SaveResult(ctx context.Context, scanID, analysisID string, result *SonarResult) error {
	id, err := uuid.Parse(scanID)
	if err != nil {
		return err
	}
	_, err = r.queries.UpsertScanSonarResult(ctx, db.UpsertScanSonarResultParams{
		ScanID:           id,
		AnalysisID:       textValue(analysisID),
		QualityGate:      result.QualityGate,
		Bugs:             result.Bugs,
		Vulnerabilities:  result.Vulnerabilities,
		CodeSmells:       result.CodeSmells,
		Coverage:         result.Coverage,
		Duplications:     result.Duplications,
		SecurityHotspots: result.SecurityHotspots,
		RawResponse:      result.RawResponse,
	})
	return err
}

func (r *SonarRepository) GetResult(ctx context.Context, scanID string) (*SonarResult, error) {
	id, err := uuid.Parse(scanID)
	if err != nil {
		return nil, err
	}
	row, err := r.queries.GetScanSonarResult(ctx, id)
	if err != nil {
		return nil, err
	}
	return &SonarResult{
		AnalysisID:       text(row.AnalysisID),
		QualityGate:      row.QualityGate,
		Bugs:             row.Bugs,
		Vulnerabilities:  row.Vulnerabilities,
		CodeSmells:       row.CodeSmells,
		Coverage:         row.Coverage,
		Duplications:     row.Duplications,
		SecurityHotspots: row.SecurityHotspots,
		RawResponse:      row.RawResponse,
	}, nil
}
