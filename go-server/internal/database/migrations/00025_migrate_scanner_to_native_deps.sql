-- +goose Up
-- +goose StatementBegin
ALTER TABLE scans
    ADD COLUMN IF NOT EXISTS sonar_project_key TEXT;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE UNIQUE INDEX IF NOT EXISTS idx_scans_sonar_project_key
    ON scans (sonar_project_key)
    WHERE sonar_project_key IS NOT NULL;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS scan_phases (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL,
    phase TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'PENDING',
    progress INT NOT NULL DEFAULT 0,
    attempt INT NOT NULL DEFAULT 0,
    error TEXT,
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT fk_scan_phases_scan
        FOREIGN KEY (scan_id)
        REFERENCES scans(id)
        ON DELETE CASCADE,

    CONSTRAINT uq_scan_phases_scan_phase
        UNIQUE (scan_id, phase),

    CONSTRAINT ck_scan_phases_status
        CHECK (status IN ('PENDING', 'IN_PROGRESS', 'SUCCESS', 'FAILED', 'SKIPPED')),

    CONSTRAINT ck_scan_phases_progress
        CHECK (progress >= 0 AND progress <= 100),

    CONSTRAINT ck_scan_phases_attempt
        CHECK (attempt >= 0)
);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE INDEX IF NOT EXISTS idx_scan_phases_scan_id
    ON scan_phases (scan_id);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE INDEX IF NOT EXISTS idx_scan_phases_phase_status
    ON scan_phases (phase, status);
-- +goose StatementEnd

-- +goose StatementBegin
INSERT INTO scan_phases (
    scan_id,
    phase,
    status,
    progress,
    error,
    started_at,
    finished_at
)
SELECT
    id,
    'clone',
    clone_status,
    CASE
        WHEN clone_status IN ('SUCCESS', 'FAILED', 'SKIPPED') THEN 100
        WHEN clone_status = 'IN_PROGRESS' THEN 50
        ELSE 0
    END,
    clone_error,
    CASE
        WHEN clone_status <> 'PENDING' THEN COALESCE(started_at, created_at)
        ELSE NULL
    END,
    CASE
        WHEN clone_status IN ('SUCCESS', 'FAILED', 'SKIPPED') THEN finished_at
        ELSE NULL
    END
FROM scans
ON CONFLICT (scan_id, phase) DO UPDATE SET
    status = EXCLUDED.status,
    progress = EXCLUDED.progress,
    error = EXCLUDED.error,
    started_at = EXCLUDED.started_at,
    finished_at = EXCLUDED.finished_at,
    updated_at = now();
-- +goose StatementEnd

-- +goose StatementBegin
INSERT INTO scan_phases (
    scan_id,
    phase,
    status,
    progress,
    error,
    started_at,
    finished_at
)
SELECT
    id,
    'sonarqube',
    sonarqube_status,
    CASE
        WHEN sonarqube_status IN ('SUCCESS', 'FAILED', 'SKIPPED') THEN 100
        WHEN sonarqube_status = 'IN_PROGRESS' THEN 50
        ELSE 0
    END,
    sonarqube_error,
    CASE
        WHEN sonarqube_status <> 'PENDING' THEN COALESCE(started_at, created_at)
        ELSE NULL
    END,
    CASE
        WHEN sonarqube_status IN ('SUCCESS', 'FAILED', 'SKIPPED') THEN finished_at
        ELSE NULL
    END
FROM scans
ON CONFLICT (scan_id, phase) DO UPDATE SET
    status = EXCLUDED.status,
    progress = EXCLUDED.progress,
    error = EXCLUDED.error,
    started_at = EXCLUDED.started_at,
    finished_at = EXCLUDED.finished_at,
    updated_at = now();
-- +goose StatementEnd

-- +goose StatementBegin
INSERT INTO scan_phases (
    scan_id,
    phase,
    status,
    progress,
    error,
    started_at,
    finished_at
)
SELECT
    id,
    'dependency',
    CASE
        WHEN owasp_status = 'FAILED' OR trivy_status = 'FAILED' THEN 'FAILED'
        WHEN owasp_status = 'IN_PROGRESS' OR trivy_status = 'IN_PROGRESS' THEN 'IN_PROGRESS'
        WHEN owasp_status = 'SUCCESS' OR trivy_status = 'SUCCESS' THEN 'SUCCESS'
        WHEN owasp_status = 'SKIPPED' OR trivy_status = 'SKIPPED' THEN 'SKIPPED'
        ELSE 'PENDING'
    END,
    CASE
        WHEN owasp_status IN ('SUCCESS', 'FAILED', 'SKIPPED')
          OR trivy_status IN ('SUCCESS', 'FAILED', 'SKIPPED') THEN 100
        WHEN owasp_status = 'IN_PROGRESS' OR trivy_status = 'IN_PROGRESS' THEN 50
        ELSE 0
    END,
    NULLIF(CONCAT_WS(E'\n', NULLIF(owasp_error, ''), NULLIF(trivy_error, '')), ''),
    CASE
        WHEN owasp_status <> 'PENDING' OR trivy_status <> 'PENDING' THEN COALESCE(started_at, created_at)
        ELSE NULL
    END,
    CASE
        WHEN owasp_status IN ('SUCCESS', 'FAILED', 'SKIPPED')
          OR trivy_status IN ('SUCCESS', 'FAILED', 'SKIPPED') THEN finished_at
        ELSE NULL
    END
FROM scans
ON CONFLICT (scan_id, phase) DO UPDATE SET
    status = EXCLUDED.status,
    progress = EXCLUDED.progress,
    error = EXCLUDED.error,
    started_at = EXCLUDED.started_at,
    finished_at = EXCLUDED.finished_at,
    updated_at = now();
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE scan_sonar_results
    ADD COLUMN IF NOT EXISTS analysis_id TEXT;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE UNIQUE INDEX IF NOT EXISTS idx_scan_sonar_results_analysis_id
    ON scan_sonar_results (analysis_id)
    WHERE analysis_id IS NOT NULL;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE scan_dependency_results
    ADD COLUMN IF NOT EXISTS language TEXT NOT NULL DEFAULT 'unknown';
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE scan_dependency_results
    DROP CONSTRAINT IF EXISTS ck_scan_dependency_results_tool;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE INDEX IF NOT EXISTS idx_scan_dependency_results_tool
    ON scan_dependency_results (tool);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE INDEX IF NOT EXISTS idx_scan_dependency_results_language
    ON scan_dependency_results (language);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE INDEX IF NOT EXISTS idx_scan_dependency_results_vulnerable
    ON scan_dependency_results (is_vulnerable);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE INDEX IF NOT EXISTS idx_scan_dependency_results_outdated
    ON scan_dependency_results (is_outdated);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_scan_dependency_results_outdated;
-- +goose StatementEnd

-- +goose StatementBegin
DROP INDEX IF EXISTS idx_scan_dependency_results_vulnerable;
-- +goose StatementEnd

-- +goose StatementBegin
DROP INDEX IF EXISTS idx_scan_dependency_results_language;
-- +goose StatementEnd

-- +goose StatementBegin
DROP INDEX IF EXISTS idx_scan_dependency_results_tool;
-- +goose StatementEnd

-- +goose StatementBegin
DROP INDEX IF EXISTS idx_scan_sonar_results_analysis_id;
-- +goose StatementEnd

-- +goose StatementBegin
DROP INDEX IF EXISTS idx_scan_phases_phase_status;
-- +goose StatementEnd

-- +goose StatementBegin
DROP INDEX IF EXISTS idx_scan_phases_scan_id;
-- +goose StatementEnd

-- +goose StatementBegin
DROP INDEX IF EXISTS idx_scans_sonar_project_key;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE scan_dependency_results
    DROP COLUMN IF EXISTS language;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE scan_sonar_results
    DROP COLUMN IF EXISTS analysis_id;
-- +goose StatementEnd

-- +goose StatementBegin
DROP TABLE IF EXISTS scan_phases;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE scans
    DROP COLUMN IF EXISTS sonar_project_key;
-- +goose StatementEnd

-- +goose StatementBegin
-- The legacy tool constraint is intentionally not recreated here because
-- rows written after this migration may already contain native tool names.
SELECT 1;
-- +goose StatementEnd
