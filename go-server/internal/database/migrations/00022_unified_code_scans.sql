-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_key TEXT NOT NULL,
    repository_id UUID,
    repository_snapshot_id UUID,
    repository_url TEXT,
    source_dir TEXT NOT NULL,
    branch TEXT,
    commit_sha TEXT,
    source_hash TEXT,
    scan_config_hash TEXT,
    user_id UUID NOT NULL,

    status TEXT NOT NULL DEFAULT 'PENDING',
    sonarqube_status TEXT NOT NULL DEFAULT 'PENDING',
    owasp_status TEXT NOT NULL DEFAULT 'PENDING',
    trivy_status TEXT NOT NULL DEFAULT 'PENDING',

    progress INT NOT NULL DEFAULT 0,
    error_message TEXT,
    sonarqube_error TEXT,
    owasp_error TEXT,
    trivy_error TEXT,

    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT fk_scans_user
        FOREIGN KEY (user_id)
        REFERENCES users(user_id)
        ON DELETE CASCADE,

    CONSTRAINT fk_scans_repository
        FOREIGN KEY (repository_id)
        REFERENCES repositories(id)
        ON DELETE SET NULL,

    CONSTRAINT fk_scans_repository_snapshot
        FOREIGN KEY (repository_snapshot_id)
        REFERENCES repository_snapshots(id)
        ON DELETE SET NULL,

    CONSTRAINT ck_scans_status
        CHECK (status IN ('PENDING', 'IN_PROGRESS', 'SUCCESS', 'FAILED', 'PARTIAL')),

    CONSTRAINT ck_scans_sonarqube_status
        CHECK (sonarqube_status IN ('PENDING', 'IN_PROGRESS', 'SUCCESS', 'FAILED', 'SKIPPED')),

    CONSTRAINT ck_scans_owasp_status
        CHECK (owasp_status IN ('PENDING', 'IN_PROGRESS', 'SUCCESS', 'FAILED', 'SKIPPED')),

    CONSTRAINT ck_scans_trivy_status
        CHECK (trivy_status IN ('PENDING', 'IN_PROGRESS', 'SUCCESS', 'FAILED', 'SKIPPED')),

    CONSTRAINT ck_scans_progress
        CHECK (progress >= 0 AND progress <= 100)
);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS scan_sonar_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL,
    quality_gate TEXT NOT NULL DEFAULT 'NONE',
    bugs INT NOT NULL DEFAULT 0,
    vulnerabilities INT NOT NULL DEFAULT 0,
    code_smells INT NOT NULL DEFAULT 0,
    coverage DOUBLE PRECISION NOT NULL DEFAULT 0,
    duplications DOUBLE PRECISION NOT NULL DEFAULT 0,
    security_hotspots INT NOT NULL DEFAULT 0,
    raw_response JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT fk_scan_sonar_results_scan
        FOREIGN KEY (scan_id)
        REFERENCES scans(id)
        ON DELETE CASCADE,

    CONSTRAINT uq_scan_sonar_results_scan
        UNIQUE (scan_id),

    CONSTRAINT ck_scan_sonar_results_quality_gate
        CHECK (quality_gate IN ('OK', 'WARN', 'ERROR', 'NONE'))
);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS scan_dependency_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL,
    tool TEXT NOT NULL,
    finding_key TEXT NOT NULL,
    package_name TEXT NOT NULL,
    ecosystem TEXT,
    installed_version TEXT,
    fixed_version TEXT,
    latest_version TEXT,
    cve_id TEXT,
    cve_severity TEXT,
    license TEXT,
    is_outdated BOOLEAN NOT NULL DEFAULT false,
    is_vulnerable BOOLEAN NOT NULL DEFAULT false,
    has_license_issue BOOLEAN NOT NULL DEFAULT false,
    description TEXT,
    raw_finding JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT fk_scan_dependency_results_scan
        FOREIGN KEY (scan_id)
        REFERENCES scans(id)
        ON DELETE CASCADE,

    CONSTRAINT ck_scan_dependency_results_tool
        CHECK (tool IN ('OWASP', 'TRIVY')),

    CONSTRAINT ck_scan_dependency_results_severity
        CHECK (
            cve_severity IS NULL OR
            cve_severity IN ('UNKNOWN', 'INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
        ),

    CONSTRAINT uq_scan_dependency_results_finding
        UNIQUE (scan_id, finding_key)
);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE INDEX IF NOT EXISTS idx_scans_project_created_at
    ON scans (project_key, created_at DESC);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE INDEX IF NOT EXISTS idx_scans_user_created_at
    ON scans (user_id, created_at DESC);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE INDEX IF NOT EXISTS idx_scans_repository_created_at
    ON scans (repository_id, created_at DESC);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE INDEX IF NOT EXISTS idx_scans_repository_snapshot
    ON scans (repository_snapshot_id);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE INDEX IF NOT EXISTS idx_scans_status
    ON scans (status);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE INDEX IF NOT EXISTS idx_scans_source_identity
    ON scans (project_key, branch, commit_sha);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE INDEX IF NOT EXISTS idx_scan_dependency_results_scan_tool
    ON scan_dependency_results (scan_id, tool);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE INDEX IF NOT EXISTS idx_scan_dependency_results_severity
    ON scan_dependency_results (cve_severity);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE INDEX IF NOT EXISTS idx_scan_dependency_results_cve
    ON scan_dependency_results (cve_id);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE INDEX IF NOT EXISTS idx_scan_dependency_results_package
    ON scan_dependency_results (package_name);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE INDEX IF NOT EXISTS idx_scan_sonar_results_quality_gate
    ON scan_sonar_results (quality_gate);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_scan_sonar_results_quality_gate;
-- +goose StatementEnd

-- +goose StatementBegin
DROP INDEX IF EXISTS idx_scan_dependency_results_package;
-- +goose StatementEnd

-- +goose StatementBegin
DROP INDEX IF EXISTS idx_scan_dependency_results_cve;
-- +goose StatementEnd

-- +goose StatementBegin
DROP INDEX IF EXISTS idx_scan_dependency_results_severity;
-- +goose StatementEnd

-- +goose StatementBegin
DROP INDEX IF EXISTS idx_scan_dependency_results_scan_tool;
-- +goose StatementEnd

-- +goose StatementBegin
DROP INDEX IF EXISTS idx_scans_source_identity;
-- +goose StatementEnd

-- +goose StatementBegin
DROP INDEX IF EXISTS idx_scans_status;
-- +goose StatementEnd

-- +goose StatementBegin
DROP INDEX IF EXISTS idx_scans_repository_snapshot;
-- +goose StatementEnd

-- +goose StatementBegin
DROP INDEX IF EXISTS idx_scans_repository_created_at;
-- +goose StatementEnd

-- +goose StatementBegin
DROP INDEX IF EXISTS idx_scans_user_created_at;
-- +goose StatementEnd

-- +goose StatementBegin
DROP INDEX IF EXISTS idx_scans_project_created_at;
-- +goose StatementEnd

-- +goose StatementBegin
DROP TABLE IF EXISTS scan_dependency_results;
-- +goose StatementEnd

-- +goose StatementBegin
DROP TABLE IF EXISTS scan_sonar_results;
-- +goose StatementEnd

-- +goose StatementBegin
DROP TABLE IF EXISTS scans;
-- +goose StatementEnd
