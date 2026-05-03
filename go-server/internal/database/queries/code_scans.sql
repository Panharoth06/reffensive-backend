-- name: GetRepositorySnapshotByID :one
SELECT * FROM repository_snapshots
WHERE id = $1;

-- name: GetRepositorySnapshotByCommit :one
SELECT * FROM repository_snapshots
WHERE repository_id = $1 AND commit_sha = $2;

-- name: GetRepositorySnapshotBySourceHash :one
SELECT * FROM repository_snapshots
WHERE source_snapshot_hash = $1;

-- name: ListSnapshotsByRepository :many
SELECT * FROM repository_snapshots
WHERE repository_id = $1
ORDER BY created_at DESC;

-- name: CreateRepositorySnapshot :one
INSERT INTO repository_snapshots (
    repository_id, branch_name, commit_sha,
    source_snapshot_hash, dependency_hash
)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: UpdateRepositorySnapshotDependencyHash :one
UPDATE repository_snapshots
SET dependency_hash = $2
WHERE id = $1
RETURNING *;

-- name: UpsertScanSonarResult :one
INSERT INTO scan_sonar_results (
    scan_id,
    analysis_id,
    quality_gate,
    bugs,
    vulnerabilities,
    code_smells,
    coverage,
    duplications,
    security_hotspots,
    raw_response
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
ON CONFLICT (scan_id) DO UPDATE SET
    analysis_id = EXCLUDED.analysis_id,
    quality_gate = EXCLUDED.quality_gate,
    bugs = EXCLUDED.bugs,
    vulnerabilities = EXCLUDED.vulnerabilities,
    code_smells = EXCLUDED.code_smells,
    coverage = EXCLUDED.coverage,
    duplications = EXCLUDED.duplications,
    security_hotspots = EXCLUDED.security_hotspots,
    raw_response = EXCLUDED.raw_response
RETURNING *;

-- name: GetScanSonarResult :one
SELECT * FROM scan_sonar_results
WHERE scan_id = $1;

-- name: CreateUnifiedScan :one
INSERT INTO scans (
    project_key,
    repository_url,
    source_dir,
    branch,
    user_id,
    status,
    progress
)
VALUES ($1, $2, $3, $4, $5, 'PENDING', 0)
RETURNING *;

-- name: UpdateUnifiedScanSonarProjectKey :one
UPDATE scans
SET sonar_project_key = $2,
    updated_at = now()
WHERE id = $1
RETURNING *;

-- name: GetUnifiedScan :one
SELECT * FROM scans
WHERE id = $1;

-- name: DeleteUnifiedScan :execrows
DELETE FROM scans
WHERE id = $1;

-- name: UpdateUnifiedScanProgress :one
UPDATE scans
SET progress = GREATEST(progress, $2),
    updated_at = now()
WHERE id = $1
RETURNING *;

-- name: UpdateUnifiedScanStatus :one
UPDATE scans
SET status = $2,
    error_message = $3,
    updated_at = now()
WHERE id = $1
RETURNING *;

-- name: MarkUnifiedScanStarted :one
UPDATE scans
SET status = 'IN_PROGRESS',
    started_at = COALESCE(started_at, now()),
    updated_at = now()
WHERE id = $1
RETURNING *;

-- name: MarkUnifiedScanFinished :one
UPDATE scans
SET finished_at = now(),
    updated_at = now()
WHERE id = $1
RETURNING *;

-- name: UpdateUnifiedScanClonePhase :one
UPDATE scans
SET clone_status = $2,
    clone_error = $3,
    updated_at = now()
WHERE id = $1
RETURNING *;

-- name: UpdateUnifiedScanSonarqubePhase :one
UPDATE scans
SET sonarqube_status = $2,
    sonarqube_error = $3,
    updated_at = now()
WHERE id = $1
RETURNING *;

-- name: UpdateUnifiedScanOwaspPhase :one
UPDATE scans
SET owasp_status = $2,
    owasp_error = $3,
    updated_at = now()
WHERE id = $1
RETURNING *;

-- name: UpdateUnifiedScanTrivyPhase :one
UPDATE scans
SET trivy_status = $2,
    trivy_error = $3,
    updated_at = now()
WHERE id = $1
RETURNING *;

-- name: ListUnifiedProjectScans :many
SELECT * FROM scans
WHERE project_key = $1
ORDER BY created_at DESC
LIMIT $2 OFFSET $3;

-- name: CountUnifiedProjectScans :one
SELECT COUNT(*) FROM scans
WHERE project_key = $1;

-- name: ListUnifiedUserScans :many
SELECT * FROM scans
WHERE user_id = $1
  AND ($2::text = '' OR project_key = $2)
ORDER BY created_at DESC
LIMIT $3 OFFSET $4;

-- name: CountUnifiedUserScans :one
SELECT COUNT(*) FROM scans
WHERE user_id = $1
  AND ($2::text = '' OR project_key = $2);

-- name: UpsertScanDependencyResult :one
INSERT INTO scan_dependency_results (
    scan_id,
    tool,
    finding_key,
    language,
    package_name,
    ecosystem,
    installed_version,
    fixed_version,
    latest_version,
    cve_id,
    cve_severity,
    license,
    is_outdated,
    is_vulnerable,
    has_license_issue,
    description,
    raw_finding
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
ON CONFLICT (scan_id, finding_key) DO UPDATE SET
    tool = EXCLUDED.tool,
    language = EXCLUDED.language,
    package_name = EXCLUDED.package_name,
    ecosystem = EXCLUDED.ecosystem,
    installed_version = EXCLUDED.installed_version,
    fixed_version = EXCLUDED.fixed_version,
    latest_version = EXCLUDED.latest_version,
    cve_id = EXCLUDED.cve_id,
    cve_severity = EXCLUDED.cve_severity,
    license = EXCLUDED.license,
    is_outdated = EXCLUDED.is_outdated,
    is_vulnerable = EXCLUDED.is_vulnerable,
    has_license_issue = EXCLUDED.has_license_issue,
    description = EXCLUDED.description,
    raw_finding = EXCLUDED.raw_finding
RETURNING *;

-- name: ListScanDependencyResults :many
SELECT * FROM scan_dependency_results
WHERE scan_id = $1
  AND ($2::text = '' OR tool = $2)
  AND ($3::text = '' OR cve_severity = $3)
  AND ($4::text[] IS NULL OR cardinality($4::text[]) = 0 OR ecosystem = ANY($4::text[]))
  AND ($5::text[] IS NULL OR cardinality($5::text[]) = 0 OR language = ANY($5::text[]))
  AND (NOT $6::boolean OR is_outdated)
  AND (NOT $7::boolean OR is_vulnerable)
ORDER BY created_at DESC
LIMIT $8 OFFSET $9;

-- name: CountScanDependencyResults :one
SELECT COUNT(*) FROM scan_dependency_results
WHERE scan_id = $1
  AND ($2::text = '' OR tool = $2)
  AND ($3::text = '' OR cve_severity = $3)
  AND ($4::text[] IS NULL OR cardinality($4::text[]) = 0 OR ecosystem = ANY($4::text[]))
  AND ($5::text[] IS NULL OR cardinality($5::text[]) = 0 OR language = ANY($5::text[]))
  AND (NOT $6::boolean OR is_outdated)
  AND (NOT $7::boolean OR is_vulnerable);

-- name: GetScanDependencySummary :one
SELECT
    COUNT(*)::int AS total,
    COUNT(*) FILTER (WHERE is_vulnerable)::int AS vulnerable,
    COUNT(*) FILTER (WHERE is_outdated)::int AS outdated,
    COUNT(*) FILTER (WHERE has_license_issue)::int AS license_issues,
    COUNT(*) FILTER (WHERE cve_severity = 'CRITICAL')::int AS critical,
    COUNT(*) FILTER (WHERE cve_severity = 'HIGH')::int AS high,
    COUNT(*) FILTER (WHERE cve_severity = 'MEDIUM')::int AS medium,
    COUNT(*) FILTER (WHERE cve_severity = 'LOW')::int AS low
FROM scan_dependency_results
WHERE scan_id = $1;

-- name: GetScanDependencySummaryByEcosystem :many
SELECT COALESCE(ecosystem, 'OTHER') AS ecosystem, COUNT(*)::int AS total
FROM scan_dependency_results
WHERE scan_id = $1
GROUP BY COALESCE(ecosystem, 'OTHER')
ORDER BY total DESC, ecosystem ASC;

-- name: GetScanDependencySummaryByLanguage :many
SELECT
    language,
    COUNT(*)::int AS total,
    COUNT(*) FILTER (WHERE is_vulnerable)::int AS vulnerable,
    COUNT(*) FILTER (WHERE is_outdated)::int AS outdated,
    COUNT(*) FILTER (WHERE has_license_issue)::int AS license_issues,
    COUNT(*) FILTER (WHERE cve_severity = 'CRITICAL')::int AS critical,
    COUNT(*) FILTER (WHERE cve_severity = 'HIGH')::int AS high,
    COUNT(*) FILTER (WHERE cve_severity = 'MEDIUM')::int AS medium,
    COUNT(*) FILTER (WHERE cve_severity = 'LOW')::int AS low
FROM scan_dependency_results
WHERE scan_id = $1
GROUP BY language
ORDER BY language ASC;
