-- name: GetFindingByID :one
SELECT * FROM findings
WHERE finding_id = $1;

-- name: ListFindingsByJob :many
SELECT * FROM findings
WHERE job_id = $1
ORDER BY severity DESC, created_at DESC;

-- name: ListFindingsByProject :many
SELECT * FROM findings
WHERE project_id = $1
ORDER BY severity DESC, created_at DESC;

-- name: ListFindingsBySeverity :many
SELECT * FROM findings
WHERE job_id = $1 AND severity = $2
ORDER BY created_at DESC;

-- name: CreateFinding :one
INSERT INTO findings (project_id, job_id, step_id, tool_id, severity, title, host, port, fingerprint, raw_result_id)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
RETURNING *;

-- name: UpsertFinding :one
INSERT INTO findings (project_id, job_id, step_id, tool_id, severity, title, host, port, fingerprint, raw_result_id)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
ON CONFLICT (job_id, tool_id, fingerprint)
DO UPDATE SET
    severity      = EXCLUDED.severity,
    title         = EXCLUDED.title,
    raw_result_id = EXCLUDED.raw_result_id
RETURNING *;

-- name: CountFindingsByJobAndSeverity :many
SELECT severity, COUNT(*) AS count
FROM findings
WHERE job_id = $1
GROUP BY severity;

-- name: GetAISuggestionByJobID :one
SELECT * FROM ai_suggestions
WHERE job_id = $1;

-- name: CreateAISuggestion :one
INSERT INTO ai_suggestions (job_id, content)
VALUES ($1, $2)
RETURNING *;

-- name: UpdateAISuggestion :one
UPDATE ai_suggestions
SET
    content      = $2,
    is_suggested = $3
WHERE job_id = $1
RETURNING *;
