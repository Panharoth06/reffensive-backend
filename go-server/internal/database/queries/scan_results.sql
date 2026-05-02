-- name: GetScanResultByID :one
SELECT * FROM scan_results
WHERE result_id = $1;

-- name: ListScanResultsByJob :many
SELECT * FROM scan_results
WHERE job_id = $1
ORDER BY created_at ASC;

-- name: ListScanResultsByStep :many
SELECT * FROM scan_results
WHERE step_id = $1 AND job_id = $2
ORDER BY created_at ASC;

-- name: CreateScanResult :one
INSERT INTO scan_results (
    step_id, job_id, project_id, target_id, tool_id,
    raw_data, parsed_data, severity, status,
    started_at, finished_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
RETURNING *;

-- name: ListScanResultsBySeverity :many
SELECT * FROM scan_results
WHERE job_id = $1 AND severity = $2
ORDER BY created_at DESC;

-- name: GetParsedDataByStep :one
SELECT result_id, step_id, job_id, tool_id, parsed_data
FROM scan_results
WHERE step_id = $1 AND job_id = $2
ORDER BY created_at DESC
LIMIT 1;
