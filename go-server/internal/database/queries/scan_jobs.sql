-- name: GetScanJobByID :one
SELECT * FROM scan_jobs
WHERE job_id = $1;

-- name: ListScanJobsByProject :many
SELECT * FROM scan_jobs
WHERE project_id = $1
ORDER BY created_at DESC;

-- name: ListScanJobsByProjectAndStatus :many
SELECT * FROM scan_jobs
WHERE project_id = $1
  AND status = $2
ORDER BY created_at DESC;

-- name: CreateScanJob :one
INSERT INTO scan_jobs (project_id, target_id, triggered_by, api_key_id, execution_mode)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: UpdateScanJobStatus :one
UPDATE scan_jobs
SET status = $2
WHERE job_id = $1
RETURNING *;

-- name: FinishScanJob :one
UPDATE scan_jobs
SET
    status      = $2,
    finished_at = now()
WHERE job_id = $1
RETURNING *;

-- name: DeleteScanJob :exec
DELETE FROM scan_jobs
WHERE job_id = $1;
