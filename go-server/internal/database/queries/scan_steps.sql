-- name: GetScanStepByID :one
SELECT * FROM scan_steps
WHERE step_id = $1;

-- name: ListScanStepsByJob :many
SELECT * FROM scan_steps
WHERE job_id = $1
ORDER BY step_order ASC;

-- name: CreateScanStep :one
INSERT INTO scan_steps (job_id, tool_id, tool_version, input_source, input_step_id, step_key, step_order)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING *;

-- name: UpdateScanStepStatus :one
UPDATE scan_steps
SET status = $2
WHERE step_id = $1
RETURNING *;

-- name: StartScanStep :one
UPDATE scan_steps
SET
    status     = 'running',
    started_at = now()
WHERE step_id = $1
RETURNING *;

-- name: FinishScanStep :one
UPDATE scan_steps
SET
    status      = $2,
    finished_at = now()
WHERE step_id = $1
RETURNING *;
