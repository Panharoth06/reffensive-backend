-- name: GetProjectByID :one
SELECT * FROM projects
WHERE project_id = $1 AND user_id = $2;

-- name: GetProjectByName :one
SELECT * FROM projects
WHERE project_name = $1 AND user_id = $2;

-- name: GetProjectByIDInternal :one
SELECT * FROM projects
WHERE project_id = $1;

-- name: ListProjectsByUser :many
SELECT * FROM projects
WHERE user_id = $1
ORDER BY created_at DESC;

-- name: CreateProject :one
INSERT INTO projects (user_id, project_name, description)
VALUES ($1, $2, $3)
RETURNING *;

-- name: UpdateProject :one
UPDATE projects
SET
    project_name  = COALESCE(sqlc.narg('project_name'), project_name),
    description   = COALESCE(sqlc.narg('description'), description),
    last_modified = now()
WHERE project_id = $1 AND user_id = $2
RETURNING *;

-- name: DeleteProject :exec
DELETE FROM projects
WHERE project_id = $1 AND user_id = $2;

-- name: DeleteProjectFindings :exec
DELETE FROM findings
WHERE project_id = $1;

-- name: DeleteProjectScanResults :exec
DELETE FROM scan_results
WHERE project_id = $1;

-- name: DeleteProjectScanJobs :exec
-- scan_steps will be auto-deleted via ON DELETE CASCADE from scan_jobs
DELETE FROM scan_jobs
WHERE project_id = $1;

-- name: DeleteProjectTargets :exec
DELETE FROM targets
WHERE project_id = $1;

-- name: CountProjectsByUser :one
SELECT COUNT(*) FROM projects
WHERE user_id = $1;
