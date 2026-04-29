-- name: GetTargetByID :one
SELECT * FROM targets
WHERE target_id = $1;

-- name: ListTargetsByProject :many
SELECT * FROM targets
WHERE project_id = $1
ORDER BY created_at DESC;

-- name: CreateTarget :one
INSERT INTO targets (project_id, name, type, description)
VALUES ($1, $2, $3, $4)
RETURNING *;

-- name: UpdateTarget :one
UPDATE targets
SET
    name        = COALESCE(sqlc.narg('name'), name),
    type        = COALESCE(sqlc.narg('type'), type),
    description = COALESCE(sqlc.narg('description'), description)
WHERE target_id = $1 AND project_id = $2
RETURNING *;

-- name: DeleteTarget :exec
DELETE FROM targets
WHERE target_id = $1 AND project_id = $2;
