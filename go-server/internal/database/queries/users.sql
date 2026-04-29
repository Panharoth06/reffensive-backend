-- name: GetUserByID :one
SELECT * FROM users
WHERE user_id = $1;

-- name: GetUserByEmail :one
SELECT * FROM users
WHERE email = $1;

-- name: GetUserByUsername :one
SELECT * FROM users
WHERE username = $1;

-- name: CreateUser :one
INSERT INTO users (user_id, username, email, alias_name, avatar_profile)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: UpdateUser :one
UPDATE users
SET
    username = COALESCE(sqlc.narg('username'), username),
    email = COALESCE(sqlc.narg('email'), email),
    alias_name    = COALESCE(sqlc.narg('alias_name'), alias_name),
    avatar_profile = COALESCE(sqlc.narg('avatar_profile'), avatar_profile),
    last_modified = now()
WHERE user_id = $1
RETURNING *;

-- name: DeleteUser :execrows
DELETE FROM users
WHERE user_id = $1;

-- name: ListUsers :many
SELECT * FROM users
ORDER BY created_at DESC;
