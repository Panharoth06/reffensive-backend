-- name: GetProviderAccountByID :one
SELECT * FROM provider_accounts
WHERE id = $1;

-- name: ListProviderAccountsByUser :many
SELECT * FROM provider_accounts
WHERE user_id = $1
ORDER BY connected_at DESC;

-- name: GetProviderAccountByIdentity :one
SELECT * FROM provider_accounts
WHERE provider_type = $1 AND provider_account_id = $2;

-- name: CreateProviderAccount :one
INSERT INTO provider_accounts (
    user_id, provider_type, provider_account_id,
    provider_username, provider_email, status
)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: UpdateProviderAccountStatus :one
UPDATE provider_accounts
SET
    status     = $2,
    updated_at = now()
WHERE id = $1
RETURNING *;

-- name: UpdateProviderAccountOAuthData :one
UPDATE provider_accounts
SET
    provider_username      = $2,
    provider_email         = $3,
    status                 = $4,
    access_token_encrypted = $5,
    refresh_token_encrypted = $6,
    updated_at             = now()
WHERE id = $1
RETURNING *;

-- name: DeleteProviderAccount :exec
DELETE FROM provider_accounts
WHERE id = $1;

-- name: GetRepositoryByID :one
SELECT * FROM repositories
WHERE id = $1;

-- name: ListRepositoriesByUser :many
SELECT * FROM repositories
WHERE user_id = $1
ORDER BY created_at DESC;

-- name: ListRepositoriesByProviderAccount :many
SELECT * FROM repositories
WHERE provider_account_id = $1
ORDER BY full_name ASC;

-- name: GetRepositoryByIdentityHash :one
SELECT * FROM repositories
WHERE repository_identity_hash = $1;

-- name: CreateRepository :one
INSERT INTO repositories (
    user_id, provider_account_id, provider_repository_id,
    full_name, repository_identity_hash, is_private, default_branch
)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING *;

-- name: UpdateRepository :one
UPDATE repositories
SET
    is_private     = COALESCE(sqlc.narg('is_private'), is_private),
    default_branch = COALESCE(sqlc.narg('default_branch'), default_branch),
    updated_at     = now()
WHERE id = $1
RETURNING *;

-- name: DeleteRepository :exec
DELETE FROM repositories
WHERE id = $1;
