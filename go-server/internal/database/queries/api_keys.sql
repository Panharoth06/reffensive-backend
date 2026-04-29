-- API Key Management Queries

-- name: CreateAPIKey :one
-- Create a new API key for a project
INSERT INTO api_keys (
  project_id,
  user_id,
  name,
  prefix,
  description,
  hashed_secret,
  scopes,
  is_active,
  expired_at
) VALUES (
  $1, $2, $3, $4, $5, $6, $7, $8, $9
) RETURNING *;

-- name: GetAPIKeyByHashedSecret :one
-- Retrieve API key by its hashed secret (for validation)
SELECT *
FROM api_keys
WHERE hashed_secret = $1;

-- name: GetActiveAPIKeyByHashedSecret :one
-- Get active API key by hashed secret (commonly used for validation)
SELECT *
FROM api_keys
WHERE hashed_secret = $1 AND is_active = true;

-- name: GetAPIKeyByID :one
-- Retrieve API key by ID
SELECT *
FROM api_keys
WHERE key_id = $1;

-- name: GetAPIKeyByPrefix :one
-- Retrieve API key by prefix
SELECT *
FROM api_keys
WHERE prefix = $1;

-- name: ListAPIKeysByProject :many
-- List all API keys for a project (including revoked)
SELECT *
FROM api_keys
WHERE project_id = $1
ORDER BY key_id DESC;

-- name: ListActiveAPIKeysByProject :many
-- List active API keys for a project
SELECT *
FROM api_keys
WHERE project_id = $1 AND is_active = true
ORDER BY key_id DESC;

-- name: RevokeAPIKey :one
-- Revoke an API key (soft delete)
UPDATE api_keys
SET is_active = false,
    revoked_at = CURRENT_TIMESTAMP
WHERE key_id = $1
RETURNING *;

-- name: UpdateAPIKeyScopes :one
-- Update the scopes of an API key
UPDATE api_keys
SET scopes = $2
WHERE key_id = $1
RETURNING *;

-- name: DeleteAPIKey :exec
-- Hard delete an API key (use with caution)
DELETE FROM api_keys
WHERE key_id = $1;

-- name: CountProjectAPIKeys :one
-- Count active API keys for a project
SELECT COUNT(*)
FROM api_keys
WHERE project_id = $1 AND is_active = true;
