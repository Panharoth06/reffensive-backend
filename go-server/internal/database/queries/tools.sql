-- name: GetToolByID :one
SELECT * FROM tools
WHERE tool_id = $1;

-- name: GetToolByName :one
SELECT * FROM tools
WHERE tool_name = $1;

-- name: ListTools :many
SELECT * FROM tools
ORDER BY tool_name ASC;

-- name: ListActiveTools :many
SELECT * FROM tools
WHERE is_active = true
ORDER BY tool_name ASC;

-- name: ListToolsByCategory :many
SELECT * FROM tools
WHERE category_id = $1
ORDER BY tool_name ASC;

-- name: CreateTool :one
INSERT INTO tools (
    category_id, tool_name, tool_description, tool_long_description,
    examples, input_schema, output_schema, scan_config,
    install_method, version_id, image_ref, image_source, denied_options,
    shadow_output_config, parser_config
)
VALUES (
    sqlc.arg('category_id'),
    sqlc.arg('tool_name'),
    sqlc.arg('tool_description'),
    sqlc.arg('tool_long_description'),
    sqlc.arg('examples'),
    sqlc.arg('input_schema'),
    sqlc.arg('output_schema'),
    sqlc.arg('scan_config'),
    sqlc.arg('install_method'),
    sqlc.arg('version_id'),
    sqlc.arg('image_ref'),
    sqlc.arg('image_source'),
    sqlc.arg('denied_options'),
    sqlc.arg('shadow_output_config'),
    sqlc.arg('parser_config')
)
RETURNING *;

-- name: UpdateTool :one
UPDATE tools
SET
    category_id           = COALESCE(sqlc.narg('category_id'), category_id),
    tool_name             = COALESCE(sqlc.narg('tool_name'), tool_name),
    tool_description      = COALESCE(sqlc.narg('tool_description'), tool_description),
    tool_long_description = COALESCE(sqlc.narg('tool_long_description'), tool_long_description),
    examples              = COALESCE(sqlc.narg('examples'), examples),
    input_schema          = COALESCE(sqlc.narg('input_schema'), input_schema),
    output_schema         = COALESCE(sqlc.narg('output_schema'), output_schema),
    scan_config           = COALESCE(sqlc.narg('scan_config'), scan_config),
    install_method        = COALESCE(sqlc.narg('install_method'), install_method),
    version_id            = COALESCE(sqlc.narg('version_id'), version_id),
    image_ref             = COALESCE(sqlc.narg('image_ref'), image_ref),
    image_source          = COALESCE(sqlc.narg('image_source'), image_source),
    denied_options        = COALESCE(sqlc.narg('denied_options'), denied_options),
    shadow_output_config  = COALESCE(sqlc.narg('shadow_output_config'), shadow_output_config),
    parser_config         = COALESCE(sqlc.narg('parser_config'), parser_config),
    is_active             = COALESCE(sqlc.narg('is_active'), is_active),
    updated_at            = now()
WHERE tool_id = $1
RETURNING *;

-- name: DeleteTool :exec
DELETE FROM tools
WHERE tool_id = $1;

-- name: GetToolCategoryByID :one
SELECT * FROM tool_categories
WHERE category_id = $1;

-- name: ListToolCategories :many
SELECT * FROM tool_categories
ORDER BY name ASC;

-- name: CreateToolCategory :one
INSERT INTO tool_categories (name, description)
VALUES ($1, $2)
RETURNING *;

-- name: UpdateToolCategory :one
UPDATE tool_categories
SET
    name          = COALESCE(sqlc.narg('name'), name),
    description   = COALESCE(sqlc.narg('description'), description),
    last_modified = now()
WHERE category_id = $1
RETURNING *;

-- name: DeleteToolCategory :exec
DELETE FROM tool_categories
WHERE category_id = $1;


-- name: GetToolWithVersion :one
SELECT 
    t.*, 
    v.version_number, 
    v.installed_at 
FROM tools t
JOIN versions v ON t.version_id = v.version_id
WHERE t.tool_id = $1;
