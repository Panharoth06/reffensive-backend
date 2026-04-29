-- name: GetReportByID :one
SELECT * FROM reports
WHERE report_id = $1;

-- name: ListReportsByProject :many
SELECT * FROM reports
WHERE project_id = $1
ORDER BY created_at DESC;

-- name: CreateReport :one
INSERT INTO reports (project_id, scope_id, scope_type, document_id, file_name, file_extension)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: DeleteReport :exec
DELETE FROM reports
WHERE report_id = $1;

-- name: GetDocumentByID :one
SELECT * FROM documents
WHERE document_id = $1;

-- name: CreateDocument :one
INSERT INTO documents (default_locale, is_publish)
VALUES ($1, $2)
RETURNING *;

-- name: PublishDocument :one
UPDATE documents
SET
    is_publish       = true,
    last_modified_at = now()
WHERE document_id = $1
RETURNING *;

-- name: GetTranslation :one
SELECT * FROM document_translations
WHERE document_id = $1 AND locale = $2;

-- name: ListTranslationsByDocument :many
SELECT * FROM document_translations
WHERE document_id = $1;

-- name: UpsertTranslation :one
INSERT INTO document_translations (document_id, locale, title, content)
VALUES ($1, $2, $3, $4)
ON CONFLICT (document_id, locale)
DO UPDATE SET
    title            = EXCLUDED.title,
    content          = EXCLUDED.content,
    last_modified_at = now()
RETURNING *;
