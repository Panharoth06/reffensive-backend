-- +goose Up
-- +goose StatementBegin
ALTER TABLE ai_suggestions
    ADD COLUMN IF NOT EXISTS content TEXT NOT NULL DEFAULT '';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- Compatibility-only column restore; keep on rollback to avoid destructive schema drift.
SELECT 1;
-- +goose StatementEnd
