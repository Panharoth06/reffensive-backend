-- +goose Up
-- +goose StatementBegin
ALTER TABLE ai_suggestions
    ADD COLUMN IF NOT EXISTS mode TEXT NOT NULL DEFAULT 'analysis',
    ADD COLUMN IF NOT EXISTS provider TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS model TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS output_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS input_tokens INT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS output_tokens INT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS feedback TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now();
-- +goose StatementEnd

-- +goose StatementBegin
UPDATE ai_suggestions
SET
    output_json = CASE
        WHEN COALESCE(content, '') = '' THEN '{}'::jsonb
        ELSE jsonb_build_object('content', content)
    END,
    updated_at = COALESCE(created_at, now())
WHERE output_json = '{}'::jsonb;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE ai_suggestions
    DROP CONSTRAINT IF EXISTS ai_suggestions_job_id_key;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE ai_suggestions
    ADD CONSTRAINT ai_suggestions_job_id_mode_key UNIQUE (job_id, mode);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE ai_suggestions
    DROP CONSTRAINT IF EXISTS ai_suggestions_job_id_mode_key;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE ai_suggestions
    ADD CONSTRAINT ai_suggestions_job_id_key UNIQUE (job_id);
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE ai_suggestions
    DROP COLUMN IF EXISTS mode,
    DROP COLUMN IF EXISTS provider,
    DROP COLUMN IF EXISTS model,
    DROP COLUMN IF EXISTS output_json,
    DROP COLUMN IF EXISTS input_tokens,
    DROP COLUMN IF EXISTS output_tokens,
    DROP COLUMN IF EXISTS feedback,
    DROP COLUMN IF EXISTS updated_at;
-- +goose StatementEnd
