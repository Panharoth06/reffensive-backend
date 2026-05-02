-- +goose Up
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS versions (
    version_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    version_number TEXT NOT NULL,
    installed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- +goose StatementBegin
ALTER TABLE tools
    DROP COLUMN IF EXISTS version,
    ADD COLUMN version_id UUID NOT NULL,
    ADD CONSTRAINT fk_tools_version
        FOREIGN KEY (version_id) REFERENCES versions(version_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE tools
    DROP CONSTRAINT IF EXISTS fk_tools_version,
    DROP COLUMN IF EXISTS version_id,
    ADD COLUMN version TEXT;
-- +goose StatementEnd

DROP TABLE IF EXISTS versions;