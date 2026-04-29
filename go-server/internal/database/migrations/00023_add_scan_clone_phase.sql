-- +goose Up
-- +goose StatementBegin
ALTER TABLE scans
    ADD COLUMN IF NOT EXISTS clone_status TEXT NOT NULL DEFAULT 'PENDING',
    ADD COLUMN IF NOT EXISTS clone_error TEXT;

ALTER TABLE scans
    DROP CONSTRAINT IF EXISTS ck_scans_clone_status;

ALTER TABLE scans
    ADD CONSTRAINT ck_scans_clone_status
        CHECK (clone_status IN ('PENDING', 'IN_PROGRESS', 'SUCCESS', 'FAILED', 'SKIPPED'));
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE scans
    DROP CONSTRAINT IF EXISTS ck_scans_clone_status;

ALTER TABLE scans
    DROP COLUMN IF EXISTS clone_error,
    DROP COLUMN IF EXISTS clone_status;
-- +goose StatementEnd
