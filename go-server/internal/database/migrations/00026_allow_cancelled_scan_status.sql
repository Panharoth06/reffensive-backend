-- +goose Up
-- +goose StatementBegin
ALTER TABLE scans
    DROP CONSTRAINT IF EXISTS ck_scans_status;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE scans
    ADD CONSTRAINT ck_scans_status
        CHECK (status IN ('PENDING', 'IN_PROGRESS', 'SUCCESS', 'FAILED', 'PARTIAL', 'CANCELLED'));
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE scans
    DROP CONSTRAINT IF EXISTS ck_scans_status;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE scans
    ADD CONSTRAINT ck_scans_status
        CHECK (status IN ('PENDING', 'IN_PROGRESS', 'SUCCESS', 'FAILED', 'PARTIAL'));
-- +goose StatementEnd
