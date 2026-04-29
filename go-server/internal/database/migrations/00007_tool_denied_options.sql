-- +goose Up
CREATE EXTENSION IF NOT EXISTS pgcrypto;

ALTER TABLE tools
    ADD COLUMN denied_options TEXT[];

-- +goose Down
ALTER TABLE tools
    DROP COLUMN denied_options;
