-- +goose Up
-- Add parser_config column for declarative, tool-specific result parsing.
-- Allows admin-added tools to define their own parsing rules without code changes.
ALTER TABLE tools
    ADD COLUMN IF NOT EXISTS parser_config JSONB DEFAULT NULL;

-- +goose Down
ALTER TABLE tools
    DROP COLUMN IF EXISTS parser_config;
