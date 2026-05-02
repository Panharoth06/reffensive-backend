-- +goose Up
-- Add shadow_output_config column to tools table
-- Stores JSON configuration for shadow output pattern

ALTER TABLE tools
    ADD COLUMN IF NOT EXISTS shadow_output_config JSONB;

-- Add comment for documentation
COMMENT ON COLUMN tools.shadow_output_config IS 'Shadow output configuration: {json_flag, file_flag, default_path, filename_template, alternative_formats, parse_timeout_seconds, fallback_to_stdout, is_streaming}';

-- +goose Down
ALTER TABLE tools
    DROP COLUMN IF EXISTS shadow_output_config;
