-- +goose Up
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION try_parse_jsonb(input_text TEXT)
RETURNS JSONB
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN input_text::jsonb;
EXCEPTION WHEN others THEN
    RETURN NULL;
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION normalize_examples_jsonb(input_text TEXT)
RETURNS JSONB
LANGUAGE plpgsql
AS $$
DECLARE
    parsed JSONB;
BEGIN
    IF input_text IS NULL OR btrim(input_text) = '' THEN
        RETURN '[]'::jsonb;
    END IF;

    parsed := try_parse_jsonb(input_text);

    IF parsed IS NULL THEN
        RETURN jsonb_build_array(jsonb_build_object('raw', input_text));
    END IF;

    IF jsonb_typeof(parsed) = 'array' THEN
        RETURN parsed;
    END IF;

    RETURN jsonb_build_array(parsed);
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE tools
    RENAME COLUMN options_schema TO scan_config;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE tools
    ADD COLUMN examples_jsonb JSONB;
-- +goose StatementEnd

-- +goose StatementBegin
UPDATE tools
SET examples_jsonb = normalize_examples_jsonb(examples);
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE tools
    DROP COLUMN examples;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE tools
    RENAME COLUMN examples_jsonb TO examples;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE tools
    ALTER COLUMN examples SET DEFAULT '[]'::jsonb,
    ALTER COLUMN examples SET NOT NULL,
    ALTER COLUMN scan_config SET DEFAULT '{}'::jsonb;
-- +goose StatementEnd

-- +goose StatementBegin
DROP FUNCTION IF EXISTS normalize_examples_jsonb(TEXT);
-- +goose StatementEnd

-- +goose StatementBegin
DROP FUNCTION IF EXISTS try_parse_jsonb(TEXT);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE tools
    RENAME COLUMN scan_config TO options_schema;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE tools
    ADD COLUMN examples_text TEXT;
-- +goose StatementEnd

-- +goose StatementBegin
UPDATE tools
SET examples_text = examples::text;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE tools
    DROP COLUMN examples;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE tools
    RENAME COLUMN examples_text TO examples;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE tools
    ALTER COLUMN options_schema DROP DEFAULT;
-- +goose StatementEnd
