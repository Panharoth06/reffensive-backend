-- +goose Up
-- +goose StatementBegin
CREATE EXTENSION IF NOT EXISTS pgcrypto;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TYPE scan_job_status AS ENUM ('pending', 'running', 'completed', 'failed');
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TYPE execution_mode AS ENUM ('cli', 'cicd', 'web');
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TYPE scan_step_status AS ENUM ('pending', 'running', 'completed', 'failed', 'skipped');
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TYPE input_source_type AS ENUM ('target', 'step');
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TYPE report_scope_type AS ENUM ('project', 'target', 'job');
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TYPE severity_level AS ENUM ('info', 'low', 'medium', 'high', 'critical');
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TYPE provider_type_enum AS ENUM ('github', 'gitlab', 'bitbucket');
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TYPE provider_account_status AS ENUM ('CONNECTED', 'DISCONNECTED', 'REVOKED');
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TYPE IF EXISTS provider_account_status;
-- +goose StatementEnd

-- +goose StatementBegin
DROP TYPE IF EXISTS provider_type_enum;
-- +goose StatementEnd

-- +goose StatementBegin
DROP TYPE IF EXISTS severity_level;
-- +goose StatementEnd

-- +goose StatementBegin
DROP TYPE IF EXISTS report_scope_type;
-- +goose StatementEnd

-- +goose StatementBegin
DROP TYPE IF EXISTS input_source_type;
-- +goose StatementEnd

-- +goose StatementBegin
DROP TYPE IF EXISTS scan_step_status;
-- +goose StatementEnd

-- +goose StatementBegin
DROP TYPE IF EXISTS execution_mode;
-- +goose StatementEnd

-- +goose StatementBegin
DROP TYPE IF EXISTS scan_job_status;
-- +goose StatementEnd
