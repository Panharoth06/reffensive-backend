-- +goose Up
-- +goose StatementBegin
CREATE TABLE users (
    user_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    alias_name TEXT,
    avatar_profile TEXT,
    created_at TIMESTAMPTZ DEFAULT now(),
    last_modified TIMESTAMPTZ DEFAULT now()
);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE projects (
    project_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    project_name TEXT NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ DEFAULT now(),
    last_modified TIMESTAMPTZ DEFAULT now(),

    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    UNIQUE (project_id, user_id)
);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE targets (
    target_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL,
    name TEXT NOT NULL,
    type TEXT NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ DEFAULT now(),

    FOREIGN KEY (project_id) REFERENCES projects(project_id) ON DELETE CASCADE,
    UNIQUE (target_id, project_id)
);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE api_keys (
    key_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL,
    user_id UUID NOT NULL,

    name TEXT,
    prefix TEXT UNIQUE,
    description TEXT,
    hashed_secret TEXT NOT NULL,

    scopes TEXT[],
    is_active BOOLEAN DEFAULT TRUE,

    revoked_at TIMESTAMPTZ,
    expired_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT now(),

    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (project_id, user_id)
        REFERENCES projects(project_id, user_id)
        ON DELETE CASCADE
);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE INDEX idx_api_keys_active_project
ON api_keys(project_id) WHERE is_active = true;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE tool_categories (
    category_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT UNIQUE NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ DEFAULT now(),
    last_modified TIMESTAMPTZ DEFAULT now()
);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE tools (
    tool_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    category_id UUID,
    tool_name TEXT UNIQUE NOT NULL,

    tool_description TEXT,
    tool_long_description TEXT,
    examples TEXT,

    input_schema JSONB,
    output_schema JSONB,
    options_schema JSONB,

    install_method TEXT,
    version TEXT,
    image_ref TEXT,
    image_source TEXT,

    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now(),

    FOREIGN KEY (category_id) REFERENCES tool_categories(category_id)
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS tools;
-- +goose StatementEnd

-- +goose StatementBegin
DROP TABLE IF EXISTS tool_categories;
-- +goose StatementEnd

-- +goose StatementBegin
DROP INDEX IF EXISTS idx_api_keys_active_project;
-- +goose StatementEnd

-- +goose StatementBegin
DROP TABLE IF EXISTS api_keys;
-- +goose StatementEnd

-- +goose StatementBegin
DROP TABLE IF EXISTS targets;
-- +goose StatementEnd

-- +goose StatementBegin
DROP TABLE IF EXISTS projects;
-- +goose StatementEnd

-- +goose StatementBegin
DROP TABLE IF EXISTS users;
-- +goose StatementEnd
