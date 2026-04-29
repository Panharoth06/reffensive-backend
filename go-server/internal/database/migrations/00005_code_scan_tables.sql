-- +goose Up
-- +goose StatementBegin
CREATE TABLE provider_accounts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    provider_type provider_type_enum NOT NULL,
    provider_account_id TEXT NOT NULL,
    provider_username TEXT NOT NULL,
    provider_email TEXT,
    status provider_account_status NOT NULL DEFAULT 'CONNECTED',

    connected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT fk_provider_accounts_user
        FOREIGN KEY (user_id)
        REFERENCES users(user_id)
        ON DELETE CASCADE,

    CONSTRAINT uq_provider_accounts_identity
        UNIQUE (provider_type, provider_account_id)
);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE repositories (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    provider_account_id UUID NOT NULL,
    provider_repository_id TEXT,
    full_name TEXT NOT NULL,
    repository_identity_hash TEXT NOT NULL,
    is_private BOOLEAN NOT NULL DEFAULT true,
    default_branch TEXT NOT NULL DEFAULT 'main',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT fk_repositories_user
        FOREIGN KEY (user_id)
        REFERENCES users(user_id)
        ON DELETE CASCADE,

    CONSTRAINT fk_repositories_provider_account
        FOREIGN KEY (provider_account_id)
        REFERENCES provider_accounts(id)
        ON DELETE CASCADE,

    CONSTRAINT uq_repositories_provider_full_name
        UNIQUE (provider_account_id, full_name),

    CONSTRAINT uq_repositories_identity_hash
        UNIQUE (repository_identity_hash)
);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE repository_snapshots (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repository_id UUID NOT NULL,
    branch_name TEXT NOT NULL,
    commit_sha TEXT NOT NULL,
    source_snapshot_hash TEXT NOT NULL,
    dependency_hash TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT fk_repository_snapshots_repository
        FOREIGN KEY (repository_id)
        REFERENCES repositories(id)
        ON DELETE CASCADE,

    CONSTRAINT uq_repository_snapshots_repo_commit
        UNIQUE (repository_id, commit_sha),

    CONSTRAINT uq_repository_snapshots_source_hash
        UNIQUE (source_snapshot_hash)
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS repository_snapshots;
-- +goose StatementEnd

-- +goose StatementBegin
DROP TABLE IF EXISTS repositories;
-- +goose StatementEnd

-- +goose StatementBegin
DROP TABLE IF EXISTS provider_accounts;
-- +goose StatementEnd
