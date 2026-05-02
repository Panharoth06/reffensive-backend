-- +goose Up
-- +goose StatementBegin
CREATE TABLE documents (
    document_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    default_locale TEXT DEFAULT 'en',
    is_publish BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT now(),
    last_modified_at TIMESTAMPTZ DEFAULT now()
);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE reports (
    report_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL,
    scope_id UUID NOT NULL,
    scope_type report_scope_type NOT NULL,
    document_id UUID,
    file_name TEXT,
    file_extension TEXT,
    created_at TIMESTAMPTZ DEFAULT now(),

    FOREIGN KEY (project_id) REFERENCES projects(project_id) ON DELETE CASCADE,
    FOREIGN KEY (document_id) REFERENCES documents(document_id) ON DELETE SET NULL
);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE document_translations (
    translation_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    document_id UUID NOT NULL,
    locale TEXT NOT NULL,
    title TEXT,
    content TEXT,
    created_at TIMESTAMPTZ DEFAULT now(),
    last_modified_at TIMESTAMPTZ DEFAULT now(),

    UNIQUE(document_id, locale),

    FOREIGN KEY (document_id) REFERENCES documents(document_id) ON DELETE CASCADE
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS document_translations;
-- +goose StatementEnd

-- +goose StatementBegin
DROP TABLE IF EXISTS reports;
-- +goose StatementEnd

-- +goose StatementBegin
DROP TABLE IF EXISTS documents;
-- +goose StatementEnd
