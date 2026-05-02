-- +goose Up
-- +goose StatementBegin
CREATE TABLE scan_suggestions (
    suggestion_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL,
    job_id UUID NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    reasoning TEXT,
    priority TEXT,
    confidence DOUBLE PRECISION,
    tool_id UUID NOT NULL REFERENCES tools(tool_id),
    input_step_id UUID,
    params JSONB NOT NULL DEFAULT '{}'::jsonb,
    status TEXT NOT NULL DEFAULT 'pending',
    executed_job_id UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT fk_scan_suggestions_job
        FOREIGN KEY (job_id, project_id)
        REFERENCES scan_jobs(job_id, project_id)
        ON DELETE CASCADE,

    CONSTRAINT fk_scan_suggestions_input_step
        FOREIGN KEY (job_id, input_step_id)
        REFERENCES scan_steps(job_id, step_id)
        ON DELETE SET NULL,

    CONSTRAINT fk_scan_suggestions_executed_job
        FOREIGN KEY (executed_job_id)
        REFERENCES scan_jobs(job_id)
        ON DELETE SET NULL,

    CONSTRAINT chk_scan_suggestions_priority
        CHECK (priority IS NULL OR priority IN ('low', 'medium', 'high')),

    CONSTRAINT chk_scan_suggestions_status
        CHECK (status IN ('pending', 'accepted', 'rejected', 'executed'))
);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE INDEX idx_scan_suggestions_job_created
ON scan_suggestions (job_id, created_at DESC);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE INDEX idx_scan_suggestions_project_status
ON scan_suggestions (project_id, status, created_at DESC);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_scan_suggestions_project_status;
-- +goose StatementEnd

-- +goose StatementBegin
DROP INDEX IF EXISTS idx_scan_suggestions_job_created;
-- +goose StatementEnd

-- +goose StatementBegin
DROP TABLE IF EXISTS scan_suggestions;
-- +goose StatementEnd
