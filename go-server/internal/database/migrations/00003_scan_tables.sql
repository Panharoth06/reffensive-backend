-- +goose Up
-- +goose StatementBegin
CREATE TABLE scan_jobs (
    job_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL,
    target_id UUID NOT NULL,

    triggered_by UUID,
    api_key_id UUID,

    status scan_job_status DEFAULT 'pending',
    execution_mode execution_mode DEFAULT 'cli',

    created_at TIMESTAMPTZ DEFAULT now(),
    finished_at TIMESTAMPTZ,
    scan_duration INTERVAL GENERATED ALWAYS AS (finished_at - created_at) STORED,

    FOREIGN KEY (project_id) REFERENCES projects(project_id) ON DELETE CASCADE,
    FOREIGN KEY (target_id, project_id)
        REFERENCES targets(target_id, project_id),

    FOREIGN KEY (api_key_id) REFERENCES api_keys(key_id) ON DELETE SET NULL,

    UNIQUE (job_id, project_id),

    FOREIGN KEY (triggered_by) REFERENCES users(user_id),

    CHECK (
        (execution_mode = 'cicd' AND api_key_id IS NOT NULL) OR
        (execution_mode != 'cicd' AND triggered_by IS NOT NULL)
    )
);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE INDEX idx_scan_jobs_project_status
ON scan_jobs (project_id, status);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE scan_steps (
    step_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id UUID NOT NULL,
    tool_id UUID NOT NULL,
    tool_version TEXT,

    input_source input_source_type NOT NULL,
    input_step_id UUID,

    step_key TEXT NOT NULL,
    step_order INT NOT NULL,

    status scan_step_status DEFAULT 'pending',

    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT now(),

    FOREIGN KEY (job_id) REFERENCES scan_jobs(job_id) ON DELETE CASCADE,
    FOREIGN KEY (tool_id) REFERENCES tools(tool_id),

    UNIQUE (step_id, job_id),

    FOREIGN KEY (job_id, input_step_id)
        REFERENCES scan_steps(job_id, step_id),

    CHECK (step_id IS DISTINCT FROM input_step_id),

    UNIQUE (job_id, step_key),
    UNIQUE (job_id, step_order)
);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE INDEX idx_scan_steps_exec
ON scan_steps (job_id, step_order);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE scan_results (
    result_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    step_id UUID NOT NULL,
    job_id UUID NOT NULL,
    project_id UUID NOT NULL,
    target_id UUID NOT NULL,

    tool_id UUID NOT NULL,

    raw_data JSONB,
    parsed_data JSONB,

    severity severity_level,
    status scan_step_status,

    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT now(),

    FOREIGN KEY (step_id, job_id)
        REFERENCES scan_steps(step_id, job_id)
        ON DELETE CASCADE,

    FOREIGN KEY (job_id, project_id)
        REFERENCES scan_jobs(job_id, project_id)
        ON DELETE CASCADE,

    FOREIGN KEY (target_id, project_id)
        REFERENCES targets(target_id, project_id),

    FOREIGN KEY (tool_id) REFERENCES tools(tool_id) ON DELETE RESTRICT
);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE INDEX idx_results_raw_gin ON scan_results USING GIN (raw_data);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE INDEX idx_results_parsed_gin ON scan_results USING GIN (parsed_data);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE INDEX idx_results_stream
ON scan_results (job_id, created_at DESC);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE findings (
    finding_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    project_id UUID NOT NULL,
    job_id UUID NOT NULL,
    step_id UUID NOT NULL,

    tool_id UUID NOT NULL,
    severity severity_level,

    title TEXT,
    host TEXT,
    port INT,

    fingerprint TEXT,
    raw_result_id UUID,

    created_at TIMESTAMPTZ DEFAULT now(),

    FOREIGN KEY (step_id, job_id)
        REFERENCES scan_steps(step_id, job_id)
        ON DELETE CASCADE,

    FOREIGN KEY (raw_result_id) REFERENCES scan_results(result_id),

    FOREIGN KEY (tool_id) REFERENCES tools(tool_id) ON DELETE RESTRICT,

    FOREIGN KEY (job_id, project_id)
        REFERENCES scan_jobs(job_id, project_id),

    UNIQUE (job_id, tool_id, fingerprint)
);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE INDEX idx_findings_job ON findings(job_id);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE INDEX idx_findings_severity ON findings(severity);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE ai_suggestions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id UUID NOT NULL UNIQUE,
    content TEXT NOT NULL,
    is_suggested BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT now(),

    FOREIGN KEY (job_id) REFERENCES scan_jobs(job_id) ON DELETE CASCADE
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS ai_suggestions;
-- +goose StatementEnd

-- +goose StatementBegin
DROP INDEX IF EXISTS idx_findings_severity;
-- +goose StatementEnd

-- +goose StatementBegin
DROP INDEX IF EXISTS idx_findings_job;
-- +goose StatementEnd

-- +goose StatementBegin
DROP TABLE IF EXISTS findings;
-- +goose StatementEnd

-- +goose StatementBegin
DROP INDEX IF EXISTS idx_results_stream;
-- +goose StatementEnd

-- +goose StatementBegin
DROP INDEX IF EXISTS idx_results_parsed_gin;
-- +goose StatementEnd

-- +goose StatementBegin
DROP INDEX IF EXISTS idx_results_raw_gin;
-- +goose StatementEnd

-- +goose StatementBegin
DROP TABLE IF EXISTS scan_results;
-- +goose StatementEnd

-- +goose StatementBegin
DROP INDEX IF EXISTS idx_scan_steps_exec;
-- +goose StatementEnd

-- +goose StatementBegin
DROP TABLE IF EXISTS scan_steps;
-- +goose StatementEnd

-- +goose StatementBegin
DROP INDEX IF EXISTS idx_scan_jobs_project_status;
-- +goose StatementEnd

-- +goose StatementBegin
DROP TABLE IF EXISTS scan_jobs;
-- +goose StatementEnd
