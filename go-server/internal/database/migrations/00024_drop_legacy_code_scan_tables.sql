-- +goose Up
-- +goose StatementBegin
DROP TABLE IF EXISTS
    code_scan_results,
    sonar_analysis_steps,
    sonar_analyses,
    sonar_results,
    sonar_projects,
    code_scan_jobs;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- Irreversible cleanup migration: legacy table drops are intentionally not recreated on rollback.
SELECT 1;
-- +goose StatementEnd
