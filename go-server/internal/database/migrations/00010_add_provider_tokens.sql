-- +goose Up

ALTER TABLE provider_accounts 
ADD COLUMN IF NOT EXISTS access_token_encrypted TEXT NOT NULL DEFAULT '',
ADD COLUMN IF NOT EXISTS refresh_token_encrypted TEXT;

-- +goose Down

ALTER TABLE provider_accounts 
DROP COLUMN IF EXISTS access_token_encrypted,
DROP COLUMN IF EXISTS refresh_token_encrypted;