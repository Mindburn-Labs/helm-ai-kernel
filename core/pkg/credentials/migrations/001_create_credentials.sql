-- Migration: Create credentials table for credential management
-- Version: 001
-- Description: Stores encrypted AI provider credentials (OAuth tokens, API keys)

CREATE TABLE IF NOT EXISTS credentials (
    id            TEXT PRIMARY KEY,
    operator_id   TEXT NOT NULL,
    provider      TEXT NOT NULL CHECK (provider IN ('google', 'openai', 'anthropic')),
    token_type    TEXT NOT NULL CHECK (token_type IN ('bearer', 'apikey')),
    access_token  TEXT NOT NULL,     -- AES-256-GCM encrypted
    refresh_token TEXT,              -- AES-256-GCM encrypted (OAuth only)
    scopes        TEXT,              -- JSON array of scopes
    email         TEXT,              -- Associated email (OAuth only)
    expires_at    TIMESTAMPTZ,       -- Token expiration (null for API keys)
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at  TIMESTAMPTZ,
    
    UNIQUE (operator_id, provider)
);

-- Index for fast lookups by operator
CREATE INDEX IF NOT EXISTS idx_credentials_operator ON credentials(operator_id);

-- Audit log for credential changes
CREATE TABLE IF NOT EXISTS credential_audit_log (
    id           SERIAL PRIMARY KEY,
    operator_id  TEXT NOT NULL,
    provider     TEXT NOT NULL,
    action       TEXT NOT NULL CHECK (action IN ('created', 'updated', 'deleted', 'refreshed', 'used')),
    ip_address   TEXT,
    user_agent   TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_credential_audit_operator ON credential_audit_log(operator_id);
CREATE INDEX IF NOT EXISTS idx_credential_audit_time ON credential_audit_log(created_at);

-- Comment on encryption
COMMENT ON COLUMN credentials.access_token IS 'Encrypted with AES-256-GCM using CREDENTIAL_ENCRYPTION_KEY';
COMMENT ON COLUMN credentials.refresh_token IS 'Encrypted with AES-256-GCM using CREDENTIAL_ENCRYPTION_KEY';
