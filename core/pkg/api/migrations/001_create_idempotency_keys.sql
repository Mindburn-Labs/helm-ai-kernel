CREATE TABLE IF NOT EXISTS idempotency_keys (
    key TEXT PRIMARY KEY,
    status_code INTEGER NOT NULL,
    headers BYTEA, -- JSON stored as bytes for simplicity
    body BYTEA,
    cached_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_idempotency_cached_at ON idempotency_keys (cached_at);
