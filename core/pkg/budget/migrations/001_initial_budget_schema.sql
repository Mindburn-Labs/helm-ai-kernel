CREATE TABLE IF NOT EXISTS budgets (
    tenant_id TEXT PRIMARY KEY,
    daily_limit BIGINT NOT NULL,
    monthly_limit BIGINT NOT NULL,
    daily_used BIGINT NOT NULL DEFAULT 0,
    monthly_used BIGINT NOT NULL DEFAULT 0,
    last_updated TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_budgets_last_updated ON budgets (last_updated);
