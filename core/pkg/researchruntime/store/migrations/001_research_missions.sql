CREATE TABLE IF NOT EXISTS research_missions (
    id               TEXT PRIMARY KEY,
    type             TEXT NOT NULL,
    title            TEXT NOT NULL,
    objective        TEXT NOT NULL,
    query_seed       TEXT,
    state            TEXT NOT NULL DEFAULT 'created',
    policy_bundle_ref TEXT,
    budget_tokens_max INT,
    budget_cents_max  INT,
    trigger_type      TEXT,
    trigger_cron      TEXT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_research_missions_state ON research_missions(state);
