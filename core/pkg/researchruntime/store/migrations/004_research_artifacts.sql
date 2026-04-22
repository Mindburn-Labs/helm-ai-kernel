CREATE TABLE IF NOT EXISTS research_draft_manifests (
    id                   TEXT PRIMARY KEY,
    mission_id           TEXT NOT NULL REFERENCES research_missions(id) ON DELETE CASCADE,
    state                TEXT NOT NULL DEFAULT 'draft',
    outline_ref          TEXT,
    body_ref             TEXT,
    source_refs          JSONB,
    model_manifest_refs  JSONB,
    draft_hash           TEXT,
    evidence_pack_ref    TEXT,
    promotion_receipt_ref TEXT,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS research_publications (
    id                     TEXT PRIMARY KEY,
    mission_id             TEXT NOT NULL REFERENCES research_missions(id),
    draft_id               TEXT REFERENCES research_draft_manifests(id),
    state                  TEXT NOT NULL DEFAULT 'DRAFT',
    title                  TEXT,
    slug                   TEXT UNIQUE,
    evidence_pack_hash     TEXT,
    promotion_receipt_hash TEXT,
    superseded_by          TEXT,
    published_at           TIMESTAMPTZ,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS research_overrides (
    id              TEXT PRIMARY KEY,
    mission_id      TEXT NOT NULL REFERENCES research_missions(id),
    artifact_id     TEXT,
    reason_codes    JSONB,
    operator_id     TEXT,
    decision        TEXT NOT NULL DEFAULT 'pending',
    notes           TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS research_feed_events (
    id         TEXT PRIMARY KEY,
    mission_id TEXT NOT NULL REFERENCES research_missions(id),
    actor      TEXT NOT NULL,
    action     TEXT NOT NULL,
    detail     TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_feed_events_mission ON research_feed_events(mission_id);
CREATE INDEX IF NOT EXISTS idx_feed_events_time    ON research_feed_events(created_at DESC);
