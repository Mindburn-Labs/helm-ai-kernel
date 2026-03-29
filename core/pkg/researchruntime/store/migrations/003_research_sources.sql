CREATE TABLE IF NOT EXISTS research_source_snapshots (
    id               TEXT PRIMARY KEY,
    mission_id       TEXT NOT NULL REFERENCES research_missions(id) ON DELETE CASCADE,
    url              TEXT NOT NULL,
    canonical_url    TEXT,
    title            TEXT,
    content_hash     TEXT,
    snapshot_hash    TEXT,
    blob_ref         TEXT,
    citation_map_ref TEXT,
    state            TEXT NOT NULL DEFAULT 'discovered',
    freshness_score  DOUBLE PRECISION,
    is_primary       BOOLEAN NOT NULL DEFAULT FALSE,
    captured_at      TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_research_sources_mission ON research_source_snapshots(mission_id);
