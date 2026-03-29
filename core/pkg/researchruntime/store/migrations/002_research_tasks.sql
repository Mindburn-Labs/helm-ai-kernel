CREATE TABLE IF NOT EXISTS research_tasks (
    id             TEXT PRIMARY KEY,
    mission_id     TEXT NOT NULL REFERENCES research_missions(id) ON DELETE CASCADE,
    parent_task_id TEXT,
    node_id        TEXT NOT NULL,
    role           TEXT NOT NULL,
    state          TEXT NOT NULL DEFAULT 'pending',
    input_ref      TEXT,
    output_ref     TEXT,
    attempt        INT NOT NULL DEFAULT 0,
    lease_holder   TEXT,
    lease_until    TIMESTAMPTZ,
    deadline_at    TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_research_tasks_mission ON research_tasks(mission_id);
CREATE INDEX IF NOT EXISTS idx_research_tasks_state   ON research_tasks(state);
