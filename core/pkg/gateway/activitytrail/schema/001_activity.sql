CREATE TABLE gateway_activity_sources (
    tenant_id TEXT NOT NULL REFERENCES authority_tenants (tenant_id),
    workspace_id TEXT NOT NULL CHECK (workspace_id <> ''),
    repository TEXT NOT NULL CHECK (repository <> ''),
    enabled BOOLEAN NOT NULL DEFAULT true,
    enabled_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    default_branch TEXT NOT NULL CHECK (default_branch <> ''),
    head_sha TEXT NOT NULL CHECK (head_sha ~ '^[0-9a-fA-F]{40}$'),
    last_poll_at TIMESTAMPTZ,
    last_poll_error TEXT NOT NULL DEFAULT '',
    last_event_poll_at TIMESTAMPTZ,
    next_event_poll_at TIMESTAMPTZ,
    event_window_capped BOOLEAN NOT NULL DEFAULT false,
    PRIMARY KEY (tenant_id, workspace_id, repository)
);

CREATE TABLE gateway_activity_observations (
    tenant_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    repository TEXT NOT NULL,
    fact_digest BYTEA NOT NULL CHECK (length(fact_digest) = 32),
    ref TEXT NOT NULL CHECK (ref LIKE 'refs/heads/%'),
    before_sha TEXT NOT NULL CHECK (before_sha ~ '^[0-9a-fA-F]{40}$'),
    after_sha TEXT NOT NULL CHECK (after_sha ~ '^[0-9a-fA-F]{40}$'),
    actor_login TEXT,
    provider_time TIMESTAMPTZ,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    source TEXT NOT NULL DEFAULT 'github activity' CHECK (source = 'github activity'),
    coverage TEXT NOT NULL DEFAULT 'observed-only' CHECK (coverage = 'observed-only'),
    governed BOOLEAN NOT NULL DEFAULT false CHECK (governed = false),
    PRIMARY KEY (tenant_id, workspace_id, repository, fact_digest),
    FOREIGN KEY (tenant_id, workspace_id, repository)
        REFERENCES gateway_activity_sources (tenant_id, workspace_id, repository)
);
CREATE INDEX gateway_activity_observations_page
    ON gateway_activity_observations (tenant_id, workspace_id, repository, observed_at DESC, fact_digest DESC);

CREATE TABLE gateway_activity_evidence (
    tenant_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    repository TEXT NOT NULL,
    evidence_digest BYTEA NOT NULL CHECK (length(evidence_digest) = 32),
    fact_digest BYTEA NOT NULL CHECK (length(fact_digest) = 32),
    delivery_id TEXT CHECK (delivery_id IS NULL OR delivery_id <> ''),
    kind TEXT NOT NULL CHECK (kind IN ('compare','push_webhook','repository_event')),
    evidence JSONB NOT NULL CHECK (jsonb_typeof(evidence) = 'object'),
    observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, workspace_id, repository, evidence_digest),
    FOREIGN KEY (tenant_id, workspace_id, repository, fact_digest)
        REFERENCES gateway_activity_observations (tenant_id, workspace_id, repository, fact_digest)
);
CREATE UNIQUE INDEX gateway_activity_delivery_unique
    ON gateway_activity_evidence (tenant_id, workspace_id, repository, delivery_id)
    WHERE delivery_id IS NOT NULL;
