-- Provision membership is identity history, not a second budget ledger.
-- A replacement copies used counters but leaves unsettled attempts on their
-- original limit. Retain every actual applied limit, including removed nodes,
-- so a read can select those attempts once instead of summing copied counters.
-- Old databases have already lost this history: a later apply must not claim
-- to reconstruct it from the current node names.
ALTER TABLE authority_provisions
    ADD COLUMN IF NOT EXISTS budget_lineage_complete BOOLEAN NOT NULL DEFAULT false;

CREATE TABLE IF NOT EXISTS authority_provision_limits (
    tenant_id       TEXT NOT NULL,
    limit_id        UUID NOT NULL,
    org_ref         TEXT NOT NULL CHECK (org_ref ~ '^org:[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
    node            TEXT NOT NULL CHECK (node <> ''),
    mandate_id      UUID NOT NULL,
    first_plan_digest TEXT NOT NULL CHECK (first_plan_digest ~ '^[0-9a-f]{64}$'),
    first_revision  BIGINT NOT NULL CHECK (first_revision > 0),
    attempt_id      UUID NOT NULL,
    recorded_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, limit_id),
    FOREIGN KEY (tenant_id, limit_id) REFERENCES authority_limits (tenant_id, limit_id),
    FOREIGN KEY (tenant_id, mandate_id) REFERENCES authority_mandates (tenant_id, mandate_id),
    FOREIGN KEY (tenant_id, attempt_id) REFERENCES authority_effect_attempts (tenant_id, attempt_id)
);
CREATE INDEX IF NOT EXISTS authority_provision_limits_node
    ON authority_provision_limits (tenant_id, org_ref, node);
