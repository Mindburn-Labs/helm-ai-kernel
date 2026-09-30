-- Authority provisioning (contract 5, docs/architecture/gateway-provisioning-api.md).
--
-- Runs after the authority rows (mandates.SchemaDDL) in the same migration
-- step, so a database created before principals carried an external subject
-- gains those columns from that DDL.
--
-- authority_provisions is the plan the gateway last applied for an organization
-- of a tenant. plan_digest is the compare-and-set key of the next plan (its
-- base_plan_digest); nodes maps each plan node to the mandate it became, in the
-- plan's order; principals is the principals the plan listed, which the next
-- plan may disable; requested_by is the organization's provisioner, the only
-- principal a plan that needs no approval is accepted from; attempt_id is the
-- helm.authority.provision.v1 or narrow.v1 attempt that applied it; revision
-- counts the plans applied. The row changes in the transaction that changes the
-- mandates, so the two never disagree. Rows are never deleted.
CREATE TABLE IF NOT EXISTS authority_provisions (
    tenant_id    TEXT NOT NULL REFERENCES authority_tenants (tenant_id),
    org_ref      TEXT NOT NULL CHECK (org_ref ~ '^org:[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
    plan_digest  TEXT NOT NULL CHECK (plan_digest ~ '^[0-9a-f]{64}$'),
    version_ref  TEXT NOT NULL CHECK (version_ref ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    stage        TEXT NOT NULL CHECK (stage IN ('draft', 'approval-required', 'constrained-live', 'certified-live')),
    nodes        JSONB NOT NULL CHECK (jsonb_typeof(nodes) = 'array'),
    principals   JSONB NOT NULL CHECK (jsonb_typeof(principals) = 'array'),
    requested_by TEXT NOT NULL CHECK (requested_by <> ''),
    attempt_id   UUID NOT NULL,
    revision     BIGINT NOT NULL CHECK (revision > 0),
    applied_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, org_ref),
    FOREIGN KEY (tenant_id, requested_by) REFERENCES authority_principals (tenant_id, principal_id),
    FOREIGN KEY (tenant_id, attempt_id) REFERENCES authority_effect_attempts (tenant_id, attempt_id)
);
