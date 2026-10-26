-- Recovery is a hold on one provisioned organization version in one workspace.
-- These rows live with the authoritative gateway, outside CP snapshot restore.
-- There is deliberately no release transition in this first capability.
CREATE TABLE authority_recovery_fences (
    tenant_id TEXT NOT NULL REFERENCES authority_tenants (tenant_id),
    workspace_id TEXT NOT NULL,
    org_ref TEXT NOT NULL,
    organization_version_id TEXT NOT NULL,
    operation_id UUID NOT NULL,
    installation_id TEXT NOT NULL CHECK (octet_length(installation_id) BETWEEN 1 AND 128),
    generation BIGINT NOT NULL CHECK (generation > 0),
    plan_digest TEXT NOT NULL,
    authority_revision BIGINT NOT NULL,
    requested_by TEXT NOT NULL,
    cutoff_watermark TEXT NOT NULL CHECK (cutoff_watermark ~ '^[0-9a-f]{64}$'),
    fenced_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, operation_id),
    UNIQUE (tenant_id, workspace_id, org_ref, organization_version_id, generation),
    FOREIGN KEY (tenant_id, org_ref) REFERENCES authority_provisions (tenant_id, org_ref),
    FOREIGN KEY (tenant_id, requested_by) REFERENCES authority_principals (tenant_id, principal_id)
);
CREATE TABLE authority_recovery_scopes (
    tenant_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    org_ref TEXT NOT NULL,
    organization_version_id TEXT NOT NULL,
    operation_id UUID NOT NULL,
    generation BIGINT NOT NULL CHECK (generation > 0),
    PRIMARY KEY (tenant_id, workspace_id, org_ref, organization_version_id),
    FOREIGN KEY (tenant_id, operation_id) REFERENCES authority_recovery_fences (tenant_id, operation_id)
);
CREATE TABLE authority_recovery_members (
    tenant_id TEXT NOT NULL,
    operation_id UUID NOT NULL,
    attempt_id UUID NOT NULL,
    PRIMARY KEY (tenant_id, operation_id, attempt_id),
    FOREIGN KEY (tenant_id, operation_id) REFERENCES authority_recovery_fences (tenant_id, operation_id)
    -- No attempt FK: checking it takes KEY SHARE on an attempt already locked
    -- by a claim waiting for our tenant control lock, creating a lock cycle.
    -- Membership is inserted only from original native attempts in this tx;
    -- the gateway runtime cannot DELETE attempts or membership.
);
CREATE TABLE authority_recovery_checkpoints (
    tenant_id TEXT NOT NULL,
    operation_id UUID NOT NULL,
    checkpoint_digest TEXT NOT NULL CHECK (checkpoint_digest ~ '^[0-9a-f]{64}$'),
    inventory_watermark TEXT NOT NULL CHECK (inventory_watermark ~ '^[0-9a-f]{64}$'),
    bound_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, operation_id),
    FOREIGN KEY (tenant_id, operation_id) REFERENCES authority_recovery_fences (tenant_id, operation_id)
);

-- Native and older gateway writers must meet the same hold. The control lock
-- is the dispatch claim's existing serialization point. A pre-cutoff claim may
-- still perform provider I/O after acknowledgement; its original row is a member.
CREATE FUNCTION authority_guard_provider_recovery() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.organization_version_id IS NULL THEN
        RETURN NEW;
    END IF;
    PERFORM 1 FROM authority_tenants WHERE tenant_id = NEW.tenant_id FOR SHARE;
    IF TG_OP = 'INSERT' AND EXISTS (SELECT 1 FROM authority_effect_attempts
        WHERE tenant_id=NEW.tenant_id AND idempotency_key=NEW.idempotency_key) THEN
        -- ON CONFLICT can still recover the original identity. It cannot
        -- consume its permit or authorize another effect while held.
        RETURN NEW;
    END IF;
    IF EXISTS (SELECT 1 FROM authority_recovery_scopes
        WHERE tenant_id = NEW.tenant_id AND workspace_id = NEW.workspace_id
          AND organization_version_id = NEW.organization_version_id) THEN
        RAISE EXCEPTION 'provider_recovery_fenced' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER authority_guard_provider_recovery_insert BEFORE INSERT ON authority_effect_attempts
    FOR EACH ROW EXECUTE FUNCTION authority_guard_provider_recovery();
CREATE TRIGGER authority_guard_provider_recovery_claim BEFORE UPDATE OF state ON authority_effect_attempts
    FOR EACH ROW WHEN (NEW.state IN ('ADMITTED', 'DISPATCHING') AND NEW.state IS DISTINCT FROM OLD.state)
    EXECUTE FUNCTION authority_guard_provider_recovery();

-- A held version cannot be made ambiguous or replaced through provisioning.
-- That would let new credentials escape the exact version cutoff or hold a
-- neighbor organization which happened to reuse the version string.
CREATE FUNCTION authority_guard_recovery_provision() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    PERFORM 1 FROM authority_tenants WHERE tenant_id=NEW.tenant_id FOR SHARE;
    IF EXISTS (SELECT 1 FROM authority_recovery_scopes
        WHERE tenant_id=NEW.tenant_id
          AND ((org_ref=NEW.org_ref AND organization_version_id<>NEW.version_ref)
            OR (org_ref<>NEW.org_ref AND organization_version_id=NEW.version_ref))) THEN
        RAISE EXCEPTION 'provider_recovery_provision_fenced' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER authority_guard_recovery_provision BEFORE INSERT OR UPDATE OF version_ref ON authority_provisions
    FOR EACH ROW EXECUTE FUNCTION authority_guard_recovery_provision();
