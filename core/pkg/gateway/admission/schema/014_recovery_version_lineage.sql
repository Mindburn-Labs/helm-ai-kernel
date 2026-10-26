-- CP lifecycle versions can advance without changing the applied authority plan.
-- Retain both identities and the exact CP-issued alias set outside CP restore.
ALTER TABLE authority_recovery_fences ADD COLUMN authority_version_ref TEXT;
ALTER TABLE authority_recovery_fences ADD COLUMN covered_version_refs JSONB;
ALTER TABLE authority_recovery_fences ADD COLUMN expected_plan_digest TEXT NOT NULL DEFAULT '';
UPDATE authority_recovery_fences SET authority_version_ref=organization_version_id,
    covered_version_refs=jsonb_build_array(organization_version_id);
ALTER TABLE authority_recovery_fences ALTER COLUMN authority_version_ref SET NOT NULL;
ALTER TABLE authority_recovery_fences ALTER COLUMN covered_version_refs SET NOT NULL;
ALTER TABLE authority_recovery_fences ADD CONSTRAINT authority_recovery_lineage_shape CHECK (
    authority_version_ref ~ '^[A-Za-z0-9._:-]{1,128}$'
    AND jsonb_typeof(covered_version_refs)='array'
    AND jsonb_array_length(covered_version_refs) BETWEEN 1 AND 4096
    AND covered_version_refs ? organization_version_id
    AND covered_version_refs ? authority_version_ref
    AND (expected_plan_digest='' OR expected_plan_digest=plan_digest));

-- Never guess which independent legacy operation superseded another. Such a
-- database keeps its original holds and requires explicit reconciliation before
-- this transaction can commit. Normal legacy singleton operations upgrade as-is.
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM authority_recovery_scopes
        GROUP BY tenant_id,workspace_id,org_ref HAVING count(*)>1) THEN
        RAISE EXCEPTION 'multiple legacy recovery scopes require reconciliation';
    END IF;
END $$;
ALTER TABLE authority_recovery_scopes ADD CONSTRAINT authority_recovery_current_org
    UNIQUE (tenant_id,workspace_id,org_ref);

-- The same immutable set drives admission, older-writer claims and inventory.
-- Keep the existing authority lock order and idempotency identity lookup.
CREATE OR REPLACE FUNCTION authority_guard_provider_recovery() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.organization_version_id IS NULL THEN
        RETURN NEW;
    END IF;
    PERFORM 1 FROM authority_tenants WHERE tenant_id=NEW.tenant_id FOR SHARE;
    IF TG_OP='INSERT' AND EXISTS (SELECT 1 FROM authority_effect_attempts
        WHERE tenant_id=NEW.tenant_id AND idempotency_key=NEW.idempotency_key) THEN
        RETURN NEW;
    END IF;
    IF EXISTS (SELECT 1 FROM authority_recovery_scopes s
        JOIN authority_recovery_fences f ON f.tenant_id=s.tenant_id AND f.operation_id=s.operation_id
        WHERE s.tenant_id=NEW.tenant_id AND s.workspace_id=NEW.workspace_id
          AND f.covered_version_refs ? NEW.organization_version_id) THEN
        RAISE EXCEPTION 'provider_recovery_fenced' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$;

-- Changing the native authority version cannot escape a held plan. A foreign
-- org cannot take an alias already bound by a trusted CP-issued recovery set.
CREATE OR REPLACE FUNCTION authority_guard_recovery_provision() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    PERFORM 1 FROM authority_tenants WHERE tenant_id=NEW.tenant_id FOR SHARE;
    IF EXISTS (SELECT 1 FROM authority_recovery_scopes s
        JOIN authority_recovery_fences f ON f.tenant_id=s.tenant_id AND f.operation_id=s.operation_id
        WHERE s.tenant_id=NEW.tenant_id
          AND ((s.org_ref=NEW.org_ref AND f.authority_version_ref<>NEW.version_ref)
            OR (s.org_ref<>NEW.org_ref AND f.covered_version_refs ? NEW.version_ref))) THEN
        RAISE EXCEPTION 'provider_recovery_provision_fenced' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$;
