CREATE TABLE IF NOT EXISTS approval_effect_dispositions (
    tenant_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    admission_id TEXT NOT NULL,
    command_id TEXT NOT NULL,
    disposition_sequence BIGINT NOT NULL,
    command_hash TEXT NOT NULL,
    previous_receipt_hash TEXT,
    action TEXT NOT NULL,
    disposition_ref TEXT NOT NULL,
    fence_command_id TEXT NOT NULL,
    fence_command_hash TEXT NOT NULL,
    fence_epoch BIGINT NOT NULL,
    fence_receipt_hash TEXT NOT NULL,
    reservation_sequence BIGINT NOT NULL,
    reservation_head_hash TEXT NOT NULL,
    reservation_state TEXT NOT NULL,
    fence_json JSONB NOT NULL,
    command_envelope_json JSONB NOT NULL,
    receipt_json JSONB NOT NULL,
    signature_algorithm TEXT NOT NULL,
    signature TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, workspace_id, command_id),
    UNIQUE (tenant_id, workspace_id, admission_id, disposition_sequence),
    UNIQUE (tenant_id, workspace_id, disposition_ref),
    CONSTRAINT approval_effect_dispositions_sequence_ck CHECK (
        disposition_sequence BETWEEN 1 AND 9007199254740991
        AND fence_epoch BETWEEN 1 AND 9007199254740991
        AND reservation_sequence BETWEEN 1 AND 9007199254740991
        AND ((disposition_sequence = 1 AND previous_receipt_hash IS NULL)
            OR (disposition_sequence > 1 AND previous_receipt_hash IS NOT NULL))
    ),
    CONSTRAINT approval_effect_dispositions_action_ck CHECK (
        action IN ('HOLD', 'RECONCILE_SOURCE', 'REQUEST_CANCEL', 'REQUEST_COMPENSATE')
    ),
    CONSTRAINT approval_effect_dispositions_state_ck CHECK (
        reservation_state IN ('STARTED', 'UNCERTAIN')
    ),
    CONSTRAINT approval_effect_dispositions_json_ck CHECK (
        jsonb_typeof(fence_json) = 'object'
        AND jsonb_typeof(command_envelope_json) = 'object'
        AND jsonb_typeof(receipt_json) = 'object'
    )
);

ALTER TABLE approval_effect_dispositions ENABLE ROW LEVEL SECURITY;
ALTER TABLE approval_effect_dispositions FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = current_schema()
          AND tablename = 'approval_effect_dispositions'
          AND policyname = 'approval_effect_dispositions_tenant_isolation'
    ) THEN
        CREATE POLICY approval_effect_dispositions_tenant_isolation
            ON approval_effect_dispositions
            USING (
                tenant_id = current_setting('app.current_tenant', true)
                AND workspace_id = current_setting('app.current_workspace', true)
            )
            WITH CHECK (
                tenant_id = current_setting('app.current_tenant', true)
                AND workspace_id = current_setting('app.current_workspace', true)
            );
    END IF;
END
$$;

ALTER POLICY approval_effect_dispositions_tenant_isolation
    ON approval_effect_dispositions
    USING (
        tenant_id = current_setting('app.current_tenant', true)
        AND workspace_id = current_setting('app.current_workspace', true)
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant', true)
        AND workspace_id = current_setting('app.current_workspace', true)
    );

CREATE OR REPLACE FUNCTION enforce_approval_effect_disposition_append()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
    head_sequence BIGINT;
    head_state TEXT;
    fence_command_id_current TEXT;
    fence_command_hash_current TEXT;
    fence_epoch_current BIGINT;
    fence_receipt_hash_current TEXT;
    prior_disposition_sequence BIGINT;
    prior_receipt_hash TEXT;
BEGIN
    IF NEW.command_envelope_json#>>'{command,tenant_id}' IS DISTINCT FROM NEW.tenant_id
        OR NEW.command_envelope_json#>>'{command,workspace_id}' IS DISTINCT FROM NEW.workspace_id
        OR NEW.command_envelope_json#>>'{command,admission_id}' IS DISTINCT FROM NEW.admission_id
        OR NEW.command_envelope_json#>>'{command,command_id}' IS DISTINCT FROM NEW.command_id
        OR (NEW.command_envelope_json#>>'{command,disposition_sequence}')::bigint IS DISTINCT FROM NEW.disposition_sequence
        OR NEW.command_envelope_json#>>'{command,command_hash}' IS DISTINCT FROM NEW.command_hash
        OR COALESCE(NEW.command_envelope_json#>>'{command,previous_receipt_hash}', '')
            IS DISTINCT FROM COALESCE(NEW.previous_receipt_hash, '')
        OR NEW.command_envelope_json#>>'{command,action}' IS DISTINCT FROM NEW.action
        OR NEW.command_envelope_json#>>'{command,disposition_ref}' IS DISTINCT FROM NEW.disposition_ref
        OR NEW.command_envelope_json#>>'{command,fence_command_id}' IS DISTINCT FROM NEW.fence_command_id
        OR NEW.command_envelope_json#>>'{command,fence_command_hash}' IS DISTINCT FROM NEW.fence_command_hash
        OR (NEW.command_envelope_json#>>'{command,fence_epoch}')::bigint IS DISTINCT FROM NEW.fence_epoch
        OR NEW.command_envelope_json#>>'{command,fence_receipt_hash}' IS DISTINCT FROM NEW.fence_receipt_hash
        OR (NEW.command_envelope_json#>>'{command,reservation_sequence}')::bigint IS DISTINCT FROM NEW.reservation_sequence
        OR NEW.command_envelope_json#>>'{command,reservation_head_hash}' IS DISTINCT FROM NEW.reservation_head_hash
        OR NEW.command_envelope_json#>>'{command,reservation_state}' IS DISTINCT FROM NEW.reservation_state
        OR NEW.fence_json->>'tenant_id' IS DISTINCT FROM NEW.tenant_id
        OR NEW.fence_json->>'workspace_id' IS DISTINCT FROM NEW.workspace_id
        OR NEW.fence_json->>'command_id' IS DISTINCT FROM NEW.fence_command_id
        OR NEW.fence_json->>'command_hash' IS DISTINCT FROM NEW.fence_command_hash
        OR (NEW.fence_json->>'epoch')::bigint IS DISTINCT FROM NEW.fence_epoch
        OR NEW.fence_json->>'receipt_hash' IS DISTINCT FROM NEW.fence_receipt_hash
        OR NEW.receipt_json->>'command_id' IS DISTINCT FROM NEW.command_id
        OR NEW.receipt_json->>'command_hash' IS DISTINCT FROM NEW.command_hash
        OR (NEW.receipt_json->>'disposition_sequence')::bigint IS DISTINCT FROM NEW.disposition_sequence
        OR COALESCE(NEW.receipt_json->>'previous_receipt_hash', '')
            IS DISTINCT FROM COALESCE(NEW.previous_receipt_hash, '')
        OR NEW.receipt_json->>'tenant_id' IS DISTINCT FROM NEW.tenant_id
        OR NEW.receipt_json->>'workspace_id' IS DISTINCT FROM NEW.workspace_id
        OR NEW.receipt_json->>'admission_id' IS DISTINCT FROM NEW.admission_id
        OR NEW.receipt_json->>'fence_command_id' IS DISTINCT FROM NEW.fence_command_id
        OR NEW.receipt_json->>'fence_command_hash' IS DISTINCT FROM NEW.fence_command_hash
        OR (NEW.receipt_json->>'fence_epoch')::bigint IS DISTINCT FROM NEW.fence_epoch
        OR NEW.receipt_json->>'fence_receipt_hash' IS DISTINCT FROM NEW.fence_receipt_hash
        OR (NEW.receipt_json->>'reservation_sequence')::bigint IS DISTINCT FROM NEW.reservation_sequence
        OR NEW.receipt_json->>'reservation_head_hash' IS DISTINCT FROM NEW.reservation_head_hash
        OR NEW.receipt_json->>'reservation_state' IS DISTINCT FROM NEW.reservation_state
        OR NEW.receipt_json->>'action' IS DISTINCT FROM NEW.action
        OR NEW.receipt_json->>'disposition_ref' IS DISTINCT FROM NEW.disposition_ref
        OR NEW.receipt_json->>'state' IS DISTINCT FROM 'ACCEPTED'
        OR NEW.receipt_json->>'execution_authority' IS DISTINCT FROM 'NONE'
        OR (NEW.receipt_json->>'accepted_at')::timestamptz IS DISTINCT FROM NEW.created_at
    THEN
        RAISE EXCEPTION 'approval effect disposition shadow columns differ from signed artifacts'
            USING ERRCODE = '23514';
    END IF;

    PERFORM pg_advisory_xact_lock(hashtext(NEW.tenant_id), hashtext(NEW.workspace_id));

    EXECUTE format(
        'SELECT command_id, command_hash, epoch, receipt_hash '
        'FROM %I.emergency_stop_fences WHERE tenant_id = $1 AND workspace_id = $2',
        TG_TABLE_SCHEMA
    ) INTO fence_command_id_current, fence_command_hash_current, fence_epoch_current, fence_receipt_hash_current
    USING NEW.tenant_id, NEW.workspace_id;

    IF fence_command_id_current IS DISTINCT FROM NEW.fence_command_id
        OR fence_command_hash_current IS DISTINCT FROM NEW.fence_command_hash
        OR fence_epoch_current IS DISTINCT FROM NEW.fence_epoch
        OR fence_receipt_hash_current IS DISTINCT FROM NEW.fence_receipt_hash
    THEN
        RAISE EXCEPTION 'approval effect disposition does not bind the current FENCE'
            USING ERRCODE = '40001';
    END IF;

    EXECUTE format(
        'SELECT sequence, state FROM %I.approval_effect_reservation_events '
        'WHERE tenant_id = $1 AND workspace_id = $2 AND admission_id = $3 '
        'ORDER BY sequence DESC LIMIT 1',
        TG_TABLE_SCHEMA
    ) INTO head_sequence, head_state
    USING NEW.tenant_id, NEW.workspace_id, NEW.admission_id;

    IF head_sequence IS DISTINCT FROM NEW.reservation_sequence
        OR head_state IS DISTINCT FROM NEW.reservation_state
        OR head_state NOT IN ('STARTED', 'UNCERTAIN')
    THEN
        RAISE EXCEPTION 'approval effect disposition does not bind the current active reservation head'
            USING ERRCODE = '40001';
    END IF;

    EXECUTE format(
        'SELECT disposition_sequence, receipt_json->>''receipt_hash'' '
        'FROM %I.approval_effect_dispositions '
        'WHERE tenant_id = $1 AND workspace_id = $2 AND admission_id = $3 '
        'ORDER BY disposition_sequence DESC LIMIT 1',
        TG_TABLE_SCHEMA
    ) INTO prior_disposition_sequence, prior_receipt_hash
    USING NEW.tenant_id, NEW.workspace_id, NEW.admission_id;

    IF prior_disposition_sequence IS NULL THEN
        IF NEW.disposition_sequence <> 1 OR NEW.previous_receipt_hash IS NOT NULL THEN
            RAISE EXCEPTION 'approval effect disposition chain must start at sequence 1'
                USING ERRCODE = '40001';
        END IF;
    ELSIF NEW.disposition_sequence <> prior_disposition_sequence + 1
        OR NEW.previous_receipt_hash IS DISTINCT FROM prior_receipt_hash
    THEN
        RAISE EXCEPTION 'approval effect disposition chain skipped or changed its predecessor'
            USING ERRCODE = '40001';
    END IF;
    RETURN NEW;
END
$$;

CREATE OR REPLACE FUNCTION reject_approval_effect_disposition_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    RAISE EXCEPTION 'approval effect disposition history is append-only'
        USING ERRCODE = '55000';
END
$$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgrelid = 'approval_effect_dispositions'::regclass
          AND tgname = 'approval_effect_dispositions_enforce_append'
          AND NOT tgisinternal
    ) THEN
        CREATE TRIGGER approval_effect_dispositions_enforce_append
            BEFORE INSERT ON approval_effect_dispositions
            FOR EACH ROW EXECUTE FUNCTION enforce_approval_effect_disposition_append();
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgrelid = 'approval_effect_dispositions'::regclass
          AND tgname = 'approval_effect_dispositions_append_only'
          AND NOT tgisinternal
    ) THEN
        CREATE TRIGGER approval_effect_dispositions_append_only
            BEFORE UPDATE OR DELETE ON approval_effect_dispositions
            FOR EACH ROW EXECUTE FUNCTION reject_approval_effect_disposition_mutation();
    END IF;
END
$$;

REVOKE ALL ON TABLE approval_effect_dispositions FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_approval_effect_disposition_append() FROM PUBLIC;
REVOKE ALL ON FUNCTION reject_approval_effect_disposition_mutation() FROM PUBLIC;
