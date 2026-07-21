ALTER TABLE approval_effect_reservation_events
    ADD COLUMN IF NOT EXISTS close_prior_state TEXT,
    ADD COLUMN IF NOT EXISTS acknowledgement_hash TEXT,
    ADD COLUMN IF NOT EXISTS close_receipt_hash TEXT,
    ADD COLUMN IF NOT EXISTS outcome TEXT,
    ADD COLUMN IF NOT EXISTS evidence_pack_ref TEXT,
    ADD COLUMN IF NOT EXISTS evidence_pack_hash TEXT,
    ADD COLUMN IF NOT EXISTS reconciliation_ref TEXT;

DO $$
DECLARE
    state_definition TEXT;
    shape_definition TEXT;
BEGIN
    SELECT pg_get_constraintdef(oid) INTO state_definition
    FROM pg_constraint
    WHERE conrelid = 'approval_effect_reservation_events'::regclass
      AND conname = 'approval_effect_reservation_state_ck';
    IF state_definition IS NULL OR position('COMPLETED' IN state_definition) = 0 THEN
        ALTER TABLE approval_effect_reservation_events
            DROP CONSTRAINT IF EXISTS approval_effect_reservation_state_ck;
        ALTER TABLE approval_effect_reservation_events
            ADD CONSTRAINT approval_effect_reservation_state_ck
                CHECK (state IN ('ADMITTED', 'STARTED', 'NOT_STARTED', 'UNCERTAIN', 'COMPLETED'));
    END IF;

    SELECT pg_get_constraintdef(oid) INTO shape_definition
    FROM pg_constraint
    WHERE conrelid = 'approval_effect_reservation_events'::regclass
      AND conname = 'approval_effect_reservation_shape_ck';
    IF shape_definition IS NULL OR position('close_prior_state' IN shape_definition) = 0 THEN
        ALTER TABLE approval_effect_reservation_events
            DROP CONSTRAINT IF EXISTS approval_effect_reservation_shape_ck;
        ALTER TABLE approval_effect_reservation_events
            ADD CONSTRAINT approval_effect_reservation_shape_ck CHECK (
        (state = 'ADMITTED' AND sequence = 1 AND started_at IS NULL AND resolved_at IS NULL
            AND occurred_at = admitted_at AND reason_code IS NULL AND connector_execution_ref IS NULL
            AND proof_session_ref IS NULL AND intent_ref IS NULL AND effect_ref IS NULL
            AND close_prior_state IS NULL AND acknowledgement_hash IS NULL AND close_receipt_hash IS NULL
            AND outcome IS NULL AND evidence_pack_ref IS NULL AND evidence_pack_hash IS NULL
            AND reconciliation_ref IS NULL)
        OR
        (state = 'STARTED' AND sequence = 2 AND started_at = occurred_at AND resolved_at IS NULL
            AND connector_execution_ref IS NOT NULL
            AND close_prior_state IS NULL AND acknowledgement_hash IS NULL AND close_receipt_hash IS NULL
            AND outcome IS NULL AND evidence_pack_ref IS NULL AND evidence_pack_hash IS NULL
            AND reconciliation_ref IS NULL)
        OR
        (state = 'NOT_STARTED' AND sequence = 2 AND started_at IS NULL AND resolved_at = occurred_at
            AND reason_code IS NOT NULL AND connector_execution_ref IS NULL
            AND close_prior_state IS NULL AND acknowledgement_hash IS NULL AND close_receipt_hash IS NULL
            AND outcome IS NULL AND evidence_pack_ref IS NULL AND evidence_pack_hash IS NULL
            AND reconciliation_ref IS NULL)
        OR
        (state = 'UNCERTAIN' AND sequence IN (2, 3) AND resolved_at = occurred_at AND reason_code IS NOT NULL
            AND ((sequence = 2 AND started_at IS NULL) OR (sequence = 3 AND started_at IS NOT NULL))
            AND close_prior_state IS NULL AND acknowledgement_hash IS NULL AND close_receipt_hash IS NULL
            AND outcome IS NULL AND evidence_pack_ref IS NULL AND evidence_pack_hash IS NULL
            AND reconciliation_ref IS NULL)
        OR
        (state = 'COMPLETED' AND sequence IN (3, 4) AND resolved_at = occurred_at AND reason_code IS NULL
            AND connector_execution_ref IS NOT NULL AND intent_ref IS NOT NULL
            AND close_prior_state IN ('STARTED', 'UNCERTAIN')
            AND acknowledgement_hash IS NOT NULL AND close_receipt_hash IS NOT NULL
            AND outcome IN ('APPLIED', 'NOT_APPLIED')
            AND evidence_pack_ref IS NOT NULL AND evidence_pack_hash IS NOT NULL
            AND ((outcome = 'APPLIED' AND effect_ref IS NOT NULL)
                OR (outcome = 'NOT_APPLIED' AND effect_ref IS NULL))
            AND ((close_prior_state = 'STARTED' AND sequence = 3 AND started_at IS NOT NULL)
                OR (close_prior_state = 'UNCERTAIN' AND reconciliation_ref IS NOT NULL
                    AND ((sequence = 3 AND started_at IS NULL)
                        OR (sequence = 4 AND started_at IS NOT NULL)))))
            );
    END IF;
END
$$;

CREATE TABLE IF NOT EXISTS approval_effect_closures (
    tenant_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    admission_id TEXT NOT NULL,
    close_id TEXT NOT NULL,
    acknowledgement_hash TEXT NOT NULL,
    receipt_hash TEXT NOT NULL,
    outcome TEXT NOT NULL,
    evidence_pack_ref TEXT NOT NULL,
    evidence_pack_hash TEXT NOT NULL,
    acknowledgement_json JSONB NOT NULL,
    receipt_json JSONB NOT NULL,
    signature_algorithm TEXT NOT NULL,
    signature TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, workspace_id, admission_id),
    UNIQUE (tenant_id, workspace_id, close_id),
    UNIQUE (tenant_id, workspace_id, acknowledgement_hash),
    CONSTRAINT approval_effect_closures_outcome_ck CHECK (outcome IN ('APPLIED', 'NOT_APPLIED')),
    CONSTRAINT approval_effect_closures_json_ck CHECK (
        jsonb_typeof(acknowledgement_json) = 'object'
        AND jsonb_typeof(receipt_json) = 'object'
    )
);

ALTER TABLE approval_effect_closures ENABLE ROW LEVEL SECURITY;
ALTER TABLE approval_effect_closures FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = current_schema()
          AND tablename = 'approval_effect_closures'
          AND policyname = 'approval_effect_closures_tenant_isolation'
    ) THEN
        CREATE POLICY approval_effect_closures_tenant_isolation
            ON approval_effect_closures
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

ALTER POLICY approval_effect_closures_tenant_isolation
    ON approval_effect_closures
    USING (
        tenant_id = current_setting('app.current_tenant', true)
        AND workspace_id = current_setting('app.current_workspace', true)
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant', true)
        AND workspace_id = current_setting('app.current_workspace', true)
    );

CREATE OR REPLACE FUNCTION enforce_approval_effect_closure_append()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
    head_sequence BIGINT;
    head_state TEXT;
BEGIN
    IF NEW.acknowledgement_json#>>'{acknowledgement,admission_id}' IS DISTINCT FROM NEW.admission_id
        OR NEW.acknowledgement_json#>>'{acknowledgement,tenant_id}' IS DISTINCT FROM NEW.tenant_id
        OR NEW.acknowledgement_json#>>'{acknowledgement,workspace_id}' IS DISTINCT FROM NEW.workspace_id
        OR NEW.acknowledgement_json#>>'{acknowledgement,acknowledgement_hash}' IS DISTINCT FROM NEW.acknowledgement_hash
        OR NEW.acknowledgement_json#>>'{acknowledgement,outcome}' IS DISTINCT FROM NEW.outcome
        OR NEW.receipt_json->>'admission_id' IS DISTINCT FROM NEW.admission_id
        OR NEW.receipt_json->>'tenant_id' IS DISTINCT FROM NEW.tenant_id
        OR NEW.receipt_json->>'workspace_id' IS DISTINCT FROM NEW.workspace_id
        OR NEW.receipt_json->>'close_id' IS DISTINCT FROM NEW.close_id
        OR NEW.receipt_json->>'acknowledgement_hash' IS DISTINCT FROM NEW.acknowledgement_hash
        OR NEW.receipt_json->>'receipt_hash' IS DISTINCT FROM NEW.receipt_hash
        OR NEW.receipt_json->>'outcome' IS DISTINCT FROM NEW.outcome
        OR NEW.receipt_json->>'evidence_pack_ref' IS DISTINCT FROM NEW.evidence_pack_ref
        OR NEW.receipt_json->>'evidence_pack_hash' IS DISTINCT FROM NEW.evidence_pack_hash
        OR (NEW.receipt_json->>'closed_at')::timestamptz IS DISTINCT FROM NEW.created_at
    THEN
        RAISE EXCEPTION 'approval effect closure shadow columns differ from signed artifacts'
            USING ERRCODE = '23514';
    END IF;

    PERFORM pg_advisory_xact_lock(hashtext(NEW.tenant_id), hashtext(NEW.workspace_id));

    EXECUTE format(
        'SELECT sequence, state FROM %I.approval_effect_reservation_events '
        'WHERE tenant_id = $1 AND workspace_id = $2 AND admission_id = $3 '
        'ORDER BY sequence DESC LIMIT 1',
        TG_TABLE_SCHEMA
    ) INTO head_sequence, head_state
    USING NEW.tenant_id, NEW.workspace_id, NEW.admission_id;

    IF head_state NOT IN ('STARTED', 'UNCERTAIN')
        OR (NEW.receipt_json->>'reservation_sequence')::bigint IS DISTINCT FROM head_sequence
        OR NEW.receipt_json->>'prior_state' IS DISTINCT FROM head_state
    THEN
        RAISE EXCEPTION 'approval effect closure does not bind the current closable reservation head'
            USING ERRCODE = '40001';
    END IF;
    RETURN NEW;
END
$$;

CREATE OR REPLACE FUNCTION reject_approval_effect_closure_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    RAISE EXCEPTION 'approval effect closure history is append-only'
        USING ERRCODE = '55000';
END
$$;

CREATE OR REPLACE FUNCTION enforce_approval_effect_reservation_append()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
    head_sequence BIGINT;
    head_state TEXT;
    head_started_at TIMESTAMPTZ;
    head_connector_execution_ref TEXT;
    head_proof_session_ref TEXT;
    head_intent_ref TEXT;
    head_effect_ref TEXT;
    head_admission JSONB;
    head_release JSONB;
    head_release_observed_at TIMESTAMPTZ;
    head_admitted_at TIMESTAMPTZ;
    closure_receipt_hash TEXT;
    closure_acknowledgement_hash TEXT;
    closure_outcome TEXT;
    closure_evidence_pack_ref TEXT;
    closure_evidence_pack_hash TEXT;
    closure_receipt JSONB;
BEGIN
    IF NEW.admission_json#>>'{admission,admission_id}' IS DISTINCT FROM NEW.admission_id
        OR NEW.admission_json#>>'{admission,attempt_id}' IS DISTINCT FROM NEW.attempt_id
        OR NEW.admission_json#>>'{admission,approval_id}' IS DISTINCT FROM NEW.approval_id
        OR NEW.admission_json#>>'{admission,grant_id}' IS DISTINCT FROM NEW.grant_id
        OR NEW.admission_json#>>'{admission,grant_hash}' IS DISTINCT FROM NEW.grant_hash
        OR NEW.admission_json#>>'{admission,consumption_hash}' IS DISTINCT FROM NEW.consumption_hash
        OR NEW.admission_json#>>'{admission,tenant_id}' IS DISTINCT FROM NEW.tenant_id
        OR NEW.admission_json#>>'{admission,workspace_id}' IS DISTINCT FROM NEW.workspace_id
        OR NEW.admission_json#>>'{admission,audience}' IS DISTINCT FROM NEW.audience
        OR NEW.admission_json#>>'{admission,admitted_by}' IS DISTINCT FROM NEW.consumer_subject
        OR NEW.admission_json#>>'{admission,idempotency_key_hash}' IS DISTINCT FROM NEW.idempotency_key_hash
        OR NEW.admission_json#>>'{admission,effect_hash}' IS DISTINCT FROM NEW.effect_hash
        OR NEW.admission_json#>>'{admission,action}' IS DISTINCT FROM NEW.action
        OR NEW.admission_json#>>'{admission,connector_authority,connector_action}' IS DISTINCT FROM NEW.connector_action
        OR NEW.admission_json#>>'{admission,connector_authority,connector_id}' IS DISTINCT FROM NEW.connector_id
        OR NEW.admission_json#>>'{admission,connector_authority,connector_version}' IS DISTINCT FROM NEW.connector_version
        OR NEW.admission_json#>>'{admission,connector_authority,release_scope_kind}' IS DISTINCT FROM NEW.release_scope_kind
        OR NEW.admission_json#>>'{admission,connector_authority,release_authority_id}' IS DISTINCT FROM NEW.release_authority_id
        OR NEW.admission_json#>>'{admission,connector_authority,release_registry_revision}' IS DISTINCT FROM NEW.release_registry_revision::TEXT
        OR NEW.admission_json#>>'{admission,connector_authority,release_authority_hash}' IS DISTINCT FROM NEW.release_authority_hash
        OR NEW.release_authority_json#>>'{authority,scope_kind}' IS DISTINCT FROM NEW.release_scope_kind
        OR NEW.release_authority_json#>>'{authority,authority_id}' IS DISTINCT FROM NEW.release_authority_id
        OR NEW.release_authority_json#>>'{authority,registry_revision}' IS DISTINCT FROM NEW.release_registry_revision::TEXT
        OR NEW.release_authority_json#>>'{authority,authority_hash}' IS DISTINCT FROM NEW.release_authority_hash
        OR NEW.release_authority_json#>>'{authority,connector_id}' IS DISTINCT FROM NEW.connector_id
        OR NEW.release_authority_json#>>'{authority,connector_version}' IS DISTINCT FROM NEW.connector_version
    THEN
        RAISE EXCEPTION 'approval effect reservation shadow columns differ from authority artifacts'
            USING ERRCODE = '23514';
    END IF;

    PERFORM pg_advisory_xact_lock(hashtext(NEW.tenant_id), hashtext(NEW.workspace_id));

    EXECUTE format(
        'SELECT sequence, state, started_at, connector_execution_ref, proof_session_ref, intent_ref, effect_ref, '
        'admission_json, release_authority_json, release_observed_at, admitted_at '
        'FROM %I.%I WHERE tenant_id = $1 AND workspace_id = $2 AND admission_id = $3 '
        'ORDER BY sequence DESC LIMIT 1',
        TG_TABLE_SCHEMA,
        TG_TABLE_NAME
    )
    INTO head_sequence, head_state, head_started_at, head_connector_execution_ref, head_proof_session_ref,
        head_intent_ref, head_effect_ref, head_admission, head_release, head_release_observed_at, head_admitted_at
    USING NEW.tenant_id, NEW.workspace_id, NEW.admission_id;

    IF head_sequence IS NULL THEN
        IF NEW.sequence <> 1 OR NEW.state <> 'ADMITTED' THEN
            RAISE EXCEPTION 'approval effect reservation must start at ADMITTED sequence 1'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.sequence <> head_sequence + 1
        OR NEW.admission_json IS DISTINCT FROM head_admission
        OR NEW.release_authority_json IS DISTINCT FROM head_release
        OR NEW.release_observed_at IS DISTINCT FROM head_release_observed_at
        OR NEW.admitted_at IS DISTINCT FROM head_admitted_at
    THEN
        RAISE EXCEPTION 'approval effect reservation successor changed immutable authority or skipped sequence'
            USING ERRCODE = '40001';
    END IF;

    IF head_state = 'ADMITTED' AND NEW.state IN ('STARTED', 'NOT_STARTED', 'UNCERTAIN') THEN
        RETURN NEW;
    END IF;
    IF head_state = 'STARTED' AND NEW.state = 'UNCERTAIN'
        AND NEW.started_at IS NOT DISTINCT FROM head_started_at
        AND NEW.connector_execution_ref IS NOT DISTINCT FROM head_connector_execution_ref
        AND NEW.proof_session_ref IS NOT DISTINCT FROM head_proof_session_ref
        AND NEW.intent_ref IS NOT DISTINCT FROM head_intent_ref
        AND (head_effect_ref IS NULL OR NEW.effect_ref IS NOT DISTINCT FROM head_effect_ref)
    THEN
        RETURN NEW;
    END IF;
    IF head_state IN ('STARTED', 'UNCERTAIN') AND NEW.state = 'COMPLETED'
        AND NEW.close_prior_state = head_state
        AND NEW.started_at IS NOT DISTINCT FROM head_started_at
        AND NEW.connector_execution_ref IS NOT DISTINCT FROM head_connector_execution_ref
        AND NEW.proof_session_ref IS NOT DISTINCT FROM head_proof_session_ref
        AND NEW.intent_ref IS NOT DISTINCT FROM head_intent_ref
        AND (head_effect_ref IS NULL OR NEW.effect_ref IS NOT DISTINCT FROM head_effect_ref)
    THEN
        EXECUTE format(
            'SELECT receipt_hash, acknowledgement_hash, outcome, evidence_pack_ref, evidence_pack_hash, receipt_json '
            'FROM %I.approval_effect_closures '
            'WHERE tenant_id = $1 AND workspace_id = $2 AND admission_id = $3',
            TG_TABLE_SCHEMA
        ) INTO closure_receipt_hash, closure_acknowledgement_hash, closure_outcome,
            closure_evidence_pack_ref, closure_evidence_pack_hash, closure_receipt
        USING NEW.tenant_id, NEW.workspace_id, NEW.admission_id;

        IF closure_receipt_hash IS DISTINCT FROM NEW.close_receipt_hash
            OR closure_acknowledgement_hash IS DISTINCT FROM NEW.acknowledgement_hash
            OR closure_outcome IS DISTINCT FROM NEW.outcome
            OR closure_evidence_pack_ref IS DISTINCT FROM NEW.evidence_pack_ref
            OR closure_evidence_pack_hash IS DISTINCT FROM NEW.evidence_pack_hash
            OR closure_receipt->>'prior_state' IS DISTINCT FROM head_state
            OR (closure_receipt->>'reservation_sequence')::bigint IS DISTINCT FROM head_sequence
            OR closure_receipt->>'connector_execution_ref' IS DISTINCT FROM NEW.connector_execution_ref
            OR COALESCE(closure_receipt->>'proof_session_ref', '') IS DISTINCT FROM COALESCE(NEW.proof_session_ref, '')
            OR closure_receipt->>'intent_ref' IS DISTINCT FROM NEW.intent_ref
            OR COALESCE(closure_receipt->>'effect_ref', '') IS DISTINCT FROM COALESCE(NEW.effect_ref, '')
            OR COALESCE(closure_receipt->>'reconciliation_ref', '') IS DISTINCT FROM COALESCE(NEW.reconciliation_ref, '')
            OR (closure_receipt->>'closed_at')::timestamptz IS DISTINCT FROM NEW.occurred_at
        THEN
            RAISE EXCEPTION 'COMPLETED event does not match its signed effect closure'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'approval effect reservation transition is terminal or invalid'
        USING ERRCODE = '55000';
END
$$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgrelid = 'approval_effect_closures'::regclass
          AND tgname = 'approval_effect_closures_enforce_append'
          AND NOT tgisinternal
    ) THEN
        CREATE TRIGGER approval_effect_closures_enforce_append
            BEFORE INSERT ON approval_effect_closures
            FOR EACH ROW EXECUTE FUNCTION enforce_approval_effect_closure_append();
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgrelid = 'approval_effect_closures'::regclass
          AND tgname = 'approval_effect_closures_append_only'
          AND NOT tgisinternal
    ) THEN
        CREATE TRIGGER approval_effect_closures_append_only
            BEFORE UPDATE OR DELETE ON approval_effect_closures
            FOR EACH ROW EXECUTE FUNCTION reject_approval_effect_closure_mutation();
    END IF;
END
$$;

REVOKE ALL ON TABLE approval_effect_closures FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_approval_effect_closure_append() FROM PUBLIC;
REVOKE ALL ON FUNCTION reject_approval_effect_closure_mutation() FROM PUBLIC;
