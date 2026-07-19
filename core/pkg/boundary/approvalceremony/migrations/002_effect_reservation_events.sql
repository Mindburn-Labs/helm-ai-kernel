CREATE TABLE IF NOT EXISTS approval_effect_reservation_events (
    tenant_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    admission_id TEXT NOT NULL,
    sequence BIGINT NOT NULL,
    state TEXT NOT NULL,
    attempt_id TEXT NOT NULL,
    approval_id TEXT NOT NULL,
    grant_id TEXT NOT NULL,
    grant_hash TEXT NOT NULL,
    consumption_hash TEXT NOT NULL,
    consumer_subject TEXT NOT NULL,
    audience TEXT NOT NULL,
    idempotency_key_hash TEXT NOT NULL,
    effect_hash TEXT NOT NULL,
    action TEXT NOT NULL,
    connector_action TEXT NOT NULL,
    connector_id TEXT NOT NULL,
    connector_version TEXT NOT NULL,
    release_scope_kind TEXT NOT NULL,
    release_authority_id TEXT NOT NULL,
    release_registry_revision BIGINT NOT NULL,
    release_authority_hash TEXT NOT NULL,
    release_observed_at TIMESTAMPTZ NOT NULL,
    admission_json JSONB NOT NULL,
    release_authority_json JSONB NOT NULL,
    admitted_at TIMESTAMPTZ NOT NULL,
    started_at TIMESTAMPTZ,
    resolved_at TIMESTAMPTZ,
    occurred_at TIMESTAMPTZ NOT NULL,
    reason_code TEXT,
    connector_execution_ref TEXT,
    proof_session_ref TEXT,
    intent_ref TEXT,
    effect_ref TEXT,
    PRIMARY KEY (tenant_id, workspace_id, admission_id, sequence),
    CONSTRAINT approval_effect_reservation_sequence_ck CHECK (sequence BETWEEN 1 AND 9007199254740991),
    CONSTRAINT approval_effect_reservation_release_revision_ck CHECK (release_registry_revision BETWEEN 1 AND 9007199254740991),
    CONSTRAINT approval_effect_reservation_state_ck CHECK (state IN ('ADMITTED', 'STARTED', 'NOT_STARTED', 'UNCERTAIN')),
    CONSTRAINT approval_effect_reservation_json_ck CHECK (
        jsonb_typeof(admission_json) = 'object'
        AND jsonb_typeof(release_authority_json) = 'object'
    ),
    CONSTRAINT approval_effect_reservation_timeline_ck CHECK (
        admitted_at = release_observed_at
        AND occurred_at >= admitted_at
        AND (started_at IS NULL OR started_at >= admitted_at)
        AND (resolved_at IS NULL OR resolved_at >= admitted_at)
    ),
    CONSTRAINT approval_effect_reservation_shape_ck CHECK (
        (state = 'ADMITTED' AND sequence = 1 AND started_at IS NULL AND resolved_at IS NULL
            AND occurred_at = admitted_at AND reason_code IS NULL AND connector_execution_ref IS NULL
            AND proof_session_ref IS NULL AND intent_ref IS NULL AND effect_ref IS NULL)
        OR
        (state = 'STARTED' AND sequence = 2 AND started_at = occurred_at AND resolved_at IS NULL
            AND connector_execution_ref IS NOT NULL)
        OR
        (state = 'NOT_STARTED' AND sequence = 2 AND started_at IS NULL AND resolved_at = occurred_at
            AND reason_code IS NOT NULL AND connector_execution_ref IS NULL)
        OR
        (state = 'UNCERTAIN' AND sequence IN (2, 3) AND resolved_at = occurred_at AND reason_code IS NOT NULL
            AND ((sequence = 2 AND started_at IS NULL) OR (sequence = 3 AND started_at IS NOT NULL)))
    )
);

CREATE INDEX IF NOT EXISTS approval_effect_reservation_active_idx
    ON approval_effect_reservation_events (tenant_id, workspace_id, state, occurred_at DESC)
    WHERE state IN ('ADMITTED', 'STARTED', 'UNCERTAIN');

ALTER TABLE approval_effect_reservation_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE approval_effect_reservation_events FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = current_schema()
          AND tablename = 'approval_effect_reservation_events'
          AND policyname = 'approval_effect_reservation_events_tenant_isolation'
    ) THEN
        CREATE POLICY approval_effect_reservation_events_tenant_isolation
            ON approval_effect_reservation_events
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

ALTER POLICY approval_effect_reservation_events_tenant_isolation
    ON approval_effect_reservation_events
    USING (
        tenant_id = current_setting('app.current_tenant', true)
        AND workspace_id = current_setting('app.current_workspace', true)
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant', true)
        AND workspace_id = current_setting('app.current_workspace', true)
    );

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
    RAISE EXCEPTION 'approval effect reservation transition is terminal or invalid'
        USING ERRCODE = '55000';
END
$$;

CREATE OR REPLACE FUNCTION reject_approval_effect_reservation_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    RAISE EXCEPTION 'approval effect reservation history is append-only'
        USING ERRCODE = '55000';
END
$$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgrelid = 'approval_effect_reservation_events'::regclass
          AND tgname = 'approval_effect_reservation_events_enforce_append'
          AND NOT tgisinternal
    ) THEN
        CREATE TRIGGER approval_effect_reservation_events_enforce_append
            BEFORE INSERT ON approval_effect_reservation_events
            FOR EACH ROW EXECUTE FUNCTION enforce_approval_effect_reservation_append();
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgrelid = 'approval_effect_reservation_events'::regclass
          AND tgname = 'approval_effect_reservation_events_append_only'
          AND NOT tgisinternal
    ) THEN
        CREATE TRIGGER approval_effect_reservation_events_append_only
            BEFORE UPDATE OR DELETE ON approval_effect_reservation_events
            FOR EACH ROW EXECUTE FUNCTION reject_approval_effect_reservation_mutation();
    END IF;
END
$$;

REVOKE ALL ON TABLE approval_effect_reservation_events FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_approval_effect_reservation_append() FROM PUBLIC;
REVOKE ALL ON FUNCTION reject_approval_effect_reservation_mutation() FROM PUBLIC;
