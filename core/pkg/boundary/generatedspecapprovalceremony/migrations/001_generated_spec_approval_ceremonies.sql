CREATE TABLE IF NOT EXISTS generated_spec_approval_ceremonies (
    tenant_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    approval_id TEXT NOT NULL,
    state TEXT NOT NULL,

    binding_json JSONB NOT NULL,
    binding_ref TEXT NOT NULL,
    audience TEXT NOT NULL,
    generated_spec_id TEXT NOT NULL,
    generated_spec_hash TEXT NOT NULL,
    execution_plan_hash TEXT NOT NULL,
    plan_transaction_hash TEXT NOT NULL,
    write_set_hash TEXT NOT NULL,
    verification_scope_hash TEXT NOT NULL,
    policy_envelope_hash TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    policy_epoch TEXT NOT NULL,
    action TEXT NOT NULL,
    requesting_principal_id TEXT NOT NULL,
    authority_source TEXT NOT NULL,
    authority_version TEXT NOT NULL,
    authority_snapshot_hash TEXT NOT NULL,
    required_role TEXT NOT NULL,
    quorum INTEGER NOT NULL,
    server_identity TEXT NOT NULL,

    hold_started_at TIMESTAMPTZ NOT NULL,
    challenge_json JSONB,
    challenge_id TEXT,
    challenge_hash TEXT,
    challenge_nonce TEXT,
    assertions_json JSONB,
    quorum_verified_at TIMESTAMPTZ,
    grant_json JSONB,
    grant_id TEXT,
    grant_hash TEXT,
    grant_nonce TEXT,
    grant_signature_algorithm TEXT,
    grant_signature TEXT,
    consumption_json JSONB,
    consumption_hash TEXT,
    consumption_audience TEXT,
    consumption_signature_algorithm TEXT,
    consumption_signature TEXT,
    expires_at TIMESTAMPTZ,
    consumed_at TIMESTAMPTZ,
    consumed_by TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    version BIGINT NOT NULL DEFAULT 1,

    PRIMARY KEY (tenant_id, workspace_id, approval_id),
    CONSTRAINT generated_spec_approval_ceremony_state_ck CHECK (
        state IN ('HOLD_PENDING', 'CHALLENGE_ISSUED', 'QUORUM_VERIFIED', 'GRANT_ISSUED', 'CONSUMED', 'DENIED', 'EXPIRED')
    ),
    CONSTRAINT generated_spec_approval_ceremony_version_ck CHECK (version > 0),
    CONSTRAINT generated_spec_approval_ceremony_quorum_ck CHECK (quorum > 0),
    CONSTRAINT generated_spec_approval_ceremony_timeline_ck CHECK (
        created_at = hold_started_at AND updated_at >= created_at
    ),
    CONSTRAINT generated_spec_approval_ceremony_binding_shadow_ck CHECK (
        jsonb_typeof(binding_json) = 'object'
        AND binding_json ?& ARRAY['BindingRef', 'TenantID', 'WorkspaceID', 'Audience', 'GeneratedSpecID', 'GeneratedSpecHash', 'ExecutionPlanHash', 'PlanTransactionHash', 'WriteSetHash', 'VerificationScopeHash', 'PolicyEnvelopeHash', 'PolicyVersion', 'PolicyEpoch', 'Action', 'RequestingPrincipalID', 'AuthoritySource', 'AuthorityVersion', 'AuthoritySnapshotHash', 'RequiredRole', 'Quorum', 'ServerIdentity']
        AND binding_json->>'BindingRef' IS NOT DISTINCT FROM binding_ref
        AND binding_json->>'TenantID' IS NOT DISTINCT FROM tenant_id
        AND binding_json->>'WorkspaceID' IS NOT DISTINCT FROM workspace_id
        AND binding_json->>'Audience' IS NOT DISTINCT FROM audience
        AND binding_json->>'GeneratedSpecID' IS NOT DISTINCT FROM generated_spec_id
        AND binding_json->>'GeneratedSpecHash' IS NOT DISTINCT FROM generated_spec_hash
        AND binding_json->>'ExecutionPlanHash' IS NOT DISTINCT FROM execution_plan_hash
        AND binding_json->>'PlanTransactionHash' IS NOT DISTINCT FROM plan_transaction_hash
        AND binding_json->>'WriteSetHash' IS NOT DISTINCT FROM write_set_hash
        AND binding_json->>'VerificationScopeHash' IS NOT DISTINCT FROM verification_scope_hash
        AND binding_json->>'PolicyEnvelopeHash' IS NOT DISTINCT FROM policy_envelope_hash
        AND binding_json->>'PolicyVersion' IS NOT DISTINCT FROM policy_version
        AND binding_json->>'PolicyEpoch' IS NOT DISTINCT FROM policy_epoch
        AND binding_json->>'Action' IS NOT DISTINCT FROM action
        AND binding_json->>'RequestingPrincipalID' IS NOT DISTINCT FROM requesting_principal_id
        AND binding_json->>'AuthoritySource' IS NOT DISTINCT FROM authority_source
        AND binding_json->>'AuthorityVersion' IS NOT DISTINCT FROM authority_version
        AND binding_json->>'AuthoritySnapshotHash' IS NOT DISTINCT FROM authority_snapshot_hash
        AND binding_json->>'RequiredRole' IS NOT DISTINCT FROM required_role
        AND binding_json->>'ServerIdentity' IS NOT DISTINCT FROM server_identity
        AND (binding_json->>'Quorum')::INTEGER IS NOT DISTINCT FROM quorum
    ),
    CONSTRAINT generated_spec_approval_ceremony_challenge_shadow_ck CHECK (
        (challenge_json IS NULL AND challenge_id IS NULL AND challenge_hash IS NULL AND challenge_nonce IS NULL)
        OR
        (jsonb_typeof(challenge_json) = 'object'
            AND challenge_json ?& ARRAY['challenge_id', 'challenge_hash', 'nonce', 'approval_id', 'tenant_id', 'workspace_id', 'audience', 'generated_spec_id', 'generated_spec_hash', 'execution_plan_hash', 'plan_transaction_hash', 'write_set_hash', 'verification_scope_hash', 'policy_envelope_hash', 'policy_version', 'policy_epoch', 'action', 'requesting_principal_id', 'authority_source', 'authority_version', 'authority_snapshot_hash', 'required_role', 'quorum', 'server_identity']
            AND challenge_json->>'challenge_id' IS NOT DISTINCT FROM challenge_id
            AND challenge_json->>'challenge_hash' IS NOT DISTINCT FROM challenge_hash
            AND challenge_json->>'nonce' IS NOT DISTINCT FROM challenge_nonce
            AND challenge_json->>'approval_id' IS NOT DISTINCT FROM approval_id
            AND challenge_json->>'tenant_id' IS NOT DISTINCT FROM tenant_id
            AND challenge_json->>'workspace_id' IS NOT DISTINCT FROM workspace_id
            AND challenge_json->>'audience' IS NOT DISTINCT FROM audience
            AND challenge_json->>'generated_spec_id' IS NOT DISTINCT FROM generated_spec_id
            AND challenge_json->>'generated_spec_hash' IS NOT DISTINCT FROM generated_spec_hash
            AND challenge_json->>'execution_plan_hash' IS NOT DISTINCT FROM execution_plan_hash
            AND challenge_json->>'plan_transaction_hash' IS NOT DISTINCT FROM plan_transaction_hash
            AND challenge_json->>'write_set_hash' IS NOT DISTINCT FROM write_set_hash
            AND challenge_json->>'verification_scope_hash' IS NOT DISTINCT FROM verification_scope_hash
            AND challenge_json->>'policy_envelope_hash' IS NOT DISTINCT FROM policy_envelope_hash
            AND challenge_json->>'policy_version' IS NOT DISTINCT FROM policy_version
            AND challenge_json->>'policy_epoch' IS NOT DISTINCT FROM policy_epoch
            AND challenge_json->>'action' IS NOT DISTINCT FROM action
            AND challenge_json->>'requesting_principal_id' IS NOT DISTINCT FROM requesting_principal_id
            AND challenge_json->>'authority_source' IS NOT DISTINCT FROM authority_source
            AND challenge_json->>'authority_version' IS NOT DISTINCT FROM authority_version
            AND challenge_json->>'authority_snapshot_hash' IS NOT DISTINCT FROM authority_snapshot_hash
            AND challenge_json->>'required_role' IS NOT DISTINCT FROM required_role
            AND (challenge_json->>'quorum')::INTEGER IS NOT DISTINCT FROM quorum
            AND challenge_json->>'server_identity' IS NOT DISTINCT FROM server_identity)
    ),
    CONSTRAINT generated_spec_approval_ceremony_assertions_shape_ck CHECK (
        assertions_json IS NULL OR jsonb_typeof(assertions_json) = 'array'
    ),
    CONSTRAINT generated_spec_approval_ceremony_grant_shadow_ck CHECK (
        (grant_json IS NULL AND grant_id IS NULL AND grant_hash IS NULL AND grant_nonce IS NULL
            AND grant_signature_algorithm IS NULL AND grant_signature IS NULL)
        OR
        (jsonb_typeof(grant_json) = 'object' AND grant_json ?& ARRAY['grant', 'algorithm', 'signature']
            AND jsonb_typeof(grant_json->'grant') = 'object'
            AND grant_json->'grant' ?& ARRAY['grant_id', 'grant_hash', 'nonce', 'approval_id', 'tenant_id', 'workspace_id', 'audience', 'generated_spec_id', 'generated_spec_hash', 'execution_plan_hash', 'plan_transaction_hash', 'write_set_hash', 'verification_scope_hash', 'policy_envelope_hash', 'policy_version', 'policy_epoch', 'action', 'requesting_principal_id', 'authority_source', 'authority_version', 'authority_snapshot_hash', 'server_identity']
            AND grant_json#>>'{grant,grant_id}' IS NOT DISTINCT FROM grant_id
            AND grant_json#>>'{grant,grant_hash}' IS NOT DISTINCT FROM grant_hash
            AND grant_json#>>'{grant,nonce}' IS NOT DISTINCT FROM grant_nonce
            AND grant_json->>'algorithm' IS NOT DISTINCT FROM grant_signature_algorithm
            AND grant_json->>'signature' IS NOT DISTINCT FROM grant_signature
            AND grant_json#>>'{grant,approval_id}' IS NOT DISTINCT FROM approval_id
            AND grant_json#>>'{grant,tenant_id}' IS NOT DISTINCT FROM tenant_id
            AND grant_json#>>'{grant,workspace_id}' IS NOT DISTINCT FROM workspace_id
            AND grant_json#>>'{grant,audience}' IS NOT DISTINCT FROM audience
            AND grant_json#>>'{grant,generated_spec_id}' IS NOT DISTINCT FROM generated_spec_id
            AND grant_json#>>'{grant,generated_spec_hash}' IS NOT DISTINCT FROM generated_spec_hash
            AND grant_json#>>'{grant,execution_plan_hash}' IS NOT DISTINCT FROM execution_plan_hash
            AND grant_json#>>'{grant,plan_transaction_hash}' IS NOT DISTINCT FROM plan_transaction_hash
            AND grant_json#>>'{grant,write_set_hash}' IS NOT DISTINCT FROM write_set_hash
            AND grant_json#>>'{grant,verification_scope_hash}' IS NOT DISTINCT FROM verification_scope_hash
            AND grant_json#>>'{grant,policy_envelope_hash}' IS NOT DISTINCT FROM policy_envelope_hash
            AND grant_json#>>'{grant,policy_version}' IS NOT DISTINCT FROM policy_version
            AND grant_json#>>'{grant,policy_epoch}' IS NOT DISTINCT FROM policy_epoch
            AND grant_json#>>'{grant,action}' IS NOT DISTINCT FROM action
            AND grant_json#>>'{grant,requesting_principal_id}' IS NOT DISTINCT FROM requesting_principal_id
            AND grant_json#>>'{grant,authority_source}' IS NOT DISTINCT FROM authority_source
            AND grant_json#>>'{grant,authority_version}' IS NOT DISTINCT FROM authority_version
            AND grant_json#>>'{grant,authority_snapshot_hash}' IS NOT DISTINCT FROM authority_snapshot_hash
            AND grant_json#>>'{grant,server_identity}' IS NOT DISTINCT FROM server_identity)
    ),
    CONSTRAINT generated_spec_approval_ceremony_consumption_shadow_ck CHECK (
        (consumption_json IS NULL AND consumption_hash IS NULL AND consumption_audience IS NULL
            AND consumption_signature_algorithm IS NULL AND consumption_signature IS NULL
            AND consumed_at IS NULL AND consumed_by IS NULL)
        OR
        (jsonb_typeof(consumption_json) = 'object' AND consumption_json ?& ARRAY['consumption', 'algorithm', 'signature']
            AND jsonb_typeof(consumption_json->'consumption') = 'object'
            AND consumption_json->'consumption' ?& ARRAY['consumption_hash', 'audience', 'approval_id', 'tenant_id', 'workspace_id', 'consumed_by', 'grant_id', 'grant_hash']
            AND consumption_json#>>'{consumption,consumption_hash}' IS NOT DISTINCT FROM consumption_hash
            AND consumption_json#>>'{consumption,audience}' IS NOT DISTINCT FROM consumption_audience
            AND consumption_json->>'algorithm' IS NOT DISTINCT FROM consumption_signature_algorithm
            AND consumption_json->>'signature' IS NOT DISTINCT FROM consumption_signature
            AND consumption_json#>>'{consumption,approval_id}' IS NOT DISTINCT FROM approval_id
            AND consumption_json#>>'{consumption,tenant_id}' IS NOT DISTINCT FROM tenant_id
            AND consumption_json#>>'{consumption,workspace_id}' IS NOT DISTINCT FROM workspace_id
            AND consumption_json#>>'{consumption,consumed_by}' IS NOT DISTINCT FROM consumed_by
            AND consumption_json#>>'{consumption,grant_id}' IS NOT DISTINCT FROM grant_id
            AND consumption_json#>>'{consumption,grant_hash}' IS NOT DISTINCT FROM grant_hash)
    ),
    CONSTRAINT generated_spec_approval_ceremony_state_shape_ck CHECK (
        (state = 'HOLD_PENDING'
            AND challenge_json IS NULL AND assertions_json IS NULL AND quorum_verified_at IS NULL
            AND grant_json IS NULL AND consumption_json IS NULL AND expires_at IS NULL)
        OR
        (state = 'CHALLENGE_ISSUED'
            AND challenge_json IS NOT NULL AND assertions_json IS NULL AND quorum_verified_at IS NULL
            AND grant_json IS NULL AND consumption_json IS NULL AND expires_at IS NOT NULL)
        OR
        (state = 'QUORUM_VERIFIED'
            AND challenge_json IS NOT NULL AND assertions_json IS NOT NULL
            AND jsonb_array_length(assertions_json) >= quorum AND quorum_verified_at IS NOT NULL
            AND grant_json IS NULL AND consumption_json IS NULL AND expires_at IS NOT NULL)
        OR
        (state = 'GRANT_ISSUED'
            AND challenge_json IS NOT NULL AND assertions_json IS NOT NULL AND quorum_verified_at IS NOT NULL
            AND grant_json IS NOT NULL AND consumption_json IS NULL AND expires_at IS NOT NULL)
        OR
        (state = 'CONSUMED'
            AND challenge_json IS NOT NULL AND assertions_json IS NOT NULL AND quorum_verified_at IS NOT NULL
            AND grant_json IS NOT NULL AND consumption_json IS NOT NULL)
        OR
        (state = 'DENIED' AND consumption_json IS NULL)
        OR
        (state = 'EXPIRED' AND challenge_json IS NOT NULL AND consumption_json IS NULL AND expires_at IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS generated_spec_approval_ceremonies_active_scope_idx
    ON generated_spec_approval_ceremonies (tenant_id, workspace_id, state, updated_at DESC)
    WHERE state IN ('HOLD_PENDING', 'CHALLENGE_ISSUED', 'QUORUM_VERIFIED', 'GRANT_ISSUED');
CREATE INDEX IF NOT EXISTS generated_spec_approval_ceremonies_binding_ref_idx
    ON generated_spec_approval_ceremonies (tenant_id, workspace_id, binding_ref);
CREATE UNIQUE INDEX IF NOT EXISTS generated_spec_approval_ceremonies_challenge_id_uq
    ON generated_spec_approval_ceremonies (tenant_id, workspace_id, challenge_id)
    WHERE challenge_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS generated_spec_approval_ceremonies_challenge_hash_uq
    ON generated_spec_approval_ceremonies (tenant_id, workspace_id, challenge_hash)
    WHERE challenge_hash IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS generated_spec_approval_ceremonies_challenge_nonce_uq
    ON generated_spec_approval_ceremonies (tenant_id, workspace_id, challenge_nonce)
    WHERE challenge_nonce IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS generated_spec_approval_ceremonies_grant_id_uq
    ON generated_spec_approval_ceremonies (tenant_id, workspace_id, grant_id)
    WHERE grant_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS generated_spec_approval_ceremonies_grant_hash_uq
    ON generated_spec_approval_ceremonies (tenant_id, workspace_id, grant_hash)
    WHERE grant_hash IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS generated_spec_approval_ceremonies_grant_nonce_uq
    ON generated_spec_approval_ceremonies (tenant_id, workspace_id, grant_nonce)
    WHERE grant_nonce IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS generated_spec_approval_ceremonies_consumption_hash_uq
    ON generated_spec_approval_ceremonies (tenant_id, workspace_id, consumption_hash)
    WHERE consumption_hash IS NOT NULL;

CREATE OR REPLACE FUNCTION enforce_generated_spec_approval_ceremony_transition()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'HOLD_PENDING' OR NEW.version <> 1 THEN
            RAISE EXCEPTION 'generated spec approval ceremony must begin as HOLD_PENDING version 1'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
        OR NEW.workspace_id IS DISTINCT FROM OLD.workspace_id
        OR NEW.approval_id IS DISTINCT FROM OLD.approval_id
        OR NEW.binding_json IS DISTINCT FROM OLD.binding_json
        OR NEW.binding_ref IS DISTINCT FROM OLD.binding_ref
        OR NEW.audience IS DISTINCT FROM OLD.audience
        OR NEW.generated_spec_id IS DISTINCT FROM OLD.generated_spec_id
        OR NEW.generated_spec_hash IS DISTINCT FROM OLD.generated_spec_hash
        OR NEW.execution_plan_hash IS DISTINCT FROM OLD.execution_plan_hash
        OR NEW.plan_transaction_hash IS DISTINCT FROM OLD.plan_transaction_hash
        OR NEW.write_set_hash IS DISTINCT FROM OLD.write_set_hash
        OR NEW.verification_scope_hash IS DISTINCT FROM OLD.verification_scope_hash
        OR NEW.policy_envelope_hash IS DISTINCT FROM OLD.policy_envelope_hash
        OR NEW.policy_version IS DISTINCT FROM OLD.policy_version
        OR NEW.policy_epoch IS DISTINCT FROM OLD.policy_epoch
        OR NEW.action IS DISTINCT FROM OLD.action
        OR NEW.requesting_principal_id IS DISTINCT FROM OLD.requesting_principal_id
        OR NEW.authority_source IS DISTINCT FROM OLD.authority_source
        OR NEW.authority_version IS DISTINCT FROM OLD.authority_version
        OR NEW.authority_snapshot_hash IS DISTINCT FROM OLD.authority_snapshot_hash
        OR NEW.required_role IS DISTINCT FROM OLD.required_role
        OR NEW.quorum IS DISTINCT FROM OLD.quorum
        OR NEW.server_identity IS DISTINCT FROM OLD.server_identity
        OR NEW.hold_started_at IS DISTINCT FROM OLD.hold_started_at
        OR NEW.created_at IS DISTINCT FROM OLD.created_at
        OR NEW.version <> OLD.version + 1
        OR NEW.updated_at < OLD.updated_at
    THEN
        RAISE EXCEPTION 'generated spec approval ceremony immutable fields or version changed'
            USING ERRCODE = '23514';
    END IF;

    IF OLD.challenge_json IS NOT NULL AND (
        NEW.challenge_json IS DISTINCT FROM OLD.challenge_json
        OR NEW.challenge_id IS DISTINCT FROM OLD.challenge_id
        OR NEW.challenge_hash IS DISTINCT FROM OLD.challenge_hash
        OR NEW.challenge_nonce IS DISTINCT FROM OLD.challenge_nonce
    ) THEN
        RAISE EXCEPTION 'generated spec approval challenge is immutable after issuance'
            USING ERRCODE = '23514';
    END IF;
    IF OLD.assertions_json IS NOT NULL AND (
        NEW.assertions_json IS DISTINCT FROM OLD.assertions_json
        OR NEW.quorum_verified_at IS DISTINCT FROM OLD.quorum_verified_at
    ) THEN
        RAISE EXCEPTION 'generated spec approval assertions are immutable after verification'
            USING ERRCODE = '23514';
    END IF;
    IF OLD.grant_json IS NOT NULL AND (
        NEW.grant_json IS DISTINCT FROM OLD.grant_json
        OR NEW.grant_id IS DISTINCT FROM OLD.grant_id
        OR NEW.grant_hash IS DISTINCT FROM OLD.grant_hash
        OR NEW.grant_nonce IS DISTINCT FROM OLD.grant_nonce
        OR NEW.grant_signature_algorithm IS DISTINCT FROM OLD.grant_signature_algorithm
        OR NEW.grant_signature IS DISTINCT FROM OLD.grant_signature
        OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
    ) THEN
        RAISE EXCEPTION 'generated spec approval grant is immutable after issuance'
            USING ERRCODE = '23514';
    END IF;
    IF OLD.consumption_json IS NOT NULL AND (
        NEW.consumption_json IS DISTINCT FROM OLD.consumption_json
        OR NEW.consumption_hash IS DISTINCT FROM OLD.consumption_hash
        OR NEW.consumption_audience IS DISTINCT FROM OLD.consumption_audience
        OR NEW.consumption_signature_algorithm IS DISTINCT FROM OLD.consumption_signature_algorithm
        OR NEW.consumption_signature IS DISTINCT FROM OLD.consumption_signature
        OR NEW.consumed_at IS DISTINCT FROM OLD.consumed_at
        OR NEW.consumed_by IS DISTINCT FROM OLD.consumed_by
    ) THEN
        RAISE EXCEPTION 'generated spec approval consumption is immutable after use'
            USING ERRCODE = '23514';
    END IF;

    IF (OLD.state = 'HOLD_PENDING' AND NEW.state NOT IN ('CHALLENGE_ISSUED', 'DENIED'))
        OR (OLD.state = 'CHALLENGE_ISSUED' AND NEW.state NOT IN ('QUORUM_VERIFIED', 'DENIED', 'EXPIRED'))
        OR (OLD.state = 'QUORUM_VERIFIED' AND NEW.state NOT IN ('GRANT_ISSUED', 'DENIED', 'EXPIRED'))
        OR (OLD.state = 'GRANT_ISSUED' AND NEW.state NOT IN ('CONSUMED', 'DENIED', 'EXPIRED'))
        OR (OLD.state IN ('CONSUMED', 'DENIED', 'EXPIRED'))
    THEN
        RAISE EXCEPTION 'generated spec approval ceremony transition is invalid or terminal'
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS generated_spec_approval_ceremonies_enforce_transition
    ON generated_spec_approval_ceremonies;
CREATE TRIGGER generated_spec_approval_ceremonies_enforce_transition
    BEFORE INSERT OR UPDATE ON generated_spec_approval_ceremonies
    FOR EACH ROW EXECUTE FUNCTION enforce_generated_spec_approval_ceremony_transition();

ALTER TABLE generated_spec_approval_ceremonies ENABLE ROW LEVEL SECURITY;
ALTER TABLE generated_spec_approval_ceremonies FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = current_schema()
          AND tablename = 'generated_spec_approval_ceremonies'
          AND policyname = 'generated_spec_approval_ceremonies_scope_isolation'
    ) THEN
        CREATE POLICY generated_spec_approval_ceremonies_scope_isolation
            ON generated_spec_approval_ceremonies
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

ALTER POLICY generated_spec_approval_ceremonies_scope_isolation
    ON generated_spec_approval_ceremonies
    USING (
        tenant_id = current_setting('app.current_tenant', true)
        AND workspace_id = current_setting('app.current_workspace', true)
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant', true)
        AND workspace_id = current_setting('app.current_workspace', true)
    );

REVOKE ALL ON TABLE generated_spec_approval_ceremonies FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_generated_spec_approval_ceremony_transition() FROM PUBLIC;
