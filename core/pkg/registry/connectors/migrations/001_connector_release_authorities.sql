CREATE TABLE IF NOT EXISTS connector_release_authorities (
    scope_kind TEXT NOT NULL,
    tenant_id TEXT NOT NULL DEFAULT '',
    workspace_id TEXT NOT NULL DEFAULT '',
    connector_id TEXT NOT NULL,
    connector_version TEXT NOT NULL,
    registry_revision BIGINT NOT NULL,
    state TEXT NOT NULL,
    authority_hash TEXT NOT NULL,
    previous_authority_hash TEXT,
    revokes_authority_hash TEXT,
    signed_at TIMESTAMPTZ(6) NOT NULL,
    valid_from TIMESTAMPTZ(6) NOT NULL,
    valid_until TIMESTAMPTZ(6),
    envelope_json JSONB NOT NULL,
    signature TEXT NOT NULL,
    created_at TIMESTAMPTZ(6) NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (
        scope_kind,
        tenant_id,
        workspace_id,
        connector_id,
        connector_version,
        registry_revision
    ),
    CONSTRAINT connector_release_authorities_scope_ck CHECK (
        (scope_kind = 'global' AND tenant_id = '' AND workspace_id = '')
        OR
        (scope_kind = 'tenant_workspace' AND tenant_id <> '' AND workspace_id <> '')
    ),
    CONSTRAINT connector_release_authorities_revision_ck CHECK (
        registry_revision > 0 AND registry_revision <= 9007199254740991
    ),
    CONSTRAINT connector_release_authorities_state_ck CHECK (state IN ('certified', 'revoked')),
    CONSTRAINT connector_release_authorities_time_ck CHECK (
        signed_at <= valid_from
        AND (valid_until IS NULL OR valid_until > valid_from)
    ),
    CONSTRAINT connector_release_authorities_hash_ck CHECK (
        authority_hash ~ '^sha256:[0-9a-f]{64}$'
        AND (previous_authority_hash IS NULL OR previous_authority_hash ~ '^sha256:[0-9a-f]{64}$')
        AND (revokes_authority_hash IS NULL OR revokes_authority_hash ~ '^sha256:[0-9a-f]{64}$')
    ),
    CONSTRAINT connector_release_authorities_chain_ck CHECK (
        (registry_revision = 1 AND previous_authority_hash IS NULL)
        OR
        (registry_revision > 1 AND previous_authority_hash IS NOT NULL)
    ),
    CONSTRAINT connector_release_authorities_lifecycle_ck CHECK (
        (state = 'certified' AND valid_until IS NOT NULL AND revokes_authority_hash IS NULL)
        OR
        (
            state = 'revoked'
            AND registry_revision > 1
            AND valid_until IS NULL
            AND revokes_authority_hash = previous_authority_hash
        )
    ),
    CONSTRAINT connector_release_authorities_signature_ck CHECK (signature ~ '^[0-9a-f]{128}$'),
    CONSTRAINT connector_release_authorities_envelope_ck CHECK (jsonb_typeof(envelope_json) = 'object')
);

CREATE UNIQUE INDEX IF NOT EXISTS connector_release_authorities_hash_uq
    ON connector_release_authorities (authority_hash);

CREATE INDEX IF NOT EXISTS connector_release_authorities_current_idx
    ON connector_release_authorities (
        scope_kind,
        tenant_id,
        workspace_id,
        connector_id,
        connector_version,
        registry_revision DESC
    );

ALTER TABLE connector_release_authorities ENABLE ROW LEVEL SECURITY;
ALTER TABLE connector_release_authorities FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_policies
        WHERE schemaname = current_schema()
          AND tablename = 'connector_release_authorities'
          AND policyname = 'connector_release_authorities_scope_isolation'
    ) THEN
        CREATE POLICY connector_release_authorities_scope_isolation
            ON connector_release_authorities
            USING (
                scope_kind = 'global'
                OR (
                    scope_kind = 'tenant_workspace'
                    AND tenant_id = current_setting('app.current_tenant', true)
                    AND workspace_id = current_setting('app.current_workspace', true)
                )
            )
            WITH CHECK (
                scope_kind = 'global'
                OR (
                    scope_kind = 'tenant_workspace'
                    AND tenant_id = current_setting('app.current_tenant', true)
                    AND workspace_id = current_setting('app.current_workspace', true)
                )
            );
    END IF;
END
$$;

ALTER POLICY connector_release_authorities_scope_isolation
    ON connector_release_authorities
    USING (
        scope_kind = 'global'
        OR (
            scope_kind = 'tenant_workspace'
            AND tenant_id = current_setting('app.current_tenant', true)
            AND workspace_id = current_setting('app.current_workspace', true)
        )
    )
    WITH CHECK (
        scope_kind = 'global'
        OR (
            scope_kind = 'tenant_workspace'
            AND tenant_id = current_setting('app.current_tenant', true)
            AND workspace_id = current_setting('app.current_workspace', true)
        )
    );

CREATE OR REPLACE FUNCTION enforce_connector_release_authority_append()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
    head_revision BIGINT;
    head_state TEXT;
    head_hash TEXT;
    head_envelope JSONB;
    head_signed_at TIMESTAMPTZ;
    head_valid_from TIMESTAMPTZ;
    material_field TEXT;
BEGIN
    IF jsonb_typeof(NEW.envelope_json->'authority') IS DISTINCT FROM 'object' THEN
        RAISE EXCEPTION 'connector release authority envelope must contain an authority object'
            USING ERRCODE = '23514';
    END IF;

    IF NEW.envelope_json->>'signature' IS DISTINCT FROM NEW.signature
        OR NEW.envelope_json#>>'{authority,scope_kind}' IS DISTINCT FROM NEW.scope_kind
        OR NEW.envelope_json#>>'{authority,tenant_id}' IS DISTINCT FROM NULLIF(NEW.tenant_id, '')
        OR NEW.envelope_json#>>'{authority,workspace_id}' IS DISTINCT FROM NULLIF(NEW.workspace_id, '')
        OR NEW.envelope_json#>>'{authority,connector_id}' IS DISTINCT FROM NEW.connector_id
        OR NEW.envelope_json#>>'{authority,connector_version}' IS DISTINCT FROM NEW.connector_version
        OR NEW.envelope_json#>>'{authority,registry_revision}' IS DISTINCT FROM NEW.registry_revision::TEXT
        OR NEW.envelope_json#>>'{authority,state}' IS DISTINCT FROM NEW.state
        OR NEW.envelope_json#>>'{authority,authority_hash}' IS DISTINCT FROM NEW.authority_hash
        OR NEW.envelope_json#>>'{authority,previous_authority_hash}' IS DISTINCT FROM NEW.previous_authority_hash
        OR NEW.envelope_json#>>'{authority,revokes_authority_hash}' IS DISTINCT FROM NEW.revokes_authority_hash
        OR (NEW.envelope_json#>>'{authority,signed_at}')::TIMESTAMPTZ IS DISTINCT FROM NEW.signed_at
        OR (NEW.envelope_json#>>'{authority,valid_from}')::TIMESTAMPTZ IS DISTINCT FROM NEW.valid_from
        OR ((NEW.envelope_json#>>'{authority,valid_until}') IS NULL) IS DISTINCT FROM (NEW.valid_until IS NULL)
        OR (
            (NEW.envelope_json#>>'{authority,valid_until}') IS NOT NULL
            AND (NEW.envelope_json#>>'{authority,valid_until}')::TIMESTAMPTZ IS DISTINCT FROM NEW.valid_until
        )
    THEN
        RAISE EXCEPTION 'connector release authority shadow columns differ from envelope'
            USING ERRCODE = '23514';
    END IF;

    PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(
        chr(31), NEW.scope_kind, NEW.tenant_id, NEW.workspace_id,
        NEW.connector_id, NEW.connector_version
    ), 0));

    EXECUTE format(
        'SELECT registry_revision, state, authority_hash, envelope_json, signed_at, valid_from '
        'FROM %I.%I '
        'WHERE scope_kind = $1 AND tenant_id = $2 AND workspace_id = $3 '
        'AND connector_id = $4 AND connector_version = $5 '
        'ORDER BY registry_revision DESC LIMIT 1',
        TG_TABLE_SCHEMA,
        TG_TABLE_NAME
    )
    INTO head_revision, head_state, head_hash, head_envelope, head_signed_at, head_valid_from
    USING NEW.scope_kind, NEW.tenant_id, NEW.workspace_id, NEW.connector_id, NEW.connector_version;

    IF head_revision IS NULL THEN
        IF NEW.registry_revision <> 1 OR NEW.previous_authority_hash IS NOT NULL THEN
            RAISE EXCEPTION 'connector release authority first revision must be 1'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    IF head_state = 'revoked' THEN
        RAISE EXCEPTION 'connector release authority revocation is terminal'
            USING ERRCODE = '55000';
    END IF;
    IF NEW.registry_revision <> head_revision + 1 OR NEW.previous_authority_hash <> head_hash THEN
        RAISE EXCEPTION 'connector release authority revision is not the current head successor'
            USING ERRCODE = '40001';
    END IF;
    IF NEW.signed_at < head_signed_at OR NEW.valid_from < head_valid_from THEN
        RAISE EXCEPTION 'connector release authority signed timeline moved backwards'
            USING ERRCODE = '23514';
    END IF;

    FOREACH material_field IN ARRAY ARRAY[
        'schema_version',
        'contract_version',
        'authority_id',
        'algorithm',
        'scope_kind',
        'tenant_id',
        'workspace_id',
        'connector_id',
        'connector_version',
        'connector_executor_kind',
        'connector_sandbox_profile',
        'connector_drift_policy_ref',
        'connector_binary_hash',
        'connector_signature_ref',
        'connector_signature_hash',
        'connector_signer_id',
        'certification_ref',
        'certification_hash',
        'certification_authority'
    ]
    LOOP
        IF NEW.envelope_json#>>ARRAY['authority', material_field]
            IS DISTINCT FROM head_envelope#>>ARRAY['authority', material_field]
        THEN
            RAISE EXCEPTION 'connector release authority exact-version material changed: %', material_field
                USING ERRCODE = '23514';
        END IF;
    END LOOP;

    RETURN NEW;
END
$$;

CREATE OR REPLACE FUNCTION reject_connector_release_authority_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    RAISE EXCEPTION 'connector release authority history is append-only'
        USING ERRCODE = '55000';
END
$$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_trigger
        WHERE tgrelid = 'connector_release_authorities'::regclass
          AND tgname = 'connector_release_authorities_enforce_append'
          AND NOT tgisinternal
    ) THEN
        CREATE TRIGGER connector_release_authorities_enforce_append
            BEFORE INSERT ON connector_release_authorities
            FOR EACH ROW
            EXECUTE FUNCTION enforce_connector_release_authority_append();
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM pg_trigger
        WHERE tgrelid = 'connector_release_authorities'::regclass
          AND tgname = 'connector_release_authorities_append_only'
          AND NOT tgisinternal
    ) THEN
        CREATE TRIGGER connector_release_authorities_append_only
            BEFORE UPDATE OR DELETE ON connector_release_authorities
            FOR EACH ROW
            EXECUTE FUNCTION reject_connector_release_authority_mutation();
    END IF;
END
$$;

REVOKE ALL ON TABLE connector_release_authorities FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_connector_release_authority_append() FROM PUBLIC;
REVOKE ALL ON FUNCTION reject_connector_release_authority_mutation() FROM PUBLIC;
