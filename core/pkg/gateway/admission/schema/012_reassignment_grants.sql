-- One current recipient generation per exact work item. A grant is usable
-- only while this row still names its generation and grant_id. Both read and
-- replay consult it in the same tenant transaction as the member read.
ALTER TABLE authority_effect_attempts
    ADD COLUMN IF NOT EXISTS episode_profile TEXT CHECK (episode_profile IN ('worker', 'executor'));

CREATE TABLE IF NOT EXISTS authority_reassignment_work (
    tenant_id      TEXT NOT NULL REFERENCES authority_tenants (tenant_id),
    workspace_id   TEXT NOT NULL CHECK (workspace_id <> ''),
    work_item_id   TEXT NOT NULL CHECK (work_item_id <> ''),
    generation     BIGINT NOT NULL CHECK (generation > 0),
    grant_id       UUID NOT NULL,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, workspace_id, work_item_id)
);

-- Installed by the approved Kernel authority effect, never by an episode
-- token or CP-only assignment. The producer's prepared manifest and native
-- drain are pinned by digest; the original effect attempt remains untouched.
CREATE TABLE IF NOT EXISTS authority_reassignment_grants (
    tenant_id               TEXT NOT NULL REFERENCES authority_tenants (tenant_id),
    grant_id                UUID NOT NULL,
    grant_attempt_id        UUID NOT NULL,
    workspace_id            TEXT NOT NULL CHECK (workspace_id <> ''),
    org_ref                 TEXT NOT NULL CHECK (org_ref ~ '^org:[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
    work_item_id            TEXT NOT NULL CHECK (work_item_id <> ''),
    organization_version_id TEXT NOT NULL CHECK (organization_version_id <> ''),
    commitment_id           TEXT NOT NULL CHECK (commitment_id <> ''),
    terms_digest            BYTEA NOT NULL CHECK (length(terms_digest) = 32),
    manifest_digest         BYTEA NOT NULL CHECK (length(manifest_digest) = 32),
    drain_digest            BYTEA NOT NULL CHECK (length(drain_digest) = 32),
    plan_digest             TEXT NOT NULL CHECK (plan_digest ~ '^[0-9a-f]{64}$'),
    authority_revision      BIGINT NOT NULL CHECK (authority_revision > 0),
    generation              BIGINT NOT NULL CHECK (generation > 0),
    recipient_episode_id    TEXT NOT NULL CHECK (recipient_episode_id <> ''),
    recipient_seat_id       TEXT NOT NULL CHECK (recipient_seat_id <> ''),
    recipient_principal_id  TEXT NOT NULL CHECK (recipient_principal_id <> ''),
    recipient_actor_id      TEXT NOT NULL CHECK (recipient_actor_id <> ''),
    recipient_profile       TEXT NOT NULL CHECK (recipient_profile IN ('worker', 'executor')),
    recipient_client        TEXT NOT NULL,
    approved_by             TEXT NOT NULL CHECK (approved_by <> ''),
    expires_at              TIMESTAMPTZ NOT NULL,
    revoked_at              TIMESTAMPTZ,
    revoked_by              TEXT,
    revoke_reason           TEXT CHECK (revoke_reason IS NULL OR octet_length(revoke_reason) BETWEEN 1 AND 1024),
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, grant_id),
    UNIQUE (tenant_id, grant_attempt_id),
    UNIQUE (tenant_id, workspace_id, work_item_id, generation),
    FOREIGN KEY (tenant_id, grant_attempt_id) REFERENCES authority_effect_attempts (tenant_id, attempt_id),
    FOREIGN KEY (tenant_id, approved_by) REFERENCES authority_principals (tenant_id, principal_id),
    FOREIGN KEY (tenant_id, recipient_principal_id) REFERENCES authority_principals (tenant_id, principal_id),
    CHECK (recipient_principal_id = 'agt:' || recipient_seat_id),
    CHECK ((recipient_profile = 'worker' AND recipient_client = '')
        OR (recipient_profile = 'executor' AND recipient_client <> '')),
    CHECK (expires_at > created_at)
);

ALTER TABLE authority_reassignment_work
    ADD CONSTRAINT authority_reassignment_work_grant
    FOREIGN KEY (tenant_id, grant_id) REFERENCES authority_reassignment_grants (tenant_id, grant_id);

-- A row lists exactly one original attempt, with the original source binding.
-- No permit, approval, quote or exposure is copied or reassigned.
CREATE TABLE IF NOT EXISTS authority_reassignment_members (
    tenant_id            TEXT NOT NULL,
    grant_id             UUID NOT NULL,
    attempt_id           UUID NOT NULL,
    source_episode_id    TEXT NOT NULL CHECK (source_episode_id <> ''),
    source_principal_id  TEXT NOT NULL CHECK (source_principal_id <> ''),
    source_actor_id      TEXT NOT NULL CHECK (source_actor_id <> ''),
    PRIMARY KEY (tenant_id, grant_id, attempt_id),
    FOREIGN KEY (tenant_id, grant_id) REFERENCES authority_reassignment_grants (tenant_id, grant_id),
    FOREIGN KEY (tenant_id, attempt_id) REFERENCES authority_effect_attempts (tenant_id, attempt_id)
);
CREATE INDEX IF NOT EXISTS authority_reassignment_members_by_attempt
    ON authority_reassignment_members (tenant_id, attempt_id, grant_id);

-- Serialize a first work-effect insert with the complete-membership scan of
-- grant installation. A source proposal that began before installation is
-- either included in that scan or waits and is refused by the new generation.
-- A recipient may submit new effects only under its own episode and profile;
-- exact old effects use the read-only retained lookup before admission.
CREATE OR REPLACE FUNCTION authority_fence_reassigned_work()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    current_recipient RECORD;
BEGIN
    IF NEW.idempotency_key NOT LIKE 'work:%' OR NEW.case_id IS NULL THEN
        RETURN NEW;
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(
        json_build_array(NEW.tenant_id, NEW.workspace_id, NEW.case_id)::text, 754133));
    SELECT g.recipient_episode_id, g.recipient_principal_id, g.recipient_actor_id, g.recipient_profile,
           g.revoked_at, g.expires_at
      INTO current_recipient
      FROM authority_reassignment_work w
      JOIN authority_reassignment_grants g
        ON g.tenant_id = w.tenant_id AND g.grant_id = w.grant_id
     WHERE w.tenant_id = NEW.tenant_id AND w.workspace_id = NEW.workspace_id
       AND w.work_item_id = NEW.case_id;
    IF FOUND AND (current_recipient.revoked_at IS NOT NULL OR current_recipient.expires_at <= now()
        OR NEW.episode_id IS DISTINCT FROM current_recipient.recipient_episode_id
        OR NEW.requester_principal_id IS DISTINCT FROM current_recipient.recipient_principal_id
        OR NEW.requester_actor_id IS DISTINCT FROM current_recipient.recipient_actor_id
        OR NEW.episode_profile IS DISTINCT FROM current_recipient.recipient_profile) THEN
        RAISE EXCEPTION 'work_reassignment_fenced' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS authority_fence_reassigned_work_insert ON authority_effect_attempts;
CREATE TRIGGER authority_fence_reassigned_work_insert
    BEFORE INSERT ON authority_effect_attempts
    FOR EACH ROW EXECUTE FUNCTION authority_fence_reassigned_work();
