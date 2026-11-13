-- Owner passkeys (helm-tracker#334): the human principals' WebAuthn
-- credentials the gateway verifies approvals with, and the verified owner
-- assertion an approval kept. Forced row security on the new table is applied
-- by schema.go.
--
-- A credential is enrolled once, by exactly one of two acts: the tenant's
-- genesis (EnsurePrincipals on a tenant it creates, with the owner's
-- self-signed genesis assertion, kept here so it can be verified again
-- offline), or an approved provision plan (enrolled_attempt_id). A tenant has
-- at most one genesis credential: its owner's. Only the signature counter of a
-- credential ever changes, and it never goes backwards.
CREATE TABLE IF NOT EXISTS authority_principal_credentials (
    tenant_id                  TEXT NOT NULL,
    credential_id              BYTEA NOT NULL CHECK (octet_length(credential_id) BETWEEN 1 AND 1023),
    principal_id               TEXT NOT NULL,
    alg                        INTEGER NOT NULL CHECK (alg IN (-7, -8)),
    public_key_spki            BYTEA NOT NULL CHECK (octet_length(public_key_spki) BETWEEN 1 AND 512),
    rp_id                      TEXT NOT NULL CHECK (octet_length(rp_id) BETWEEN 1 AND 253),
    sign_count                 BIGINT NOT NULL DEFAULT 0 CHECK (sign_count BETWEEN 0 AND 4294967295),
    enrolled_by                TEXT NOT NULL CHECK (enrolled_by IN ('genesis', 'plan')),
    enrolled_attempt_id        UUID,
    genesis_authenticator_data BYTEA,
    genesis_client_data_json   BYTEA,
    genesis_signature          BYTEA,
    created_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, credential_id),
    FOREIGN KEY (tenant_id, principal_id) REFERENCES authority_principals (tenant_id, principal_id),
    CHECK ((enrolled_by = 'genesis') = (enrolled_attempt_id IS NULL)),
    CHECK ((enrolled_by = 'genesis') = (genesis_authenticator_data IS NOT NULL
        AND genesis_client_data_json IS NOT NULL AND genesis_signature IS NOT NULL)),
    CHECK (enrolled_by = 'genesis' OR (genesis_authenticator_data IS NULL
        AND genesis_client_data_json IS NULL AND genesis_signature IS NULL))
);
CREATE UNIQUE INDEX IF NOT EXISTS authority_principal_credentials_one_genesis
    ON authority_principal_credentials (tenant_id) WHERE enrolled_by = 'genesis';
CREATE INDEX IF NOT EXISTS authority_principal_credentials_principal
    ON authority_principal_credentials (tenant_id, principal_id);

CREATE OR REPLACE FUNCTION authority_guard_principal_credential() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR NEW.credential_id IS DISTINCT FROM OLD.credential_id
        OR NEW.principal_id IS DISTINCT FROM OLD.principal_id OR NEW.alg IS DISTINCT FROM OLD.alg
        OR NEW.public_key_spki IS DISTINCT FROM OLD.public_key_spki OR NEW.rp_id IS DISTINCT FROM OLD.rp_id
        OR NEW.enrolled_by IS DISTINCT FROM OLD.enrolled_by OR NEW.enrolled_attempt_id IS DISTINCT FROM OLD.enrolled_attempt_id
        OR NEW.genesis_authenticator_data IS DISTINCT FROM OLD.genesis_authenticator_data
        OR NEW.genesis_client_data_json IS DISTINCT FROM OLD.genesis_client_data_json
        OR NEW.genesis_signature IS DISTINCT FROM OLD.genesis_signature OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'an enrolled credential changes only its signature counter' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.sign_count < OLD.sign_count THEN
        RAISE EXCEPTION 'a credential''s signature counter never goes backwards' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;
DROP TRIGGER IF EXISTS authority_guard_principal_credential_update ON authority_principal_credentials;
CREATE TRIGGER authority_guard_principal_credential_update BEFORE UPDATE ON authority_principal_credentials
    FOR EACH ROW EXECUTE FUNCTION authority_guard_principal_credential();

-- The owner assertion an approval used, kept exactly as received with the
-- credential it verified against and the counter it carried, so a later
-- receipt binding can carry it and a verifier can check it again offline.
-- All NULL for an approval without one and for a rejection. IS NOT NULL comes
-- first in the second branch because a CHECK passes on NULL.
ALTER TABLE authority_approvals ADD COLUMN IF NOT EXISTS owner_credential_id BYTEA;
ALTER TABLE authority_approvals ADD COLUMN IF NOT EXISTS owner_challenge BYTEA;
ALTER TABLE authority_approvals ADD COLUMN IF NOT EXISTS owner_authenticator_data BYTEA;
ALTER TABLE authority_approvals ADD COLUMN IF NOT EXISTS owner_client_data_json BYTEA;
ALTER TABLE authority_approvals ADD COLUMN IF NOT EXISTS owner_signature BYTEA;
ALTER TABLE authority_approvals ADD COLUMN IF NOT EXISTS owner_sign_count BIGINT;
ALTER TABLE authority_approvals DROP CONSTRAINT IF EXISTS authority_approvals_owner_assertion;
ALTER TABLE authority_approvals ADD CONSTRAINT authority_approvals_owner_assertion CHECK (
    (owner_credential_id IS NULL AND owner_challenge IS NULL AND owner_authenticator_data IS NULL
        AND owner_client_data_json IS NULL AND owner_signature IS NULL AND owner_sign_count IS NULL)
    OR (decision = 'APPROVED'
        AND owner_credential_id IS NOT NULL AND owner_challenge IS NOT NULL AND owner_authenticator_data IS NOT NULL
        AND owner_client_data_json IS NOT NULL AND owner_signature IS NOT NULL AND owner_sign_count IS NOT NULL
        AND octet_length(owner_challenge) = 32 AND owner_sign_count BETWEEN 0 AND 4294967295));
