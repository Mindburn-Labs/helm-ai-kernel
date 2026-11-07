-- Signed decision receipts (helm-tracker#276). Every decision admission
-- records (ADMITTED, DENIED, ESCALATED) appends one signed receipt to its
-- workspace's hash chain, in the decision's own transaction, and the fence
-- at the end of this file refuses a decision that commits without one.
-- Forced row security on both tables is applied by schema.go.
--
-- The columns are generic: format names the signed envelope (receipt.v5
-- today), envelope holds its exact bytes, digest the chain hash the next
-- receipt links to, and binding the exact canonical bytes of the gateway's
-- binding document, whose SHA-256 the receipt signs as output_hash. A later
-- envelope format is a new format value, not a new table.

-- One chain per (tenant, workspace). seq and head_digest are the newest
-- receipt's; a chain with no receipt yet has neither. Admission locks the row
-- FOR UPDATE as the last row lock it takes on a pre-existing row, so the
-- decisions of one workspace serialize on it until they commit, and their
-- receipts are appended one at a time, in commit order.
CREATE TABLE IF NOT EXISTS authority_receipt_chains (
    tenant_id   TEXT NOT NULL REFERENCES authority_tenants (tenant_id),
    chain_id    TEXT NOT NULL CHECK (octet_length(chain_id) BETWEEN 1 AND 1024),
    format      TEXT NOT NULL CHECK (format ~ '^[a-z0-9][a-z0-9._-]{0,63}$'),
    seq         BIGINT NOT NULL DEFAULT 0 CHECK (seq >= 0),
    head_digest TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, chain_id),
    CHECK ((seq = 0) = (head_digest = '')),
    CHECK (head_digest = '' OR head_digest ~ '^[0-9a-f]{64}$')
);

-- Append-only: the runtime role holds SELECT and INSERT here and nothing else
-- (deploy/helm-chart/files/gateway-db/002_grants.sql). A chain never forks:
-- one receipt per sequence number, one successor per predecessor digest and
-- one genesis (prev_digest ''). One receipt per attempt version: the receipt
-- describes the attempt row its decision wrote.
CREATE TABLE IF NOT EXISTS authority_receipts (
    tenant_id       TEXT NOT NULL,
    chain_id        TEXT NOT NULL,
    seq             BIGINT NOT NULL CHECK (seq >= 1),
    receipt_id      UUID NOT NULL,
    format          TEXT NOT NULL CHECK (format ~ '^[a-z0-9][a-z0-9._-]{0,63}$'),
    prev_digest     TEXT NOT NULL,
    digest          TEXT NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$'),
    attempt_id      UUID NOT NULL,
    attempt_version BIGINT NOT NULL CHECK (attempt_version > 0),
    workspace_id    TEXT NOT NULL CHECK (workspace_id <> ''),
    state           TEXT NOT NULL CHECK (state IN ('ADMITTED', 'DENIED', 'ESCALATED')),
    key_id          TEXT NOT NULL CHECK (key_id <> ''),
    envelope        BYTEA NOT NULL CHECK (length(envelope) > 0),
    binding         BYTEA NOT NULL CHECK (length(binding) > 0),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, chain_id, seq),
    UNIQUE (tenant_id, receipt_id),
    UNIQUE (tenant_id, chain_id, prev_digest),
    UNIQUE (tenant_id, attempt_id, attempt_version),
    FOREIGN KEY (tenant_id, chain_id) REFERENCES authority_receipt_chains (tenant_id, chain_id),
    FOREIGN KEY (tenant_id, attempt_id) REFERENCES authority_effect_attempts (tenant_id, attempt_id),
    CHECK ((seq = 1) = (prev_digest = '')),
    CHECK (prev_digest = '' OR prev_digest ~ '^[0-9a-f]{64}$')
);

-- The ledger fence: a decision commits only with its receipt. Whenever an
-- attempt row enters ADMITTED, DENIED or ESCALATED, a receipt for exactly
-- that (tenant, attempt, version, state) must exist when the transaction
-- commits.
-- During an upgrade this migration runs while pods of the previous binary
-- still serve; their decisions carry no receipt and now fail at commit,
-- instead of leaving a decision the chain does not hold. Creating the
-- triggers waits for in-flight writes to commit, as migration 11 does.
-- The check is deferred so that recordDecision can write the row first and
-- append its receipt in the same transaction.
CREATE OR REPLACE FUNCTION authority_require_decision_receipt()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM authority_receipts
        WHERE tenant_id = NEW.tenant_id AND attempt_id = NEW.attempt_id AND attempt_version = NEW.version
          AND state = NEW.state
    ) THEN
        RAISE EXCEPTION 'decision_receipt_missing'
            USING ERRCODE = '23514',
                  DETAIL = format('attempt %s entered %s at version %s without its signed receipt',
                                  NEW.attempt_id, NEW.state, NEW.version);
    END IF;
    RETURN NULL;
END;
$$;

DROP TRIGGER IF EXISTS authority_decision_receipt_insert ON authority_effect_attempts;
CREATE CONSTRAINT TRIGGER authority_decision_receipt_insert
    AFTER INSERT ON authority_effect_attempts
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW WHEN (NEW.state IN ('ADMITTED', 'DENIED', 'ESCALATED'))
    EXECUTE FUNCTION authority_require_decision_receipt();

DROP TRIGGER IF EXISTS authority_decision_receipt_update ON authority_effect_attempts;
CREATE CONSTRAINT TRIGGER authority_decision_receipt_update
    AFTER UPDATE OF state ON authority_effect_attempts
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW WHEN (NEW.state IN ('ADMITTED', 'DENIED', 'ESCALATED') AND OLD.state IS DISTINCT FROM NEW.state)
    EXECUTE FUNCTION authority_require_decision_receipt();
