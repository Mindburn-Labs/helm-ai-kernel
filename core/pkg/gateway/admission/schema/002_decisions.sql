-- Effect gateway decisions (HELM-751 s2b; ADR-0001 §1 "Approval", ADR-0005
-- §10). Forced row security on the new tables is applied by schema.go.

-- One decision per attempt (invariant I6): an approval or a rejection by a
-- verified human principal distinct from the requester. approval_digest is
-- the digest the approver presented, equal to the attempt's.
CREATE TABLE IF NOT EXISTS authority_approvals (
    tenant_id             TEXT NOT NULL,
    attempt_id            UUID NOT NULL,
    approver_principal_id TEXT NOT NULL,
    approver_actor_id     TEXT NOT NULL DEFAULT '',
    decision              TEXT NOT NULL CHECK (decision IN ('APPROVED', 'REJECTED')),
    approval_digest       BYTEA NOT NULL CHECK (length(approval_digest) = 32),
    reason                TEXT NOT NULL DEFAULT '' CHECK (octet_length(reason) <= 2000),
    decided_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, attempt_id),
    FOREIGN KEY (tenant_id, attempt_id) REFERENCES authority_effect_attempts (tenant_id, attempt_id),
    FOREIGN KEY (tenant_id, approver_principal_id) REFERENCES authority_principals (tenant_id, principal_id),
    CHECK (decision <> 'REJECTED' OR reason <> '')
);

-- Single-use decide and stop tokens (the proposed ADR-0005 §10 amendment).
-- Each accepted token's jti is recorded in the transaction of the operation
-- it authorizes; a second use is refused. Rows expire with the token (exp
-- plus the 30 s skew allowance) and are purged then. Process memory is never
-- the replay store (R5).
CREATE TABLE IF NOT EXISTS authority_token_replay (
    tenant_id  TEXT NOT NULL,
    issuer     TEXT NOT NULL,
    jti        TEXT NOT NULL CHECK (jti <> ''),
    scope      TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, issuer, jti)
);
CREATE INDEX IF NOT EXISTS authority_token_replay_expiry ON authority_token_replay (tenant_id, expires_at);

-- The distinct values a Propose carried, so Approve re-runs admission on the
-- same request (ADR-0001 §5.5).
ALTER TABLE authority_effect_attempts ADD COLUMN IF NOT EXISTS distinct_values JSONB NOT NULL DEFAULT '[]'
    CHECK (jsonb_typeof(distinct_values) = 'array');

-- A permit voided before dispatch (Cancel, or a refused claim in slice 3).
-- void_reason_code stays NULL for a Cancel, which has no registry code.
ALTER TABLE authority_permits ADD COLUMN IF NOT EXISTS voided_at TIMESTAMPTZ;
