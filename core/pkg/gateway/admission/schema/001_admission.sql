-- Effect gateway admission (HELM-751 s2; ADR-0001 §1-§2, ADR-0003 §1).
--
-- Runs after the authority rows (mandates.SchemaDDL) in the same
-- migration step. Adapted like them to the kernel's conventions: an
-- `authority_` prefix, TEXT tenant and principal ids, and forced row security
-- on app.current_tenant, which schema.go applies to every table below.
--
-- `helm-gateway migrate` runs this file; `helm-gateway serve` never runs DDL.

-- A counter is one window bucket of a limit. Admission creates buckets on
-- demand and locks them FOR UPDATE in (limit_id, bucket_start) order.
-- reserved carries held exposure; used carries estimated and confirmed
-- exposure. No CHECK (used + reserved <= limit): admission enforces the limit
-- with a conditional update under the counter lock (ADR-0001 §5.6).
CREATE TABLE IF NOT EXISTS authority_counters (
    tenant_id    TEXT NOT NULL,
    limit_id     UUID NOT NULL,
    bucket_start TIMESTAMPTZ NOT NULL,
    used         BIGINT NOT NULL DEFAULT 0 CHECK (used >= 0),
    reserved     BIGINT NOT NULL DEFAULT 0 CHECK (reserved >= 0),
    PRIMARY KEY (tenant_id, limit_id, bucket_start),
    FOREIGN KEY (tenant_id, limit_id) REFERENCES authority_limits (tenant_id, limit_id)
);

-- The effect attempt (§4.3). request_digest is the idempotency comparison
-- (R6); state is the proto's EffectAttemptState without its prefix.
CREATE TABLE IF NOT EXISTS authority_effect_attempts (
    tenant_id              TEXT NOT NULL REFERENCES authority_tenants (tenant_id),
    attempt_id             UUID NOT NULL,
    workspace_id           TEXT NOT NULL CHECK (workspace_id <> ''),
    idempotency_key        TEXT NOT NULL CHECK (octet_length(idempotency_key) BETWEEN 1 AND 255),
    request_digest         BYTEA NOT NULL CHECK (length(request_digest) = 32),
    requester_principal_id TEXT NOT NULL CHECK (requester_principal_id <> ''),
    requester_actor_id     TEXT NOT NULL DEFAULT '',
    mandate_id             UUID,
    commitment_id          TEXT CHECK (commitment_id <> ''),
    case_id                TEXT CHECK (case_id <> ''),
    effect_type            TEXT NOT NULL CHECK (effect_type <> ''),
    target                 TEXT NOT NULL,
    target_digest          BYTEA NOT NULL CHECK (length(target_digest) = 32),
    argument_digest        BYTEA NOT NULL CHECK (length(argument_digest) = 32),
    risk_class             TEXT CHECK (risk_class IN ('low', 'medium', 'high', 'irreversible')),
    quote                  JSONB NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(quote) = 'array'),
    state                  TEXT NOT NULL CHECK (state IN (
                               'PROPOSED', 'DENIED', 'ESCALATED', 'APPROVED', 'REJECTED', 'EXPIRED',
                               'ADMITTED', 'CANCELLED', 'DISPATCHING', 'DISPATCHED', 'UNKNOWN',
                               'OBSERVED', 'RECONCILED', 'ESCALATED_TO_HUMAN', 'SETTLED', 'COMPENSATED')),
    reason_code            TEXT NOT NULL DEFAULT '',
    outcome                TEXT CHECK (outcome IN ('SUCCEEDED', 'FAILED')),
    outcome_basis          TEXT CHECK (outcome_basis IN ('OBSERVED', 'RECONCILED')),
    -- Set when the attempt escalates, and kept after the decision.
    approval_digest        BYTEA CHECK (length(approval_digest) = 32),
    approval_expires_at    TIMESTAMPTZ,
    version                BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, attempt_id),
    UNIQUE (tenant_id, idempotency_key),
    FOREIGN KEY (tenant_id, mandate_id) REFERENCES authority_mandates (tenant_id, mandate_id),
    CHECK (commitment_id IS NULL OR case_id IS NULL),
    CHECK ((approval_digest IS NULL) = (approval_expires_at IS NULL)),
    CHECK (state <> 'ESCALATED' OR approval_digest IS NOT NULL),
    CHECK ((outcome IS NULL) = (outcome_basis IS NULL))
);
CREATE INDEX IF NOT EXISTS authority_effect_attempts_by_update
    ON authority_effect_attempts (tenant_id, workspace_id, updated_at, attempt_id);

-- The exact argument bytes of an attempt (§5.6 content). A separate row, so
-- erasing content leaves the attempt and its digests.
CREATE TABLE IF NOT EXISTS authority_attempt_contents (
    tenant_id  TEXT NOT NULL,
    attempt_id UUID NOT NULL,
    arguments  BYTEA NOT NULL,
    PRIMARY KEY (tenant_id, attempt_id),
    FOREIGN KEY (tenant_id, attempt_id) REFERENCES authority_effect_attempts (tenant_id, attempt_id)
);

-- Distinct-value limits (rule class U): the uniqueness table plus the counter.
CREATE TABLE IF NOT EXISTS authority_distinct_values (
    tenant_id    TEXT NOT NULL,
    limit_id     UUID NOT NULL,
    bucket_start TIMESTAMPTZ NOT NULL,
    value_digest BYTEA NOT NULL CHECK (length(value_digest) = 32),
    attempt_id   UUID NOT NULL,
    PRIMARY KEY (tenant_id, limit_id, bucket_start, value_digest),
    FOREIGN KEY (tenant_id, limit_id, bucket_start) REFERENCES authority_counters (tenant_id, limit_id, bucket_start),
    FOREIGN KEY (tenant_id, attempt_id) REFERENCES authority_effect_attempts (tenant_id, attempt_id)
);

-- The single-use permit admission issues. authority_versions records the
-- version of every authority row admission locked; the dispatch claim
-- (slice 3) refuses the permit if any changed.
CREATE TABLE IF NOT EXISTS authority_permits (
    tenant_id          TEXT NOT NULL,
    permit_id          UUID NOT NULL,
    attempt_id         UUID NOT NULL,
    argument_digest    BYTEA NOT NULL CHECK (length(argument_digest) = 32),
    authority_versions JSONB NOT NULL CHECK (jsonb_typeof(authority_versions) = 'array'),
    expires_at         TIMESTAMPTZ NOT NULL,
    consumed_at        TIMESTAMPTZ,
    claim_id           UUID,
    void_reason_code   TEXT,
    PRIMARY KEY (tenant_id, permit_id),
    UNIQUE (tenant_id, attempt_id),
    FOREIGN KEY (tenant_id, attempt_id) REFERENCES authority_effect_attempts (tenant_id, attempt_id),
    CHECK ((consumed_at IS NULL) = (claim_id IS NULL)),
    CHECK (consumed_at IS NULL OR void_reason_code IS NULL)
);

-- Exactly one current exposure per (attempt, counter bucket). kind selects
-- the counter column that carries it: held -> reserved; estimated and
-- confirmed -> used; released -> neither (amount 0).
CREATE TABLE IF NOT EXISTS authority_exposures (
    tenant_id    TEXT NOT NULL,
    attempt_id   UUID NOT NULL,
    limit_id     UUID NOT NULL,
    bucket_start TIMESTAMPTZ NOT NULL,
    kind         TEXT NOT NULL CHECK (kind IN ('held', 'estimated', 'confirmed', 'released')),
    amount       BIGINT NOT NULL CHECK (amount >= 0),
    PRIMARY KEY (tenant_id, attempt_id, limit_id, bucket_start),
    FOREIGN KEY (tenant_id, attempt_id) REFERENCES authority_effect_attempts (tenant_id, attempt_id),
    FOREIGN KEY (tenant_id, limit_id, bucket_start) REFERENCES authority_counters (tenant_id, limit_id, bucket_start),
    CHECK (kind <> 'released' OR amount = 0)
);

-- Append-only: every exposure change is a pair of postings (reverse the old,
-- post the new). The gateway never updates or deletes a posting.
CREATE TABLE IF NOT EXISTS authority_postings (
    tenant_id    TEXT NOT NULL,
    posting_id   BIGINT GENERATED ALWAYS AS IDENTITY,
    attempt_id   UUID NOT NULL,
    limit_id     UUID NOT NULL,
    bucket_start TIMESTAMPTZ NOT NULL,
    kind         TEXT NOT NULL CHECK (kind IN ('held', 'estimated', 'confirmed')),
    amount       BIGINT NOT NULL,
    cause        TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, posting_id),
    FOREIGN KEY (tenant_id, attempt_id, limit_id, bucket_start)
        REFERENCES authority_exposures (tenant_id, attempt_id, limit_id, bucket_start)
);

-- Observations of an effect's outcome (§3, §4.1 item 4). Slice 3 (Dispatch
-- and Observe) writes them; admission reads them for preconditions such as
-- the draft pull request's branch attempt. result is the typed result
-- (result_kind names the Observation.result member), as JSON.
CREATE TABLE IF NOT EXISTS authority_observations (
    tenant_id       TEXT NOT NULL,
    observation_id  BIGINT GENERATED ALWAYS AS IDENTITY,
    attempt_id      UUID NOT NULL,
    source          TEXT NOT NULL,
    trust_class     TEXT NOT NULL,
    outcome         TEXT CHECK (outcome IN ('SUCCEEDED', 'FAILED')),
    evidence_digest BYTEA CHECK (length(evidence_digest) = 32),
    observed_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    result_ref      TEXT NOT NULL DEFAULT '',
    result_kind     TEXT NOT NULL DEFAULT '',
    result          JSONB,
    PRIMARY KEY (tenant_id, observation_id),
    FOREIGN KEY (tenant_id, attempt_id) REFERENCES authority_effect_attempts (tenant_id, attempt_id)
);
CREATE INDEX IF NOT EXISTS authority_observations_by_attempt
    ON authority_observations (tenant_id, attempt_id, observation_id);
