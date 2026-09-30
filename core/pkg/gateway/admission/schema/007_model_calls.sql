-- Model-call settlement (HELM-752; ADR-0003 §1, target architecture §8).
--
-- A model call is an effect attempt of type model.inference. Its budget
-- exposure lives in authority_exposures like any other; this table is the
-- money side of the call, one row per claimed attempt, written in the
-- dispatch claim's transaction and moved only by the settlement transaction.
-- The four amounts are integer micro-units of currency_code and are never
-- summed (proto ModelCallSettlement).
--
-- state is the proto's SettlementState without its prefix:
--   HELD              the quote is held
--   ESTIMATED         the call's usage is not known; the hold counts as estimated
--   UNRESOLVED_FINAL  reserved for the resolution window (not written yet)
--   CONFIRMED         the provider reported usage; the remainder is released
--   RELEASED          the provider refused before generating; nothing consumed
--
-- billable_micros is min(confirmed, held) once confirmed and 0 before: an
-- overage (confirmed above held) is recorded in confirmed_micros and never
-- charged past the hold.
CREATE TABLE IF NOT EXISTS authority_model_calls (
    tenant_id        TEXT NOT NULL,
    attempt_id       UUID NOT NULL,
    route            TEXT NOT NULL CHECK (route <> ''),
    api              TEXT NOT NULL CHECK (api IN ('openai-responses', 'openai-chat', 'anthropic-messages')),
    currency_code    TEXT NOT NULL DEFAULT 'USD' CHECK (currency_code ~ '^[A-Z]{3}$'),
    state            TEXT NOT NULL CHECK (state IN ('HELD', 'ESTIMATED', 'UNRESOLVED_FINAL', 'CONFIRMED', 'RELEASED')),
    held_micros      BIGINT NOT NULL CHECK (held_micros >= 0),
    estimated_micros BIGINT CHECK (estimated_micros >= 0),
    confirmed_micros BIGINT CHECK (confirmed_micros >= 0),
    billable_micros  BIGINT NOT NULL DEFAULT 0 CHECK (billable_micros >= 0),
    -- The provider-reported usage as the response carried it, for evidence.
    usage            JSONB,
    version          BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, attempt_id),
    FOREIGN KEY (tenant_id, attempt_id) REFERENCES authority_effect_attempts (tenant_id, attempt_id),
    CHECK (billable_micros <= held_micros),
    CHECK (state <> 'CONFIRMED' OR confirmed_micros IS NOT NULL),
    CHECK (state NOT IN ('ESTIMATED', 'UNRESOLVED_FINAL') OR estimated_micros IS NOT NULL)
);

-- The response a settled call delivered, kept so that the same request in the
-- same episode replays it without a second provider call (R6). A separate row
-- from the call, so erasing content leaves the call and its digests: expiry
-- clears body and keeps body_sha256 (the gateway never DELETEs a row).
CREATE TABLE IF NOT EXISTS authority_model_replays (
    tenant_id   TEXT NOT NULL,
    attempt_id  UUID NOT NULL,
    status_code INTEGER NOT NULL CHECK (status_code BETWEEN 200 AND 299),
    headers     JSONB NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(headers) = 'object'),
    body        BYTEA,
    body_sha256 BYTEA NOT NULL CHECK (length(body_sha256) = 32),
    body_bytes  BIGINT NOT NULL CHECK (body_bytes >= 0),
    expires_at  TIMESTAMPTZ NOT NULL,
    purged_at   TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, attempt_id),
    FOREIGN KEY (tenant_id, attempt_id) REFERENCES authority_effect_attempts (tenant_id, attempt_id),
    CHECK ((body IS NULL) = (purged_at IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS authority_model_replays_expiry
    ON authority_model_replays (tenant_id, expires_at) WHERE body IS NOT NULL;
