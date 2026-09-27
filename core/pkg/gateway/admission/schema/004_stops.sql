-- Effect gateway Stop (HELM-751 s3b; ADR-0001 §1 narrowing transitions).
--
-- A Stop through the gateway is idempotent on (tenant, idempotency_key) with
-- a request digest, like Propose (R6). Stops written by the authority-row
-- store before this carry no key.
ALTER TABLE authority_stops ADD COLUMN IF NOT EXISTS idempotency_key TEXT
    CHECK (idempotency_key IS NULL OR octet_length(idempotency_key) BETWEEN 1 AND 255);
ALTER TABLE authority_stops ADD COLUMN IF NOT EXISTS request_digest BYTEA
    CHECK (request_digest IS NULL OR length(request_digest) = 32);
CREATE UNIQUE INDEX IF NOT EXISTS authority_stops_idempotency
    ON authority_stops (tenant_id, idempotency_key) WHERE idempotency_key IS NOT NULL;
ALTER TABLE authority_stops DROP CONSTRAINT IF EXISTS authority_stops_idempotency_pair;
ALTER TABLE authority_stops ADD CONSTRAINT authority_stops_idempotency_pair
    CHECK ((idempotency_key IS NULL) = (request_digest IS NULL));
