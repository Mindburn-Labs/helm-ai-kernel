-- HELM-303: durable fields for the active receipt.v5 signing envelope.
-- These values are cryptographically bound, so they must survive every
-- store/reload path before a signed receipt can be independently verified.
-- Irreversible migration: replaces obsolete receipt indexes in place; no down migration is supplied.
ALTER TABLE receipts ADD COLUMN IF NOT EXISTS signature_version TEXT DEFAULT '';
ALTER TABLE receipts ADD COLUMN IF NOT EXISTS verdict TEXT DEFAULT '';
ALTER TABLE receipts ADD COLUMN IF NOT EXISTS reason_code TEXT DEFAULT '';
ALTER TABLE receipts ADD COLUMN IF NOT EXISTS policy_hash TEXT DEFAULT '';
ALTER TABLE receipts ADD COLUMN IF NOT EXISTS session_id TEXT DEFAULT '';
ALTER TABLE receipts ADD COLUMN IF NOT EXISTS causal_session_id TEXT DEFAULT '';
-- Keep the database lookup key separate from the historical receipt envelope:
-- legacy chain identity was executor_id, while receipt.v5 signs session_id.
UPDATE receipts
SET causal_session_id = CASE
    WHEN COALESCE(signature_version, '') = 'receipt.v5' THEN COALESCE(session_id, '')
    ELSE COALESCE(executor_id, '')
END
WHERE COALESCE(causal_session_id, '') = '';
DROP INDEX IF EXISTS idx_receipts_executor_lamport_unique;
DROP INDEX IF EXISTS idx_receipts_session_lamport_unique;
DROP INDEX IF EXISTS idx_receipts_session_lamport_desc;
CREATE UNIQUE INDEX IF NOT EXISTS idx_receipts_causal_session_lamport_unique ON receipts(causal_session_id, lamport_clock)
    WHERE causal_session_id IS NOT NULL AND causal_session_id <> '' AND lamport_clock > 0;
CREATE INDEX IF NOT EXISTS idx_receipts_causal_session_lamport_desc ON receipts(causal_session_id, lamport_clock DESC);
