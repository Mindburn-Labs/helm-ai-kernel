-- HELM-303: durable fields for the active receipt.v5 signing envelope.
-- These values are cryptographically bound, so they must survive every
-- store/reload path before a signed receipt can be independently verified.
ALTER TABLE receipts ADD COLUMN IF NOT EXISTS signature_version TEXT DEFAULT '';
ALTER TABLE receipts ADD COLUMN IF NOT EXISTS verdict TEXT DEFAULT '';
ALTER TABLE receipts ADD COLUMN IF NOT EXISTS reason_code TEXT DEFAULT '';
ALTER TABLE receipts ADD COLUMN IF NOT EXISTS policy_hash TEXT DEFAULT '';
ALTER TABLE receipts ADD COLUMN IF NOT EXISTS session_id TEXT DEFAULT '';
DROP INDEX IF EXISTS idx_receipts_executor_lamport_unique;
CREATE UNIQUE INDEX IF NOT EXISTS idx_receipts_session_lamport_unique ON receipts(session_id, lamport_clock)
    WHERE session_id IS NOT NULL AND session_id <> '' AND lamport_clock > 0;
CREATE INDEX IF NOT EXISTS idx_receipts_session_lamport_desc ON receipts(session_id, lamport_clock DESC);
