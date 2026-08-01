-- HELM-303: durable semantic PDP decision hash for receipt.v5 projections.
-- The first V5 API writers also placed this value in metadata. Recover only
-- that already-durable value; a row without it is intentionally left empty so
-- runtime readers fail closed rather than export an incomplete V5 receipt.
ALTER TABLE receipts ADD COLUMN IF NOT EXISTS metadata JSONB;
ALTER TABLE receipts ADD COLUMN IF NOT EXISTS decision_hash TEXT NOT NULL DEFAULT '';

UPDATE receipts
SET decision_hash = metadata->>'decision_hash'
WHERE COALESCE(signature_version, '') = 'receipt.v5'
  AND COALESCE(decision_hash, '') = ''
  AND metadata IS NOT NULL
  AND NULLIF(metadata->>'decision_hash', '') IS NOT NULL;
