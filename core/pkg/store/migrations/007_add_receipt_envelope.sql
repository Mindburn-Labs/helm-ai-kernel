-- Preserve the complete signed receipt envelope used to calculate chain_hash.
-- This migration intentionally does not fabricate historical envelopes: only
-- store initialization may backfill a projection after it exactly reproduces
-- its already-persisted chain_hash. Other legacy rows remain readable for
-- operations but unavailable for verified evidence/proof export.
ALTER TABLE receipts
	ADD COLUMN IF NOT EXISTS receipt_envelope JSONB;
