-- MIN-720: persist Receipt Transparency Log (RFC 6962) anchoring metadata.
-- anchorReceiptTransparency records the leaf identity on the receipt at
-- issuance; without these columns the LogID/LeafIndex/Transparency fields were
-- silently dropped and the HELM_TRANSPARENCY_DEGRADE "backfill later" deferral
-- promise was unbacked.

ALTER TABLE receipts ADD COLUMN IF NOT EXISTS log_id TEXT DEFAULT '';
ALTER TABLE receipts ADD COLUMN IF NOT EXISTS leaf_index BIGINT DEFAULT 0;
ALTER TABLE receipts ADD COLUMN IF NOT EXISTS transparency JSONB;
