-- Tenant-wide receipt cursors need a durable append position because Lamport
-- clocks restart for every signed session. This is additive: receipt envelopes
-- and their signatures remain unchanged.
CREATE SEQUENCE IF NOT EXISTS receipts_append_sequence_seq AS BIGINT;

ALTER TABLE receipts ADD COLUMN IF NOT EXISTS append_sequence BIGINT;
ALTER TABLE receipts ALTER COLUMN append_sequence SET DEFAULT nextval('receipts_append_sequence_seq');
ALTER SEQUENCE receipts_append_sequence_seq OWNED BY receipts.append_sequence;

-- Historical rows have no durable insertion ordinal. Establish one stable
-- baseline with the old timestamp/receipt-id tie-breaker, then reserve higher
-- values for all later writes through the sequence default.
WITH missing AS (
    SELECT receipt_id,
        COALESCE((SELECT MAX(append_sequence) FROM receipts), 0)
            + ROW_NUMBER() OVER (ORDER BY timestamp ASC NULLS FIRST, receipt_id ASC) AS append_sequence
    FROM receipts
    WHERE COALESCE(append_sequence, 0) = 0
)
UPDATE receipts AS target
SET append_sequence = missing.append_sequence
FROM missing
WHERE target.receipt_id = missing.receipt_id;

SELECT setval(
    'receipts_append_sequence_seq',
    COALESCE((SELECT MAX(append_sequence) + 1 FROM receipts), 1),
    false
);

ALTER TABLE receipts ALTER COLUMN append_sequence SET NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_receipts_append_sequence_unique ON receipts(append_sequence);
