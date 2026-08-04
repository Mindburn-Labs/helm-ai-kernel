-- Approval-ceremony baseline marker. The current source-owned bootstrap has
-- no migration ledger; this idempotent no-op preserves contiguous migration
-- identifiers until an external migration runner is introduced.
-- ponytail: no migration ledger; add one before independent deployment histories matter.
SELECT 1;
