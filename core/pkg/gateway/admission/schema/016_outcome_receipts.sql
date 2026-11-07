-- Signed outcome receipts (helm-tracker#276). The outcome of an admitted
-- effect is receipted like its decision: every write that moves an attempt
-- into OBSERVED, RECONCILED or SETTLED appends one signed receipt to the
-- workspace's chain of migration 15, in the outcome's own transaction, and
-- the fence below refuses an outcome that commits without one. Additive: the
-- tables, the decision fence and their row security are migration 15's.

-- A receipt now records a decision or an outcome. One receipt per attempt
-- version still holds: an outcome write bumps the version it describes.
ALTER TABLE authority_receipts DROP CONSTRAINT IF EXISTS authority_receipts_state_check;
ALTER TABLE authority_receipts ADD CONSTRAINT authority_receipts_state_check
    CHECK (state IN ('ADMITTED', 'DENIED', 'ESCALATED', 'OBSERVED', 'RECONCILED', 'SETTLED'));

-- The outcome fence: an outcome commits only with its receipt. Whenever an
-- attempt row enters OBSERVED, RECONCILED or SETTLED, or is written again at
-- a new version in one of them (a model call's late usage re-settles an
-- OBSERVED attempt), a receipt for exactly that (tenant, attempt, version,
-- state) must exist when the transaction commits.
-- During an upgrade this migration runs while pods of the previous binary
-- still serve; their outcomes carry no receipt and now fail at commit. The
-- attempt stays where it was (DISPATCHING, DISPATCHED or UNKNOWN) for the
-- reconciliation job a claim enqueues to settle with a receipt, or to hand to
-- a human. Creating the triggers waits for in-flight writes to commit.
-- The check is deferred so that an outcome write can update the row first and
-- append its receipt in the same transaction.
CREATE OR REPLACE FUNCTION authority_require_outcome_receipt()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM authority_receipts
        WHERE tenant_id = NEW.tenant_id AND attempt_id = NEW.attempt_id AND attempt_version = NEW.version
          AND state = NEW.state
    ) THEN
        RAISE EXCEPTION 'outcome_receipt_missing'
            USING ERRCODE = '23514',
                  DETAIL = format('attempt %s entered %s at version %s without its signed receipt',
                                  NEW.attempt_id, NEW.state, NEW.version);
    END IF;
    RETURN NULL;
END;
$$;

DROP TRIGGER IF EXISTS authority_outcome_receipt_insert ON authority_effect_attempts;
CREATE CONSTRAINT TRIGGER authority_outcome_receipt_insert
    AFTER INSERT ON authority_effect_attempts
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW WHEN (NEW.state IN ('OBSERVED', 'RECONCILED', 'SETTLED'))
    EXECUTE FUNCTION authority_require_outcome_receipt();

DROP TRIGGER IF EXISTS authority_outcome_receipt_update ON authority_effect_attempts;
CREATE CONSTRAINT TRIGGER authority_outcome_receipt_update
    AFTER UPDATE OF state, version ON authority_effect_attempts
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW WHEN (NEW.state IN ('OBSERVED', 'RECONCILED', 'SETTLED')
        AND (OLD.state IS DISTINCT FROM NEW.state OR OLD.version IS DISTINCT FROM NEW.version))
    EXECUTE FUNCTION authority_require_outcome_receipt();
