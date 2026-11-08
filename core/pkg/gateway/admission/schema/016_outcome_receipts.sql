-- Signed outcome receipts (helm-tracker#276). The outcome of an admitted
-- effect is receipted like its decision: every write that moves an attempt
-- into OBSERVED, RECONCILED or SETTLED appends one signed receipt to the
-- workspace's chain of migration 15, in the outcome's own transaction, and
-- the fence below refuses an outcome that commits without one. Additive: the
-- tables, the decision fence and their row security are migration 15's.

-- Lock order. During a rolling upgrade this migration runs while pods of the
-- previous binary still serve. Each of their decisions writes its attempt row
-- and then inserts its receipt, in that order and in one transaction. The
-- ALTER below takes ACCESS EXCLUSIVE on authority_receipts and the trigger DDL
-- takes SHARE ROW EXCLUSIVE on authority_effect_attempts; taking them the
-- other way round (receipts first) can deadlock against such a decision,
-- which holds the attempt row and waits for the receipt table. So the
-- attempts lock comes first: it waits for in-flight attempt writers to commit
-- (with their receipts) and queues new ones before they reach
-- authority_receipts. Readers of authority_receipts still finish first; a
-- transaction that reads receipts and then writes an attempt can still meet
-- this migration in a cycle, which PostgreSQL's deadlock detector breaks by
-- aborting one side (a failed migration records nothing and runs again).
LOCK TABLE authority_effect_attempts IN SHARE ROW EXCLUSIVE MODE;

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
-- An older gateway's outcomes carry no receipt and fail at commit after this
-- migration. The attempt stays where it was (DISPATCHING, DISPATCHED or
-- UNKNOWN) for the reconciliation job a claim enqueues to settle with a
-- receipt, or to hand to a human.
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

-- Both fences resolve authority_receipts by name. Pin their search_path to
-- the schema that holds the table migration 15 created (read from pg_class,
-- not assumed from this connection's search_path), and put pg_temp last: a
-- look-alike authority_receipts in the writer's own search_path, or a
-- temporary table the writer creates, cannot satisfy either fence. This also
-- pins migration 15's decision fence.
DO $pin$
DECLARE
    receipts_schema TEXT;
BEGIN
    SELECT n.nspname INTO STRICT receipts_schema
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE c.oid = 'authority_receipts'::regclass;
    EXECUTE format('ALTER FUNCTION authority_require_decision_receipt() SET search_path = %I, pg_temp', receipts_schema);
    EXECUTE format('ALTER FUNCTION authority_require_outcome_receipt() SET search_path = %I, pg_temp', receipts_schema);
END
$pin$;

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
