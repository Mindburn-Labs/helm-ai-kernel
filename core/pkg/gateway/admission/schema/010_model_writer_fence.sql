-- A legacy model gateway derives its idempotency key from the forwarded body.
-- A newer gateway derives it from the original request so repricing can replay.
-- Both protocols must not admit a new attempt concurrently. The migration's
-- table lock waits for earlier inserts to commit before the new writer serves.
-- Old rows remain mutable so in-flight calls can finish and reconcile.
ALTER TABLE authority_effect_attempts
    ADD COLUMN IF NOT EXISTS model_writer_protocol SMALLINT NOT NULL DEFAULT 1;

CREATE OR REPLACE FUNCTION authority_fence_legacy_model_writer()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.effect_type = 'model.inference' AND NEW.model_writer_protocol < 2 THEN
        -- A pre-migration key may still replay through ON CONFLICT. A new
        -- legacy key cannot create a second identity after this migration.
        IF EXISTS (
            SELECT 1 FROM authority_effect_attempts
            WHERE tenant_id = NEW.tenant_id AND idempotency_key = NEW.idempotency_key
        ) THEN
            RETURN NEW;
        END IF;
        RAISE EXCEPTION 'legacy_model_writer_fenced'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS authority_fence_legacy_model_writer_insert ON authority_effect_attempts;
CREATE TRIGGER authority_fence_legacy_model_writer_insert
    BEFORE INSERT ON authority_effect_attempts
    FOR EACH ROW EXECUTE FUNCTION authority_fence_legacy_model_writer();
