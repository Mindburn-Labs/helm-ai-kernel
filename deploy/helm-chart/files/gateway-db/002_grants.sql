-- helm-gateway runtime grants, version 1 (ADR-0004 §1; HELM-789).
--
-- Run by the chart's migrate hook after `helm-gateway migrate`, as the owner
-- role (SET ROLE through PGOPTIONS) with search_path on the gateway schema,
-- in one transaction. The caller sets helm_gateway_bootstrap.runtime_role and
-- helm_gateway_bootstrap.schema first (see 001_roles.sql).
--
-- The grants are the least privilege `helm-gateway serve` needs, the same set
-- the admission proofs run under (core/pkg/gateway/admission):
--
--   authority_* tables              SELECT, INSERT, UPDATE; no DELETE: a
--                                   revocation or cancellation is a state
--                                   transition
--   authority_postings              SELECT, INSERT (append-only ledger)
--   authority_distinct_values       SELECT, INSERT (INSERT ... ON CONFLICT
--                                   DO NOTHING and an EXISTS read only)
--   authority_token_replay          SELECT, INSERT, DELETE (expired
--                                   single-use token rows are purged; a row
--                                   is never updated). ADR-0004 amendment
--                                   of 2026-09-26.
--   gateway_schema_migrations       SELECT (/readyz compares the version)
--
--   River's tables (HELM-751 s3b; `helm-gateway migrate` creates them and
--   the job worker inside `serve` uses them):
--   river_job, river_leader,        SELECT, INSERT, UPDATE, DELETE
--   river_queue, river_notification
--   river_migration                 SELECT (/readyz checks River's version)
--   river_* sequences               USAGE (their bigserial ids)
--   The rules apply to the River tables that exist, so this file is right
--   before and after s3b's migration. A river_* table not named here fails
--   the run like any other table. The set is the one the job proofs'
--   fixture grants (core/pkg/gateway/jobs, RiverGrants).
--
--   Identity sequences (authority_postings, authority_observations) need no
--   grant: INSERT on the table covers them. Any other sequence fails the run.
--
-- No TRUNCATE, REFERENCES or TRIGGER anywhere, and nothing for PUBLIC. Every
-- run first revokes what the runtime role holds, so the result is exactly
-- this set; the transaction makes the swap atomic for live connections. A
-- table this file has no rule for fails the run instead of being left
-- ungranted or granted by guess.
DO $$
DECLARE
    runtime_role text := current_setting('helm_gateway_bootstrap.runtime_role');
    schema_name  text := current_setting('helm_gateway_bootstrap.schema');
    privileges   text;
    t            record;
BEGIN
    EXECUTE format('GRANT USAGE ON SCHEMA %I TO %I', schema_name, runtime_role);
    EXECUTE format('REVOKE ALL ON ALL TABLES IN SCHEMA %I FROM %I, PUBLIC', schema_name, runtime_role);
    EXECUTE format('REVOKE ALL ON ALL SEQUENCES IN SCHEMA %I FROM %I, PUBLIC', schema_name, runtime_role);
    FOR t IN
        SELECT c.relname
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = schema_name AND c.relkind IN ('r', 'p')
        ORDER BY c.relname
    LOOP
        privileges := CASE
            WHEN t.relname = 'gateway_schema_migrations' THEN 'SELECT'
            WHEN t.relname IN ('authority_postings', 'authority_distinct_values') THEN 'SELECT, INSERT'
            WHEN t.relname = 'authority_token_replay' THEN 'SELECT, INSERT, DELETE'
            WHEN t.relname LIKE 'authority\_%' THEN 'SELECT, INSERT, UPDATE'
            WHEN t.relname IN ('river_job', 'river_leader', 'river_queue', 'river_notification')
                THEN 'SELECT, INSERT, UPDATE, DELETE'
            WHEN t.relname = 'river_migration' THEN 'SELECT'
        END;
        IF privileges IS NULL THEN
            RAISE EXCEPTION 'table %.% has no helm_gateway grant rule; add one to 002_grants.sql', schema_name, t.relname;
        END IF;
        EXECUTE format('GRANT %s ON %I.%I TO %I', privileges, schema_name, t.relname, runtime_role);
    END LOOP;
    FOR t IN
        SELECT c.relname,
               EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = 'pg_class'::regclass AND d.objid = c.oid AND d.deptype = 'i') AS identity
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = schema_name AND c.relkind = 'S'
        ORDER BY c.relname
    LOOP
        IF t.identity THEN
            CONTINUE;
        ELSIF t.relname LIKE 'river\_%' THEN
            EXECUTE format('GRANT USAGE ON SEQUENCE %I.%I TO %I', schema_name, t.relname, runtime_role);
        ELSE
            RAISE EXCEPTION 'sequence %.% has no helm_gateway grant rule; add one to 002_grants.sql', schema_name, t.relname;
        END IF;
    END LOOP;
END
$$;
