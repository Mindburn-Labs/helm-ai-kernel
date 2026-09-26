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
--   authority_token_replay          SELECT, INSERT, UPDATE, DELETE (expired
--                                   single-use token rows are purged)
--   gateway_schema_migrations       SELECT (/readyz compares the version)
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
            WHEN t.relname = 'authority_postings' THEN 'SELECT, INSERT'
            WHEN t.relname = 'authority_token_replay' THEN 'SELECT, INSERT, UPDATE, DELETE'
            WHEN t.relname LIKE 'authority\_%' THEN 'SELECT, INSERT, UPDATE'
        END;
        IF privileges IS NULL THEN
            RAISE EXCEPTION 'table %.% has no helm_gateway grant rule; add one to 002_grants.sql', schema_name, t.relname;
        END IF;
        EXECUTE format('GRANT %s ON %I.%I TO %I', privileges, schema_name, t.relname, runtime_role);
    END LOOP;
END
$$;
