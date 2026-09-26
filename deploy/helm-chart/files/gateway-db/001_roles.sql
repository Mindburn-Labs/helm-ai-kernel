-- helm-gateway database roles, version 1 (ADR-0004 §1; HELM-789).
--
-- Run by the chart's migrate hook (gateway.database.bootstrap.enabled) as a
-- database administrator: a superuser, or a role with CREATEROLE and CREATE
-- on the database. It runs before `helm-gateway migrate`, in one transaction.
-- The caller sets three session settings first:
--
--   helm_gateway_bootstrap.owner_role    helm_owner: NOLOGIN, owns the schema
--                                        and every table; migrations SET ROLE
--                                        to it
--   helm_gateway_bootstrap.runtime_role  helm_gateway: LOGIN, the serving
--                                        role, DML grants only (002_grants.sql)
--   helm_gateway_bootstrap.schema        the gateway schema, owned by the owner
--
-- Idempotent, and converging: a role that already exists with an escalation
-- attribute is altered back, so a second run leaves the catalog as the first
-- did. Neither role gets SUPERUSER, BYPASSRLS, CREATEROLE, CREATEDB or
-- REPLICATION.
DO $$
DECLARE
    owner_role   text := current_setting('helm_gateway_bootstrap.owner_role');
    runtime_role text := current_setting('helm_gateway_bootstrap.runtime_role');
    schema_name  text := current_setting('helm_gateway_bootstrap.schema');
    set_mode     text := CASE WHEN current_setting('server_version_num')::int >= 160000 THEN 'SET' ELSE 'MEMBER' END;
    schema_owner text;
    r            record;
    fix          text;
BEGIN
    IF owner_role = '' OR runtime_role = '' OR schema_name = '' OR owner_role = runtime_role THEN
        RAISE EXCEPTION 'helm_gateway_bootstrap.owner_role, runtime_role and schema must be set, and the two roles must differ';
    END IF;

    SELECT * INTO r FROM pg_roles WHERE rolname = owner_role;
    IF NOT FOUND THEN
        EXECUTE format('CREATE ROLE %I NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION', owner_role);
    ELSE
        -- Name only the attributes that drifted: a CREATEROLE administrator
        -- may not name BYPASSRLS or REPLICATION at all unless it holds them.
        fix := concat_ws(' ', CASE WHEN r.rolcanlogin THEN 'NOLOGIN' END, CASE WHEN r.rolsuper THEN 'NOSUPERUSER' END,
            CASE WHEN r.rolbypassrls THEN 'NOBYPASSRLS' END, CASE WHEN r.rolcreaterole THEN 'NOCREATEROLE' END,
            CASE WHEN r.rolcreatedb THEN 'NOCREATEDB' END, CASE WHEN r.rolreplication THEN 'NOREPLICATION' END);
        IF fix <> '' THEN
            EXECUTE format('ALTER ROLE %I %s', owner_role, fix);
        END IF;
    END IF;

    SELECT * INTO r FROM pg_roles WHERE rolname = runtime_role;
    IF NOT FOUND THEN
        EXECUTE format('CREATE ROLE %I LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION', runtime_role);
    ELSE
        fix := concat_ws(' ', CASE WHEN NOT r.rolcanlogin THEN 'LOGIN' END, CASE WHEN r.rolsuper THEN 'NOSUPERUSER' END,
            CASE WHEN r.rolbypassrls THEN 'NOBYPASSRLS' END, CASE WHEN r.rolcreaterole THEN 'NOCREATEROLE' END,
            CASE WHEN r.rolcreatedb THEN 'NOCREATEDB' END, CASE WHEN r.rolreplication THEN 'NOREPLICATION' END);
        IF fix <> '' THEN
            EXECUTE format('ALTER ROLE %I %s', runtime_role, fix);
        END IF;
    END IF;

    -- The runtime role must never act as the owner: an owner can turn row
    -- security off.
    IF pg_has_role(runtime_role, owner_role, 'MEMBER') THEN
        RAISE EXCEPTION 'role % is a member of %; the serving role must not be able to act as the owner', runtime_role, owner_role;
    END IF;

    -- The administrator runs the migrations as the owner (SET ROLE, through
    -- PGOPTIONS), so it needs membership with SET; a superuser has it already.
    IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname = current_user)
       AND NOT pg_has_role(current_user, owner_role, set_mode) THEN
        EXECUTE format('GRANT %I TO %I', owner_role, current_user);
    END IF;

    SELECT pg_get_userbyid(nspowner) INTO schema_owner FROM pg_namespace WHERE nspname = schema_name;
    IF schema_owner IS NULL THEN
        EXECUTE format('CREATE SCHEMA %I AUTHORIZATION %I', schema_name, owner_role);
    ELSIF schema_owner <> owner_role THEN
        RAISE EXCEPTION 'schema % exists and is owned by %, not %; refusing to take it over', schema_name, schema_owner, owner_role;
    END IF;
    EXECUTE format('REVOKE ALL ON SCHEMA %I FROM PUBLIC', schema_name);

    -- The serving role resolves the gateway's unqualified table names here.
    EXECUTE format('ALTER ROLE %I IN DATABASE %I SET search_path = %I', runtime_role, current_database(), schema_name);
END
$$;
