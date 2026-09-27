-- helm-gateway database roles, version 1 (ADR-0004 §1; HELM-789).
--
-- Run by the chart's migrate hook (gateway.database.bootstrap.enabled) as a
-- database administrator: a superuser, or a role with CREATEROLE that owns
-- the gateway database. It runs before `helm-gateway migrate`, in one
-- transaction. The caller sets these session settings first:
--
--   helm_gateway_bootstrap.owner_role    helm_owner: NOLOGIN, owns the schema
--                                        and every table; migrations SET ROLE
--                                        to it
--   helm_gateway_bootstrap.runtime_role  helm_gateway: LOGIN, the serving
--                                        role, DML grants only (002_grants.sql)
--   helm_gateway_bootstrap.schema        the gateway schema, owned by the owner
--   helm_gateway_bootstrap.runtime_verifier
--                                        optional: the runtime role's password
--                                        as a SCRAM-SHA-256 verifier computed
--                                        client-side (helm-gateway db
--                                        scram-verifier); a plaintext value is
--                                        refused, so no password reaches the
--                                        server or its statement log
--
-- The gateway database shares its PostgreSQL instance with the Control
-- Plane's (QA, pilot production), so the database itself is closed: PUBLIC
-- loses CONNECT and TEMPORARY on it and only the runtime role gets CONNECT.
-- The owner role is NOLOGIN and never connects; the administrator must own
-- the database or be a superuser. Closing the instance's other databases to
-- PUBLIC is the operator's job; this file warns about each one the runtime
-- role can still connect to.
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
    verifier     text := coalesce(current_setting('helm_gateway_bootstrap.runtime_verifier', true), '');
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

    IF verifier <> '' THEN
        IF verifier !~ '^SCRAM-SHA-256\$[0-9]+:[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+$' THEN
            RAISE EXCEPTION 'helm_gateway_bootstrap.runtime_verifier must be a SCRAM-SHA-256 verifier, never a plaintext password';
        END IF;
        EXECUTE format('ALTER ROLE %I PASSWORD %L', runtime_role, verifier);
    END IF;

    -- Database isolation.
    IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname = current_user)
       AND NOT pg_has_role(current_user, (SELECT datdba FROM pg_database WHERE datname = current_database()), 'MEMBER') THEN
        RAISE EXCEPTION 'the administrator % must own database % (or be a superuser) to close it to PUBLIC', current_user, current_database();
    END IF;
    EXECUTE format('REVOKE CONNECT, TEMPORARY ON DATABASE %I FROM PUBLIC', current_database());
    EXECUTE format('GRANT CONNECT ON DATABASE %I TO %I', current_database(), runtime_role);
    FOR r IN
        SELECT datname FROM pg_database
        WHERE datallowconn AND NOT datistemplate AND datname <> current_database() AND has_database_privilege(runtime_role, oid, 'CONNECT')
        ORDER BY datname
    LOOP
        RAISE WARNING 'role % can connect to database % (through PUBLIC or a grant); revoke CONNECT there unless it needs it', runtime_role, r.datname;
    END LOOP;
END
$$;
