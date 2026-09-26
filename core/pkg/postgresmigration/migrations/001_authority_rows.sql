-- Authority rows (HELM-750 s2a; ADR-0001 §2, architecture §3 and §4.1).
--
-- Tenants, principals, effect types, mandates, limits and stops as typed rows.
-- Every row a decision depends on carries `version`. A narrowing transition
-- (stop, revoke, narrow, lower or add a limit) is an UPDATE of its scope's
-- control row that bumps `version`, in the same transaction as its detail row
-- (ADR-0001 §5.1). Admission (HELM-751) takes FOR SHARE on these rows, so a
-- narrowing either commits before admission locks them or waits for it.
--
-- Adapted to the kernel: the tables live in the kernel's schema with an
-- `authority_` prefix, tenant and principal ids are the kernel's text ids, and
-- row security uses app.current_tenant. postgresmigration applies forced row
-- security with the tenant policy to every table below after this file.
--
-- Serving code never runs this file; `helm-ai-kernel migrate` does.

CREATE TABLE IF NOT EXISTS authority_tenants (
    tenant_id  TEXT PRIMARY KEY CHECK (tenant_id <> ''),
    version    BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS authority_principals (
    tenant_id    TEXT NOT NULL REFERENCES authority_tenants (tenant_id),
    principal_id TEXT NOT NULL CHECK (principal_id <> ''),
    kind         TEXT NOT NULL CHECK (kind IN ('human', 'agent', 'service')),
    status       TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    version      BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    PRIMARY KEY (tenant_id, principal_id)
);

-- The effect-type control row exists before any mandate names the type.
CREATE TABLE IF NOT EXISTS authority_effect_types (
    tenant_id   TEXT NOT NULL REFERENCES authority_tenants (tenant_id),
    effect_type TEXT NOT NULL CHECK (effect_type ~ '^[a-z][a-z0-9_.-]{0,127}$'),
    risk_class  TEXT NOT NULL CHECK (risk_class IN ('low', 'medium', 'high', 'irreversible')),
    version     BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    PRIMARY KEY (tenant_id, effect_type)
);

-- A mandate is typed data: scope (effect_types), per-call limit, approval rule
-- (approval_threshold), validity window, and the parent it was delegated from.
-- Amounts are integer minor units. A NULL per_call_limit or approval_threshold
-- means the mandate sets none. A call whose amount is at least
-- approval_threshold needs approval (0 means every call).
--
-- Delegation only narrows: a child's terms are within every ancestor's, checked
-- when it is created (and again at admission, HELM-751). A root mandate widens
-- authority, so it records the principal that approved it, who is neither its
-- requester (created_by) nor its holder.
CREATE TABLE IF NOT EXISTS authority_mandates (
    tenant_id          TEXT NOT NULL,
    mandate_id         UUID NOT NULL,
    holder_id          TEXT NOT NULL,
    parent_id          UUID,
    depth              INTEGER NOT NULL CHECK (depth >= 0),
    effect_types       TEXT[] NOT NULL CHECK (cardinality(effect_types) > 0),
    per_call_limit     BIGINT CHECK (per_call_limit >= 0),
    approval_threshold BIGINT CHECK (approval_threshold >= 0),
    valid_from         TIMESTAMPTZ NOT NULL,
    valid_until        TIMESTAMPTZ NOT NULL,
    status             TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    created_by         TEXT NOT NULL,
    approved_by        TEXT,
    version            BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, mandate_id),
    FOREIGN KEY (tenant_id, holder_id) REFERENCES authority_principals (tenant_id, principal_id),
    FOREIGN KEY (tenant_id, created_by) REFERENCES authority_principals (tenant_id, principal_id),
    FOREIGN KEY (tenant_id, approved_by) REFERENCES authority_principals (tenant_id, principal_id),
    FOREIGN KEY (tenant_id, parent_id) REFERENCES authority_mandates (tenant_id, mandate_id),
    CHECK (valid_until > valid_from),
    CHECK ((parent_id IS NULL) = (depth = 0)),
    CHECK ((parent_id IS NULL) = (approved_by IS NOT NULL)),
    CHECK (approved_by IS NULL OR (approved_by <> created_by AND approved_by <> holder_id))
);

-- A limit is an authority row: admission locks it FOR SHARE, and lowering it
-- bumps its version. A NULL mandate_id is a tenant-level resource account.
-- Counters (one row per window bucket) arrive with the admission transaction.
CREATE TABLE IF NOT EXISTS authority_limits (
    tenant_id   TEXT NOT NULL REFERENCES authority_tenants (tenant_id),
    limit_id    UUID NOT NULL,
    mandate_id  UUID,
    unit        TEXT NOT NULL CHECK (unit ~ '^[a-z][a-z0-9_]{0,31}$'),
    measure     TEXT NOT NULL CHECK (measure IN ('sum', 'count', 'distinct')),
    window_kind TEXT NOT NULL CHECK (window_kind IN ('none', 'hour', 'day', 'month')),
    limit_value BIGINT NOT NULL CHECK (limit_value >= 0),
    span        INTEGER NOT NULL DEFAULT 1 CHECK (span BETWEEN 1 AND 744),
    version     BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    PRIMARY KEY (tenant_id, limit_id),
    FOREIGN KEY (tenant_id, mandate_id) REFERENCES authority_mandates (tenant_id, mandate_id),
    CHECK (window_kind <> 'none' OR span = 1),
    CHECK (measure <> 'distinct' OR span = 1)
);

-- The one stop mechanism (R4). A stop row is written in the transaction that
-- bumps the version of its scope's control row. A stop is active until it
-- expires or is lifted. Lifting widens authority, so a lift records who asked
-- for it and the distinct principal who approved it.
CREATE TABLE IF NOT EXISTS authority_stops (
    tenant_id         TEXT NOT NULL REFERENCES authority_tenants (tenant_id),
    stop_id           UUID NOT NULL,
    scope_kind        TEXT NOT NULL CHECK (scope_kind IN ('tenant', 'principal', 'mandate', 'effect_type')),
    scope_key         TEXT NOT NULL CHECK (scope_key <> ''),
    reason            TEXT NOT NULL CHECK (length(reason) BETWEEN 1 AND 1024),
    issued_by         TEXT NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at        TIMESTAMPTZ,
    lifted_at         TIMESTAMPTZ,
    lift_requested_by TEXT,
    lift_approved_by  TEXT,
    PRIMARY KEY (tenant_id, stop_id),
    FOREIGN KEY (tenant_id, issued_by) REFERENCES authority_principals (tenant_id, principal_id),
    FOREIGN KEY (tenant_id, lift_requested_by) REFERENCES authority_principals (tenant_id, principal_id),
    FOREIGN KEY (tenant_id, lift_approved_by) REFERENCES authority_principals (tenant_id, principal_id),
    CHECK (expires_at IS NULL OR expires_at > created_at),
    CHECK ((lifted_at IS NULL) = (lift_requested_by IS NULL)),
    CHECK ((lifted_at IS NULL) = (lift_approved_by IS NULL)),
    CHECK (lift_approved_by IS NULL OR lift_approved_by <> lift_requested_by)
);

CREATE INDEX IF NOT EXISTS authority_stops_active
    ON authority_stops (tenant_id, scope_kind, scope_key) WHERE lifted_at IS NULL;
