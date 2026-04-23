CREATE TABLE IF NOT EXISTS trust_metadata (
    role_name TEXT PRIMARY KEY,
    json_data JSONB NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS trust_versions (
    pack_id TEXT PRIMARY KEY,
    version TEXT NOT NULL,
    installed_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS trust_key_status (
    key_id TEXT PRIMARY KEY,
    status TEXT NOT NULL, -- ACTIVE, REVOKED, EXPIRED
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS trust_quarantine_overrides (
    key_id TEXT PRIMARY KEY,
    reason TEXT NOT NULL,
    authorized_by TEXT[],
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    signatures TEXT[],
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
