package registry

import (
	"context"
	"database/sql"
	"errors"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/store"
)

// PostgresRegistry implements Registry with SQL persistence.
type PostgresRegistry struct {
	db *sql.DB
}

func NewPostgresRegistry(db *sql.DB) *PostgresRegistry {
	return &PostgresRegistry{db: db}
}

// MigratePostgres applies the registry schema as an explicit owner operation.
// Serving code should construct NewPostgresRegistry after migration.
func MigratePostgres(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return errors.New("postgres registry migration requires database")
	}
	return NewPostgresRegistry(db).Init(ctx)
}

const pgRegistrySchema = `
CREATE TABLE IF NOT EXISTS registry_bundles (
	name TEXT NOT NULL,
	version TEXT NOT NULL,
	bundle_json JSONB NOT NULL,
	created_at TIMESTAMP NOT NULL,
	PRIMARY KEY (name, version)
);

CREATE TABLE IF NOT EXISTS registry_rollouts (
	name TEXT PRIMARY KEY,
	canary_version TEXT,
	canary_bundle_json JSONB,
	percentage INT,
	updated_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS registry_installations (
	tenant_id TEXT NOT NULL,
	pack_id TEXT NOT NULL,
	installed_at TIMESTAMP NOT NULL,
	PRIMARY KEY (tenant_id, pack_id)
);
`

func (r *PostgresRegistry) Init(ctx context.Context) error {
	_, err := r.db.ExecContext(ctx, pgRegistrySchema+store.TenantRowSecurityDDL("registry_installations"))
	return err
}
