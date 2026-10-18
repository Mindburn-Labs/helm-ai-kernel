package activitytrail

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/store/tenantrls"
)

//go:embed schema/*.sql
var schemaFiles embed.FS

// Tables are tenant tables. The gateway runtime role needs SELECT, INSERT,
// UPDATE on them; it does not need DELETE or access to the schema journal.
var Tables = []string{"gateway_activity_sources", "gateway_activity_observations", "gateway_activity_evidence"}

// Migrate is a self-contained migration entry point. The gateway migration
// command must call it after admission.Migrate, as these tables reference
// authority_tenants. Serving requests never runs DDL.
func Migrate(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return errors.New("activity trail migration requires a database")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(7510052)`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS gateway_activity_schema_migrations (
		version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())`); err != nil {
		return err
	}
	var version int
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM gateway_activity_schema_migrations`).Scan(&version); err != nil {
		return err
	}
	if version > 1 {
		return fmt.Errorf("activity trail database schema %d is newer than this binary", version)
	}
	if version == 1 {
		return tx.Commit()
	}
	ddl, err := schemaFiles.ReadFile("schema/001_activity.sql")
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, string(ddl)); err != nil {
		return fmt.Errorf("activity trail schema: %w", err)
	}
	for _, table := range Tables {
		if _, err := tx.ExecContext(ctx, tenantrls.DDL(table)); err != nil {
			return fmt.Errorf("activity trail RLS on %s: %w", table, err)
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO gateway_activity_schema_migrations (version,name) VALUES (1,'default-branch observations')`); err != nil {
		return err
	}
	return tx.Commit()
}

// Ready checks the activity journal without performing DDL. The runtime role
// only needs SELECT on this journal.
func Ready(ctx context.Context, db *sql.DB) error {
	var version int
	if err := db.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM gateway_activity_schema_migrations`).Scan(&version); err != nil {
		return err
	}
	if version != 1 {
		return fmt.Errorf("activity trail schema at version %d, want 1", version)
	}
	return nil
}
