package admission

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/authority/mandates"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/store/tenantrls"
)

//go:embed schema/*.sql
var schemaFiles embed.FS

// Tables are the gateway's own tables, each under forced row security with
// the kernel's tenant policy. The authority rows (mandates.Tables) are
// migrated in the same step.
var Tables = []string{
	"authority_counters",
	"authority_effect_attempts",
	"authority_attempt_contents",
	"authority_distinct_values",
	"authority_permits",
	"authority_exposures",
	"authority_postings",
	"authority_observations",
}

// migration is one version of the gateway schema.
type migration struct {
	version int
	name    string
	ddl     func() (string, error)
}

var migrations = []migration{
	{1, "authority rows and admission", func() (string, error) {
		return withRowSecurity(mandates.SchemaDDL(), "schema/001_admission.sql", Tables)
	}},
}

// HeadVersion is the schema version this binary serves.
func HeadVersion() int { return migrations[len(migrations)-1].version }

func withRowSecurity(prefix, file string, tables []string) (string, error) {
	body, err := schemaFiles.ReadFile(file)
	if err != nil {
		return "", err
	}
	var ddl strings.Builder
	ddl.WriteString(prefix)
	ddl.WriteString("\n")
	ddl.Write(body)
	for _, table := range tables {
		ddl.WriteString("\n")
		ddl.WriteString(tenantrls.DDL(table))
	}
	return ddl.String(), nil
}

const journalDDL = `CREATE TABLE IF NOT EXISTS gateway_schema_migrations (
	version    INTEGER PRIMARY KEY,
	name       TEXT NOT NULL,
	applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
)`

// Migrate applies every migration the database has not recorded, each in one
// transaction with its journal row, serialized across concurrent migrators by
// an advisory lock. It refuses a database newer than this binary.
func Migrate(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return errors.New("gateway migration requires a database")
	}
	if _, err := db.ExecContext(ctx, journalDDL); err != nil {
		return fmt.Errorf("create gateway migration journal: %w", err)
	}
	for _, m := range migrations {
		if err := apply(ctx, db, m); err != nil {
			return fmt.Errorf("gateway migration %d (%s): %w", m.version, m.name, err)
		}
	}
	return nil
}

func apply(ctx context.Context, db *sql.DB, m migration) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	// One migrator at a time: the key is arbitrary but fixed.
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(7510002)`); err != nil {
		return err
	}
	var latest int
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM gateway_schema_migrations`).Scan(&latest); err != nil {
		return err
	}
	if latest > HeadVersion() {
		return fmt.Errorf("database is at gateway schema version %d, newer than this binary's %d; refusing to migrate", latest, HeadVersion())
	}
	if latest >= m.version {
		return nil
	}
	ddl, err := m.ddl()
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, ddl); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO gateway_schema_migrations (version, name) VALUES ($1, $2)`, m.version, m.name); err != nil {
		return err
	}
	return tx.Commit()
}

// SchemaVersion returns the newest version the database records, 0 when the
// journal does not exist.
func SchemaVersion(ctx context.Context, db *sql.DB) (int, error) {
	var exists bool
	if err := db.QueryRowContext(ctx, `SELECT to_regclass('gateway_schema_migrations') IS NOT NULL`).Scan(&exists); err != nil {
		return 0, err
	}
	if !exists {
		return 0, nil
	}
	var version int
	err := db.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM gateway_schema_migrations`).Scan(&version)
	return version, err
}
