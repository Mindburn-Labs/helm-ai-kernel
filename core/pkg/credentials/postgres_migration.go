package credentials

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
)

// The credentials schema is source-owned by this package. The Kernel migration
// orchestrator invokes this function for the owner-only migration command;
// serving construction never calls it.
var (
	//go:embed migrations/001_create_credentials.sql
	postgresSchema []byte
)

// MigratePostgres applies the credentials and credential audit-log schema as
// an explicit owner operation.
func MigratePostgres(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return errors.New("postgres credentials migration requires database")
	}
	if _, err := db.ExecContext(ctx, string(postgresSchema)); err != nil {
		return fmt.Errorf("initialize postgres credentials schema: %w", err)
	}
	return nil
}
