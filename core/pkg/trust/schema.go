package trust

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"
)

//go:embed migrations/001_initial_trust_schema.sql
var schemaSQL string

// InitSchema ensures the trust schema exists.
func InitSchema(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx, schemaSQL); err != nil {
		return fmt.Errorf("failed to exec trust schema: %w", err)
	}
	return nil
}
