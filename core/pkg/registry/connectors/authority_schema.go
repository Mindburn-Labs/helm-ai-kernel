package connectors

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
)

//go:embed migrations/001_connector_release_authorities.sql
var connectorReleaseAuthoritySchemaSQL string

// ApplyConnectorReleaseAuthorityMigrations is an owner/migration operation.
// Runtime processes must receive a database role without DDL privileges and
// must never call this function during startup.
func ApplyConnectorReleaseAuthorityMigrations(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return errors.New("connector release authority migration requires database")
	}
	if _, err := db.ExecContext(ctx, connectorReleaseAuthoritySchemaSQL); err != nil {
		return fmt.Errorf("apply connector release authority migration: %w", err)
	}
	return nil
}
