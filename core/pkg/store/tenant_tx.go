package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

// TenantRowSecurityPolicy is the row-security predicate every kernel tenant
// table carries, for USING and WITH CHECK alike. app.current_tenant is the one
// tenant setting the kernel's Postgres stores use; WithTenant sets it.
const TenantRowSecurityPolicy = "tenant_id = current_setting('app.current_tenant', true)"

// TenantRowSecurityDDL returns the statements that put table under forced row
// security with the tenant policy. FORCE makes the policy bind the table owner
// too, and an unset tenant setting is NULL, which matches no row.
func TenantRowSecurityDDL(table string) string {
	return `ALTER TABLE ` + table + ` ENABLE ROW LEVEL SECURITY;
ALTER TABLE ` + table + ` FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON ` + table + `;
CREATE POLICY tenant_isolation ON ` + table + `
	USING (` + TenantRowSecurityPolicy + `)
	WITH CHECK (` + TenantRowSecurityPolicy + `);`
}

// WithTenant checks out a connection, binds it to tenantID for one
// transaction (set_config(..., true) ends with the transaction), and runs fn.
// Forced row security then admits only that tenant's rows, so a query that
// omits its tenant predicate still cannot read or write another tenant.
func WithTenant(ctx context.Context, db *sql.DB, tenantID string, fn func(*sql.Tx) error) error {
	if db == nil {
		return errors.New("tenant-bound transaction requires a database")
	}
	if strings.TrimSpace(tenantID) == "" {
		return errors.New("tenant-bound transaction requires a tenant")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `SELECT set_config('app.current_tenant', $1, true)`, tenantID); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}
