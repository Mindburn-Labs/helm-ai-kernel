package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/store/tenantrls"
)

// TenantRowSecurityPolicy is the row-security predicate every kernel tenant
// table carries (tenantrls.Policy). WithTenant sets app.current_tenant.
const TenantRowSecurityPolicy = tenantrls.Policy

// TenantRowSecurityPolicyExpr is how Postgres deparses TenantRowSecurityPolicy
// on a TEXT tenant_id (tenantrls.PolicyExpr).
const TenantRowSecurityPolicyExpr = tenantrls.PolicyExpr

// TenantRowSecurityDDL returns the statements that put table under forced row
// security with the tenant policy (tenantrls.DDL).
func TenantRowSecurityDDL(table string) string { return tenantrls.DDL(table) }

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
