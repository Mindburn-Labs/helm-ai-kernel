package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// PrincipalBinding records that a principal is authorized to act as/for a
// given tenant. The pair (TenantID, PrincipalID) is the natural key.
type PrincipalBinding struct {
	TenantID    string
	PrincipalID string
	CreatedAt   time.Time
}

// PrincipalBindingStore persists the registry of (tenant_id, principal_id)
// bindings so the kernel can authorize many tenants, not just a single
// env-configured pair.
type PrincipalBindingStore interface {
	// Bind records the binding, idempotent on (tenant_id, principal_id). It
	// refuses a principal already bound in another tenant unless
	// allowCrossTenant is set; the check and the insert are one transaction.
	Bind(ctx context.Context, b PrincipalBinding, allowCrossTenant bool) (BindResult, error)
	// Exists reports whether the given (tenant_id, principal_id) pair is bound.
	Exists(ctx context.Context, tenantID, principalID string) (bool, error)
}

// BindOutcome is what Bind did.
type BindOutcome int

const (
	// BindCreated means the binding was inserted.
	BindCreated BindOutcome = iota + 1
	// BindExisting means the binding was already there; nothing changed.
	BindExisting
	// BindRefusedCrossTenant means the principal is bound in another tenant
	// and cross-tenant bindings were not allowed; nothing changed.
	BindRefusedCrossTenant
)

// BindResult reports a Bind: its outcome and the other tenants the principal
// is bound in (never including the requested tenant).
type BindResult struct {
	Outcome      BindOutcome
	OtherTenants []string
}

// crossTenantBindRefused is the binding-integrity rule (ADR-0005 §11): a
// principal holds bindings in one tenant only, unless it is explicitly allowed
// to hold them in several.
func crossTenantBindRefused(otherTenants []string, allowCrossTenant bool) bool {
	return len(otherTenants) > 0 && !allowCrossTenant
}

// decideBind reads the principal's tenants from rows and returns the outcome
// before any insert.
func decideBind(rows *sql.Rows, tenantID string, allowCrossTenant bool) (BindResult, error) {
	defer rows.Close()
	var result BindResult
	existing := false
	for rows.Next() {
		var bound string
		if err := rows.Scan(&bound); err != nil {
			return BindResult{}, err
		}
		if bound == tenantID {
			existing = true
		} else {
			result.OtherTenants = append(result.OtherTenants, bound)
		}
	}
	if err := rows.Err(); err != nil {
		return BindResult{}, err
	}
	switch {
	case existing:
		result.Outcome = BindExisting
	case crossTenantBindRefused(result.OtherTenants, allowCrossTenant):
		result.Outcome = BindRefusedCrossTenant
	default:
		result.Outcome = BindCreated
	}
	return result, nil
}

// PostgresPrincipalBindingStore is a durable SQL-based implementation backed
// by Postgres.
type PostgresPrincipalBindingStore struct {
	db *sql.DB
}

// NewPostgresPrincipalBindingStore constructs a PostgresPrincipalBindingStore.
// It does not execute DDL; serving code must use a database prepared by the
// explicit owner migration command.
func NewPostgresPrincipalBindingStore(db *sql.DB) (*PostgresPrincipalBindingStore, error) {
	if db == nil {
		return nil, errors.New("postgres principal binding store requires database")
	}
	return &PostgresPrincipalBindingStore{db: db}, nil
}

// MigratePostgresPrincipalBindings applies the principal binding schema as an
// explicit owner operation.
func MigratePostgresPrincipalBindings(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return errors.New("postgres principal binding migration requires database")
	}
	query := `
		CREATE TABLE IF NOT EXISTS principal_bindings (
			tenant_id TEXT NOT NULL,
			principal_id TEXT NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			PRIMARY KEY (tenant_id, principal_id)
		);`
	if _, err := db.ExecContext(ctx, query); err != nil {
		return err
	}
	if _, err := db.ExecContext(ctx, TenantRowSecurityDDL("principal_bindings")); err != nil {
		return err
	}
	// principal_lookup lets a transaction bound to one principal read that
	// principal's bindings in every tenant, and nothing else. The Control Plane
	// token check needs it: a known principal presented for a tenant it is not
	// bound to is refused (ADR-0005 §3), and forced tenant row security alone
	// would hide the other tenants' rows. SELECT only; writes stay tenant-bound.
	_, err := db.ExecContext(ctx, principalLookupPolicyDDL)
	return err
}

// PrincipalLookupPolicyExpr is how Postgres deparses the principal_lookup
// USING clause. The runtime check and the row-security catalog compare the
// installed policy with it exactly, so a widened predicate is not mistaken for
// this one.
const PrincipalLookupPolicyExpr = "(principal_id = current_setting('app.current_principal'::text, true))"

const principalLookupPolicyDDL = `DROP POLICY IF EXISTS principal_lookup ON principal_bindings;
CREATE POLICY principal_lookup ON principal_bindings FOR SELECT
	USING (principal_id = current_setting('app.current_principal', true));`

// PrincipalBindingLookup reports whether a principal is bound to any tenant.
type PrincipalBindingLookup interface {
	PrincipalBound(ctx context.Context, principalID string) (bool, error)
}

// PrincipalBound reports whether principalID has a binding in any tenant. The
// transaction is bound to that principal (app.current_principal), which the
// principal_lookup policy admits; no tenant is set, so nothing else is visible.
func (s *PostgresPrincipalBindingStore) PrincipalBound(ctx context.Context, principalID string) (bool, error) {
	if strings.TrimSpace(principalID) == "" {
		return false, errors.New("principal lookup requires a principal")
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('app.current_principal', $1, true)`, principalID); err != nil {
		return false, err
	}
	var one int
	err = tx.QueryRowContext(ctx, `SELECT 1 FROM principal_bindings WHERE principal_id = $1 LIMIT 1`, principalID).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// Bind records the binding in one transaction bound to the tenant
// (store.WithTenant) and to the principal (app.current_principal, which the
// principal_lookup policy admits), so it sees this principal's bindings in
// every tenant. A transaction-scoped advisory lock on the principal serializes
// concurrent binds of it: without the lock, two binds into different tenants
// could each read no other tenant and both insert.
func (s *PostgresPrincipalBindingStore) Bind(ctx context.Context, b PrincipalBinding, allowCrossTenant bool) (BindResult, error) {
	if strings.TrimSpace(b.PrincipalID) == "" {
		return BindResult{}, errors.New("principal binding requires a principal")
	}
	createdAt := b.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	var result BindResult
	err := WithTenant(ctx, s.db, b.TenantID, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext('principal_bindings'), hashtext($1))`, b.PrincipalID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `SELECT set_config('app.current_principal', $1, true)`, b.PrincipalID); err != nil {
			return err
		}
		rows, err := tx.QueryContext(ctx, `SELECT tenant_id FROM principal_bindings WHERE principal_id = $1 ORDER BY tenant_id`, b.PrincipalID)
		if err != nil {
			return err
		}
		if result, err = decideBind(rows, b.TenantID, allowCrossTenant); err != nil || result.Outcome != BindCreated {
			return err
		}
		_, err = tx.ExecContext(ctx, `
			INSERT INTO principal_bindings (tenant_id, principal_id, created_at)
			VALUES ($1, $2, $3)
			ON CONFLICT (tenant_id, principal_id) DO NOTHING`, b.TenantID, b.PrincipalID, createdAt)
		return err
	})
	if err != nil {
		return BindResult{}, err
	}
	return result, nil
}

// Exists reports whether the given (tenant_id, principal_id) pair is bound.
func (s *PostgresPrincipalBindingStore) Exists(ctx context.Context, tenantID, principalID string) (bool, error) {
	query := `SELECT 1 FROM principal_bindings WHERE tenant_id = $1 AND principal_id = $2 LIMIT 1`
	var one int
	err := WithTenant(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, query, tenantID, principalID).Scan(&one)
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}
