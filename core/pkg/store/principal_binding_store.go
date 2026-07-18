package store

import (
	"context"
	"database/sql"
	"errors"
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
	// Upsert inserts a binding, idempotent on (tenant_id, principal_id).
	Upsert(ctx context.Context, b PrincipalBinding) error
	// Exists reports whether the given (tenant_id, principal_id) pair is bound.
	Exists(ctx context.Context, tenantID, principalID string) (bool, error)
}

// PostgresPrincipalBindingStore is a durable SQL-based implementation backed
// by Postgres.
type PostgresPrincipalBindingStore struct {
	db *sql.DB
}

// NewPostgresPrincipalBindingStore constructs a PostgresPrincipalBindingStore
// and ensures the backing table exists.
func NewPostgresPrincipalBindingStore(db *sql.DB) (*PostgresPrincipalBindingStore, error) {
	s := &PostgresPrincipalBindingStore{db: db}
	if err := s.migrate(context.Background()); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *PostgresPrincipalBindingStore) migrate(ctx context.Context) error {
	query := `
		CREATE TABLE IF NOT EXISTS principal_bindings (
			tenant_id TEXT NOT NULL,
			principal_id TEXT NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			PRIMARY KEY (tenant_id, principal_id)
		);`
	_, err := s.db.ExecContext(ctx, query)
	return err
}

// Upsert inserts a binding, idempotent on (tenant_id, principal_id).
func (s *PostgresPrincipalBindingStore) Upsert(ctx context.Context, b PrincipalBinding) error {
	query := `
		INSERT INTO principal_bindings (tenant_id, principal_id, created_at)
		VALUES ($1, $2, $3)
		ON CONFLICT (tenant_id, principal_id) DO NOTHING
	`
	createdAt := b.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx, query, b.TenantID, b.PrincipalID, createdAt)
	return err
}

// Exists reports whether the given (tenant_id, principal_id) pair is bound.
func (s *PostgresPrincipalBindingStore) Exists(ctx context.Context, tenantID, principalID string) (bool, error) {
	query := `SELECT 1 FROM principal_bindings WHERE tenant_id = $1 AND principal_id = $2 LIMIT 1`
	var one int
	err := s.db.QueryRowContext(ctx, query, tenantID, principalID).Scan(&one)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}
