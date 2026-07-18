package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	_ "modernc.org/sqlite"
)

// SQLitePrincipalBindingStore is the dependency-free local default
// implementation of PrincipalBindingStore.
type SQLitePrincipalBindingStore struct {
	db *sql.DB
}

// NewSQLitePrincipalBindingStore constructs a SQLitePrincipalBindingStore and
// ensures the backing table exists. It uses the passed db as-is; callers own
// the shared pool/pragma configuration (see SQLiteReceiptStore).
func NewSQLitePrincipalBindingStore(db *sql.DB) (*SQLitePrincipalBindingStore, error) {
	s := &SQLitePrincipalBindingStore{db: db}
	if err := s.migrate(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *SQLitePrincipalBindingStore) migrate() error {
	query := `
		CREATE TABLE IF NOT EXISTS principal_bindings (
			tenant_id TEXT NOT NULL,
			principal_id TEXT NOT NULL,
			created_at TEXT NOT NULL,
			PRIMARY KEY (tenant_id, principal_id)
		);`
	_, err := s.db.ExecContext(context.Background(), query)
	return err
}

// Upsert inserts a binding, idempotent on (tenant_id, principal_id).
func (s *SQLitePrincipalBindingStore) Upsert(ctx context.Context, b PrincipalBinding) error {
	query := `
		INSERT INTO principal_bindings (tenant_id, principal_id, created_at)
		VALUES (?, ?, ?)
		ON CONFLICT (tenant_id, principal_id) DO NOTHING
	`
	createdAt := b.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx, query, b.TenantID, b.PrincipalID, createdAt.Format(time.RFC3339Nano))
	return err
}

// Exists reports whether the given (tenant_id, principal_id) pair is bound.
func (s *SQLitePrincipalBindingStore) Exists(ctx context.Context, tenantID, principalID string) (bool, error) {
	query := `SELECT 1 FROM principal_bindings WHERE tenant_id = ? AND principal_id = ? LIMIT 1`
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
