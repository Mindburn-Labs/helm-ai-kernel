package ledger

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// PostgresLedger is a durable SQL-based implementation of the Ledger.
type PostgresLedger struct {
	db *sql.DB
}

func NewPostgresLedger(db *sql.DB) *PostgresLedger {
	return &PostgresLedger{db: db}
}

// Ensure Schema
const pgSchema = `
CREATE TABLE IF NOT EXISTS obligations (
	id TEXT PRIMARY KEY,
	idempotency_key TEXT UNIQUE,
	intent TEXT,
	state TEXT,
	created_at TIMESTAMP,
	updated_at TIMESTAMP,
	leased_by TEXT,
	leased_until TIMESTAMP,
	hash TEXT,
	previous_hash TEXT,
	metadata TEXT,
	tenant_id TEXT -- Gap 12: Multi-Tenancy
);

-- Gap 12: Enable RLS
ALTER TABLE obligations ENABLE ROW LEVEL SECURITY;

-- Create Policy (Idempotent check required in real migrations, here simple if not exists logic)
-- Note: 'create policy if not exists' is PG 10+.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE policyname = 'tenant_isolation'
    ) THEN
        CREATE POLICY tenant_isolation ON obligations
        USING (tenant_id = current_setting('app.current_tenant', true)::text);
    END IF;
END
$$;
`

func (l *PostgresLedger) Init(ctx context.Context) error {
	_, err := l.db.ExecContext(ctx, pgSchema)
	return err
}

func (l *PostgresLedger) Create(ctx context.Context, obl Obligation) error {
	// 1. Get Previous Hash (Serialization for MVP)
	// For high throughput, we'd use a separate atomic counter or log table.
	// Here we just grab the last one.
	var lastHash string
	// Order by created_at desc to find tail.
	err := l.db.QueryRowContext(ctx, "SELECT hash FROM obligations ORDER BY created_at DESC LIMIT 1").Scan(&lastHash)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if lastHash == "" {
		lastHash = "0000000000000000000000000000000000000000000000000000000000000000" // Genesis
	}

	// 2. Compute Hash
	// Hash = SHA256(PreviousHash + ID + Intent + CreatedAt)
	payload := lastHash + obl.ID + obl.Intent + obl.CreatedAt.String()
	obl.PreviousHash = lastHash
	obl.Hash = fmt.Sprintf("%x", sha256Sum([]byte(payload))) // reuse or reimplement sha256Sum

	query := `
		INSERT INTO obligations (id, idempotency_key, intent, state, created_at, updated_at, hash, previous_hash, tenant_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`
	_, err = l.db.ExecContext(ctx, query,
		obl.ID, obl.IdempotencyKey, obl.Intent, obl.State, obl.CreatedAt, obl.UpdatedAt,
		obl.Hash, obl.PreviousHash, obl.TenantID,
	)
	return err
}

func sha256Sum(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

func (l *PostgresLedger) Get(ctx context.Context, id string) (Obligation, error) {
	// We can explicitly check tenant_id if passed in ctx, but usually Get(id) implies id is unique globally or we trust caller.
	// However, if RLS is on and we set 'app.current_tenant', it filters auto.
	// For now, we assume global uniqueness or we explicitly select tenant_id too.
	query := `SELECT id, idempotency_key, intent, state, created_at, updated_at, hash, previous_hash, metadata, tenant_id FROM obligations WHERE id = $1`
	row := l.db.QueryRowContext(ctx, query, id)

	var obl Obligation
	// use sql.NullString for optionals if needed, but here we scan directly.
	// If metadata is NULL, Scan might fail if we don't use *string or NullString.
	// We defined schema as `metadata TEXT`, it implies nullable?
	// In Create/Update we inserted string(metaJSON). If empty, likely empty string "" or "null".
	// Let's use *string for nullable fields to be safe.
	// Let's use *string for nullable fields to be safe.
	var hash, prevHash, metadata, tenantID sql.NullString

	err := row.Scan(&obl.ID, &obl.IdempotencyKey, &obl.Intent, &obl.State, &obl.CreatedAt, &obl.UpdatedAt, &hash, &prevHash, &metadata, &tenantID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Obligation{}, ErrNotFound
		}
		return Obligation{}, err
	}
	obl.Hash = hash.String
	obl.PreviousHash = prevHash.String
	obl.TenantID = tenantID.String

	if metadata.Valid && metadata.String != "" {
		if err := json.Unmarshal([]byte(metadata.String), &obl.Metadata); err != nil {
			// Log error but return obligation? Or fail?
			// Fail loud for integrity.
			return Obligation{}, fmt.Errorf("corrupt metadata: %w", err)
		}
	}
	return obl, nil
}

func (l *PostgresLedger) AcquireLease(ctx context.Context, id, workerID string, duration time.Duration) (Obligation, error) {
	now := time.Now()
	leasedUntil := now.Add(duration)

	// Atomic Lease Acquisition
	query := `
		UPDATE obligations 
		SET leased_by = $1, leased_until = $2, updated_at = $3
		WHERE id = $4 AND (leased_until < $3 OR leased_by = $1 OR leased_until IS NULL)
	`
	res, err := l.db.ExecContext(ctx, query, workerID, leasedUntil, now, id)
	if err != nil {
		return Obligation{}, err
	}

	rows, err := res.RowsAffected()
	if err != nil {
		return Obligation{}, fmt.Errorf("failed to check rows affected: %w", err)
	}
	if rows == 0 {
		return Obligation{}, errors.New("locked by another worker")
	}

	return l.Get(ctx, id)
}

// AcquireNextPending fetches and leases the next available PENDING obligation.
// It uses SKIP LOCKED to allow concurrent workers to process the queue without blocking.
func (l *PostgresLedger) AcquireNextPending(ctx context.Context, workerID string, duration time.Duration) (Obligation, error) {
	tx, err := l.db.BeginTx(ctx, nil)
	if err != nil {
		return Obligation{}, err
	}
	defer func() { _ = tx.Rollback() }() // Safe to call even if committed (no-op)

	// 1. Select Next Available (Locked)
	// GAP-10: Safe Leasing
	querySelect := `
		SELECT id 
		FROM obligations 
		WHERE state = 'PENDING' 
		ORDER BY created_at ASC 
		LIMIT 1 
		FOR UPDATE SKIP LOCKED
	`
	var id string
	if err := tx.QueryRowContext(ctx, querySelect).Scan(&id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Obligation{}, errors.New("no pending obligations") // Normalized error
		}
		return Obligation{}, err
	}

	// 2. Lease It
	now := time.Now()
	leasedUntil := now.Add(duration)
	queryUpdate := `
		UPDATE obligations
		SET leased_by = $1, leased_until = $2, updated_at = $3
		WHERE id = $4
	`
	if _, err := tx.ExecContext(ctx, queryUpdate, workerID, leasedUntil, now, id); err != nil {
		return Obligation{}, err
	}

	if err := tx.Commit(); err != nil {
		return Obligation{}, err
	}

	// 3. Return Full Object
	return l.Get(ctx, id)
}

func (l *PostgresLedger) UpdateState(ctx context.Context, id string, newState State, details map[string]any) error {
	// Serialize details to JSON
	var metaJSON []byte
	if details != nil {
		var err error
		metaJSON, err = json.Marshal(details)
		if err != nil {
			return fmt.Errorf("failed to marshal metadata: %w", err)
		}
	}

	query := `UPDATE obligations SET state = $1, updated_at = $2, metadata = $3 WHERE id = $4`
	_, err := l.db.ExecContext(ctx, query, newState, time.Now(), string(metaJSON), id)
	return err
}

func (l *PostgresLedger) ListPending(ctx context.Context) ([]Obligation, error) {
	query := `SELECT id, idempotency_key, intent, state, created_at, updated_at, hash, previous_hash, metadata, tenant_id FROM obligations WHERE state = 'PENDING'`
	rows, err := l.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	result := make([]Obligation, 0)
	for rows.Next() {
		var obl Obligation
		var hash, prevHash, metadata, tenantID sql.NullString
		if err := rows.Scan(&obl.ID, &obl.IdempotencyKey, &obl.Intent, &obl.State, &obl.CreatedAt, &obl.UpdatedAt, &hash, &prevHash, &metadata, &tenantID); err != nil {
			return nil, err
		}
		obl.Hash = hash.String
		obl.PreviousHash = prevHash.String
		obl.TenantID = tenantID.String
		if metadata.Valid && metadata.String != "" {
			_ = json.Unmarshal([]byte(metadata.String), &obl.Metadata)
		}
		result = append(result, obl)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func (l *PostgresLedger) ListAll(ctx context.Context) ([]Obligation, error) {
	query := `SELECT id, idempotency_key, intent, state, created_at, updated_at, hash, previous_hash, metadata, tenant_id FROM obligations`
	rows, err := l.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	result := make([]Obligation, 0)
	for rows.Next() {
		var obl Obligation
		var hash, prevHash, metadata, tenantID sql.NullString
		if err := rows.Scan(&obl.ID, &obl.IdempotencyKey, &obl.Intent, &obl.State, &obl.CreatedAt, &obl.UpdatedAt, &hash, &prevHash, &metadata, &tenantID); err != nil {
			return nil, err
		}
		obl.Hash = hash.String
		obl.PreviousHash = prevHash.String
		obl.TenantID = tenantID.String
		if metadata.Valid && metadata.String != "" {
			_ = json.Unmarshal([]byte(metadata.String), &obl.Metadata)
		}
		result = append(result, obl)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}
