package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
)

// ReceiptStore defines the interface for persisting and retrieving execution receipts.
type ReceiptStore interface {
	Get(ctx context.Context, decisionID string) (*contracts.Receipt, error)
	GetByReceiptID(ctx context.Context, receiptID string) (*contracts.Receipt, error)
	List(ctx context.Context, limit int) ([]*contracts.Receipt, error)
	ListByAgent(ctx context.Context, agentID string, since uint64, limit int) ([]*contracts.Receipt, error)
	Store(ctx context.Context, receipt *contracts.Receipt) error
	// GetLastForSession returns the most recent receipt for a given session (for causal DAG chaining).
	GetLastForSession(ctx context.Context, sessionID string) (*contracts.Receipt, error)
}

// PostgresReceiptStore is a durable SQL-based implementation.
type PostgresReceiptStore struct {
	db *sql.DB
}

func NewPostgresReceiptStore(db *sql.DB) *PostgresReceiptStore {
	return &PostgresReceiptStore{db: db}
}

func (s *PostgresReceiptStore) Init(ctx context.Context) error {
	query := `
		CREATE TABLE IF NOT EXISTS receipts (
			receipt_id TEXT PRIMARY KEY,
			decision_id TEXT,
			execution_intent_id TEXT,
			status TEXT,
			result BYTEA,
			timestamp TIMESTAMPTZ,
			executor_id TEXT,
			prev_hash TEXT,
			lamport_clock BIGINT,
			output_hash TEXT DEFAULT '',
			args_hash TEXT DEFAULT '',
			blob_hash TEXT DEFAULT ''
		);
		CREATE INDEX IF NOT EXISTS idx_receipts_executor_id ON receipts(executor_id);
	`
	_, err := s.db.ExecContext(ctx, query)
	return err
}

// receiptColumns is the canonical column list for receipt queries.
const receiptColumns = `receipt_id, decision_id, execution_intent_id, status, timestamp, executor_id, prev_hash, lamport_clock, output_hash, args_hash, blob_hash`

func (s *PostgresReceiptStore) Get(ctx context.Context, decisionID string) (*contracts.Receipt, error) {
	query := `SELECT ` + receiptColumns + ` FROM receipts WHERE decision_id = $1`
	return s.queryOne(ctx, query, decisionID)
}

func (s *PostgresReceiptStore) GetByReceiptID(ctx context.Context, receiptID string) (*contracts.Receipt, error) {
	query := `SELECT ` + receiptColumns + ` FROM receipts WHERE receipt_id = $1`
	return s.queryOne(ctx, query, receiptID)
}

func (s *PostgresReceiptStore) List(ctx context.Context, limit int) ([]*contracts.Receipt, error) {
	query := `SELECT ` + receiptColumns + ` FROM receipts ORDER BY timestamp DESC LIMIT $1`
	rows, err := s.db.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var receipts []*contracts.Receipt
	for rows.Next() {
		r, err := scanReceipt(rows)
		if err != nil {
			return nil, err
		}
		receipts = append(receipts, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return receipts, nil
}

func (s *PostgresReceiptStore) ListByAgent(ctx context.Context, agentID string, since uint64, limit int) ([]*contracts.Receipt, error) {
	query := `SELECT ` + receiptColumns + ` FROM receipts WHERE executor_id = $1 AND lamport_clock > $2 ORDER BY lamport_clock ASC, timestamp ASC LIMIT $3`
	rows, err := s.db.QueryContext(ctx, query, agentID, since, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var receipts []*contracts.Receipt
	for rows.Next() {
		r, err := scanReceipt(rows)
		if err != nil {
			return nil, err
		}
		receipts = append(receipts, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return receipts, nil
}

// scanner is an interface satisfied by both *sql.Row and *sql.Rows.
type scanner interface {
	Scan(dest ...any) error
}

func scanReceipt(s scanner) (*contracts.Receipt, error) {
	var r contracts.Receipt
	err := s.Scan(
		&r.ReceiptID, &r.DecisionID, &r.EffectID, &r.Status, &r.Timestamp,
		&r.ExecutorID, &r.PrevHash, &r.LamportClock, &r.OutputHash, &r.ArgsHash, &r.BlobHash,
	)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (s *PostgresReceiptStore) queryOne(ctx context.Context, query string, arg any) (*contracts.Receipt, error) {
	row := s.db.QueryRowContext(ctx, query, arg)
	r, err := scanReceipt(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("receipt not found")
		}
		return nil, err
	}
	return r, nil
}

func (s *PostgresReceiptStore) Store(ctx context.Context, r *contracts.Receipt) error {
	query := `
		INSERT INTO receipts (receipt_id, decision_id, execution_intent_id, status, result, timestamp, executor_id, prev_hash, lamport_clock, output_hash, args_hash, blob_hash)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		ON CONFLICT (receipt_id) DO NOTHING
	`
	_, err := s.db.ExecContext(ctx, query,
		r.ReceiptID,
		r.DecisionID,
		r.EffectID,
		r.Status,
		[]byte(r.BlobHash),
		r.Timestamp,
		r.ExecutorID,
		r.PrevHash,
		r.LamportClock,
		r.OutputHash,
		r.ArgsHash,
		r.BlobHash,
	)
	if err != nil {
		return fmt.Errorf("failed to insert receipt: %w", err)
	}
	return nil
}

// GetLastForSession returns the most recent receipt for a session (by executor_id) for causal DAG chaining.
func (s *PostgresReceiptStore) GetLastForSession(ctx context.Context, sessionID string) (*contracts.Receipt, error) {
	query := `SELECT ` + receiptColumns + ` FROM receipts WHERE executor_id = $1 ORDER BY lamport_clock DESC LIMIT 1`
	r, err := s.queryOne(ctx, query, sessionID)
	if err != nil {
		if err.Error() == "receipt not found" {
			return nil, nil // No previous receipt for this session — genesis
		}
		return nil, err
	}
	return r, nil
}
