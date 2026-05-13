package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// ReceiptStore defines the interface for persisting and retrieving execution receipts.
type ReceiptStore interface {
	Get(ctx context.Context, decisionID string) (*contracts.Receipt, error)
	GetByReceiptID(ctx context.Context, receiptID string) (*contracts.Receipt, error)
	List(ctx context.Context, limit int) ([]*contracts.Receipt, error)
	ListSince(ctx context.Context, since uint64, limit int) ([]*contracts.Receipt, error)
	ListByAgent(ctx context.Context, agentID string, since uint64, limit int) ([]*contracts.Receipt, error)
	Store(ctx context.Context, receipt *contracts.Receipt) error
	AppendCausal(ctx context.Context, sessionID string, build CausalReceiptBuilder) error
	// GetLastForSession returns the most recent receipt for a given session (for causal DAG chaining).
	GetLastForSession(ctx context.Context, sessionID string) (*contracts.Receipt, error)
}

// CausalReceiptBuilder constructs a receipt after the store has locked the
// session chain and assigned its next Lamport clock and previous hash.
type CausalReceiptBuilder func(previous *contracts.Receipt, lamport uint64, prevHash string) (*contracts.Receipt, error)

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
			effect_id TEXT,
			external_reference_id TEXT,
			execution_intent_id TEXT,
			status TEXT,
			result BYTEA,
			timestamp TIMESTAMPTZ,
			executor_id TEXT,
			metadata JSONB,
			signature TEXT,
			merkle_root TEXT,
			prev_hash TEXT,
			lamport_clock BIGINT,
			output_hash TEXT DEFAULT '',
			args_hash TEXT DEFAULT '',
			blob_hash TEXT DEFAULT ''
		);
		ALTER TABLE receipts ADD COLUMN IF NOT EXISTS effect_id TEXT;
		ALTER TABLE receipts ADD COLUMN IF NOT EXISTS external_reference_id TEXT;
		ALTER TABLE receipts ADD COLUMN IF NOT EXISTS metadata JSONB;
		ALTER TABLE receipts ADD COLUMN IF NOT EXISTS signature TEXT;
		ALTER TABLE receipts ADD COLUMN IF NOT EXISTS merkle_root TEXT;
		ALTER TABLE receipts ADD COLUMN IF NOT EXISTS output_hash TEXT DEFAULT '';
		ALTER TABLE receipts ADD COLUMN IF NOT EXISTS args_hash TEXT DEFAULT '';
		ALTER TABLE receipts ADD COLUMN IF NOT EXISTS blob_hash TEXT DEFAULT '';
		CREATE INDEX IF NOT EXISTS idx_receipts_executor_id ON receipts(executor_id);
		CREATE INDEX IF NOT EXISTS idx_receipts_decision_id ON receipts(decision_id);
		CREATE INDEX IF NOT EXISTS idx_receipts_executor_lamport ON receipts(executor_id, lamport_clock);
		CREATE UNIQUE INDEX IF NOT EXISTS idx_receipts_executor_lamport_unique ON receipts(executor_id, lamport_clock)
			WHERE executor_id IS NOT NULL AND executor_id <> '' AND lamport_clock > 0;
		CREATE INDEX IF NOT EXISTS idx_receipts_lamport_timestamp ON receipts(lamport_clock, timestamp);
		CREATE INDEX IF NOT EXISTS idx_receipts_timestamp ON receipts(timestamp);
	`
	_, err := s.db.ExecContext(ctx, query)
	return err
}

// receiptColumns is the canonical column list for receipt queries.
const receiptColumns = `receipt_id, decision_id, COALESCE(effect_id, execution_intent_id, '') AS effect_id, COALESCE(external_reference_id, '') AS external_reference_id, status, blob_hash, output_hash, timestamp, COALESCE(executor_id, '') AS executor_id, metadata, signature, merkle_root, COALESCE(prev_hash, '') AS prev_hash, COALESCE(lamport_clock, 0) AS lamport_clock, args_hash`

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

func (s *PostgresReceiptStore) ListSince(ctx context.Context, since uint64, limit int) ([]*contracts.Receipt, error) {
	query := `SELECT ` + receiptColumns + ` FROM receipts WHERE lamport_clock > $1 ORDER BY lamport_clock ASC, timestamp ASC LIMIT $2`
	rows, err := s.db.QueryContext(ctx, query, since, limit)
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
	var metadata []byte
	var signature sql.NullString
	var merkleRoot sql.NullString
	err := s.Scan(
		&r.ReceiptID, &r.DecisionID, &r.EffectID, &r.ExternalReferenceID, &r.Status,
		&r.BlobHash, &r.OutputHash, &r.Timestamp, &r.ExecutorID, &metadata, &signature,
		&merkleRoot, &r.PrevHash, &r.LamportClock, &r.ArgsHash,
	)
	if err != nil {
		return nil, err
	}
	if len(metadata) > 0 && string(metadata) != "null" {
		if err := json.Unmarshal(metadata, &r.Metadata); err != nil {
			return nil, fmt.Errorf("decode receipt metadata: %w", err)
		}
	}
	r.Signature = signature.String
	r.MerkleRoot = merkleRoot.String
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
	return insertPostgresReceipt(ctx, s.db, r)
}

type sqlExecer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func insertPostgresReceipt(ctx context.Context, execer sqlExecer, r *contracts.Receipt) error {
	query := `
		INSERT INTO receipts (
			receipt_id, decision_id, effect_id, external_reference_id, status, result, timestamp, executor_id,
			metadata, signature, merkle_root, prev_hash, lamport_clock, output_hash, args_hash, blob_hash
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10, $11, $12, $13, $14, $15, $16)
	`
	metaJSON, err := json.Marshal(r.Metadata)
	if err != nil {
		return fmt.Errorf("marshal receipt metadata: %w", err)
	}
	_, err = execer.ExecContext(ctx, query,
		r.ReceiptID,
		r.DecisionID,
		r.EffectID,
		r.ExternalReferenceID,
		r.Status,
		[]byte(r.BlobHash),
		r.Timestamp,
		r.ExecutorID,
		string(metaJSON),
		r.Signature,
		r.MerkleRoot,
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

func (s *PostgresReceiptStore) AppendCausal(ctx context.Context, sessionID string, build CausalReceiptBuilder) error {
	if build == nil {
		return fmt.Errorf("causal receipt builder is nil")
	}
	if sessionID == "" {
		return fmt.Errorf("session id is required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin receipt transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, sessionID); err != nil {
		return fmt.Errorf("lock receipt session %s: %w", sessionID, err)
	}
	last, err := queryLastPostgresReceipt(ctx, tx, sessionID)
	if err != nil {
		return err
	}
	receipt, err := buildNextCausalReceipt(sessionID, last, build)
	if err != nil {
		return err
	}
	if err := insertPostgresReceipt(ctx, tx, receipt); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit receipt transaction: %w", err)
	}
	committed = true
	return nil
}

// GetLastForSession returns the most recent receipt for a session (by executor_id) for causal DAG chaining.
func (s *PostgresReceiptStore) GetLastForSession(ctx context.Context, sessionID string) (*contracts.Receipt, error) {
	return queryLastPostgresReceipt(ctx, s.db, sessionID)
}

type sqlQueryer interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func queryLastPostgresReceipt(ctx context.Context, queryer sqlQueryer, sessionID string) (*contracts.Receipt, error) {
	query := `SELECT ` + receiptColumns + ` FROM receipts WHERE executor_id = $1 ORDER BY lamport_clock DESC LIMIT 1`
	row := queryer.QueryRowContext(ctx, query, sessionID)
	r, err := scanReceipt(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil // No previous receipt for this session — genesis
		}
		return nil, err
	}
	return r, nil
}

func buildNextCausalReceipt(sessionID string, previous *contracts.Receipt, build CausalReceiptBuilder) (*contracts.Receipt, error) {
	lamport := uint64(1)
	prevHash := ""
	if previous != nil {
		lamport = previous.LamportClock + 1
		hash, err := contracts.ReceiptChainHash(previous)
		if err != nil {
			return nil, fmt.Errorf("hash previous receipt for %s: %w", sessionID, err)
		}
		prevHash = hash
	}
	receipt, err := build(previous, lamport, prevHash)
	if err != nil {
		return nil, err
	}
	if receipt == nil {
		return nil, fmt.Errorf("causal receipt builder returned nil")
	}
	if receipt.ExecutorID == "" {
		receipt.ExecutorID = sessionID
	}
	if receipt.ExecutorID != sessionID {
		return nil, fmt.Errorf("receipt executor %q does not match locked session %q", receipt.ExecutorID, sessionID)
	}
	if receipt.LamportClock != lamport {
		return nil, fmt.Errorf("receipt lamport %d does not match assigned lamport %d", receipt.LamportClock, lamport)
	}
	if receipt.PrevHash != prevHash {
		return nil, fmt.Errorf("receipt prev_hash %q does not match assigned prev_hash %q", receipt.PrevHash, prevHash)
	}
	return receipt, nil
}
