package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"

	_ "modernc.org/sqlite"
)

type SQLiteReceiptStore struct {
	db *sql.DB
}

func NewSQLiteReceiptStore(db *sql.DB) (*SQLiteReceiptStore, error) {
	s := &SQLiteReceiptStore{db: db}
	if err := s.migrate(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *SQLiteReceiptStore) migrate() error {
	query := `
    CREATE TABLE IF NOT EXISTS receipts (
        receipt_id TEXT PRIMARY KEY,
        decision_id TEXT,
        effect_id TEXT,
        external_reference_id TEXT,
		status TEXT,
		blob_hash TEXT,
		output_hash TEXT,
		timestamp DATETIME,
		executor_id TEXT,
		metadata JSON,
		signature TEXT,
		merkle_root TEXT,
		prev_hash TEXT NOT NULL DEFAULT '',
		lamport_clock INTEGER NOT NULL DEFAULT 0
	);`
	_, err := s.db.ExecContext(context.Background(), query)
	return err
}

func (s *SQLiteReceiptStore) Get(ctx context.Context, decisionID string) (*contracts.Receipt, error) {
	query := `
        SELECT receipt_id, decision_id, effect_id, external_reference_id, status, blob_hash, output_hash, timestamp, executor_id, metadata, signature, merkle_root
        FROM receipts
        WHERE decision_id = ?
    `
	return s.queryOne(ctx, query, decisionID)
}

func (s *SQLiteReceiptStore) GetByReceiptID(ctx context.Context, receiptID string) (*contracts.Receipt, error) {
	query := `
        SELECT receipt_id, decision_id, effect_id, external_reference_id, status, blob_hash, output_hash, timestamp, executor_id, metadata, signature, merkle_root
        FROM receipts
        WHERE receipt_id = ?
    `
	return s.queryOne(ctx, query, receiptID)
}

func (s *SQLiteReceiptStore) List(ctx context.Context, limit int) ([]*contracts.Receipt, error) {
	query := `
        SELECT receipt_id, decision_id, effect_id, external_reference_id, status, blob_hash, output_hash, timestamp, executor_id, metadata, signature, merkle_root
        FROM receipts
        ORDER BY timestamp DESC
        LIMIT ?
    `
	rows, err := s.db.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var receipts []*contracts.Receipt
	for rows.Next() {
		r, err := scanReceiptRow(rows)
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

func (s *SQLiteReceiptStore) Store(ctx context.Context, r *contracts.Receipt) error {
	query := `INSERT INTO receipts (
		receipt_id, decision_id, effect_id, external_reference_id, status, blob_hash, output_hash, timestamp, executor_id, metadata, signature, merkle_root, prev_hash, lamport_clock
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	metaJSON, _ := json.Marshal(r.Metadata)
	timestamp := r.Timestamp.UTC().Format(time.RFC3339Nano)

	_, err := s.db.ExecContext(ctx, query,
		r.ReceiptID, r.DecisionID, r.EffectID, r.ExternalReferenceID, r.Status, r.BlobHash, r.OutputHash, timestamp, r.ExecutorID, string(metaJSON), r.Signature, r.MerkleRoot, r.PrevHash, r.LamportClock,
	)
	if err != nil {
		return fmt.Errorf("failed to insert receipt: %w", err)
	}
	return nil
}

// GetLastForSession returns the most recent receipt for a session for causal DAG chaining.
func (s *SQLiteReceiptStore) GetLastForSession(ctx context.Context, sessionID string) (*contracts.Receipt, error) {
	query := `
        SELECT receipt_id, decision_id, effect_id, external_reference_id, status, blob_hash, output_hash, timestamp, executor_id, metadata, signature, merkle_root
        FROM receipts
        WHERE executor_id = ?
        ORDER BY lamport_clock DESC
        LIMIT 1
    `
	r, err := s.queryOne(ctx, query, sessionID)
	if err != nil {
		if err.Error() == "receipt not found" {
			return nil, nil
		}
		return nil, err
	}
	return r, nil
}

func (s *SQLiteReceiptStore) queryOne(ctx context.Context, query string, arg any) (*contracts.Receipt, error) {
	row := s.db.QueryRowContext(ctx, query, arg)
	var (
		receiptID  string
		decisionID string
		effectID   string
		externalID sql.NullString
		status     string
		blobHash   string
		outputHash string
		timestamp  string
		executorID sql.NullString
		metaJSON   sql.NullString
		signature  sql.NullString
		merkleRoot sql.NullString
	)
	err := row.Scan(&receiptID, &decisionID, &effectID, &externalID, &status, &blobHash, &outputHash, &timestamp, &executorID, &metaJSON, &signature, &merkleRoot)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("receipt not found")
		}
		return nil, err
	}
	parsedTime := parseTime(timestamp)

	var meta map[string]any
	if metaJSON.Valid && metaJSON.String != "" {
		_ = json.Unmarshal([]byte(metaJSON.String), &meta)
	}

	return &contracts.Receipt{
		ReceiptID:           receiptID,
		DecisionID:          decisionID,
		ExternalReferenceID: externalID.String,
		EffectID:            effectID,
		Status:              status,
		Timestamp:           parsedTime,
		BlobHash:            blobHash,
		OutputHash:          outputHash,
		ExecutorID:          executorID.String,
		Metadata:            meta,
		Signature:           signature.String,
		MerkleRoot:          merkleRoot.String,
	}, nil
}

func scanReceiptRow(rows *sql.Rows) (*contracts.Receipt, error) {
	var (
		receiptID  string
		decisionID string
		effectID   string
		externalID sql.NullString
		status     string
		blobHash   string
		outputHash string
		timestamp  string
		executorID sql.NullString
		metaJSON   sql.NullString
		signature  sql.NullString
		merkleRoot sql.NullString
	)
	if err := rows.Scan(&receiptID, &decisionID, &effectID, &externalID, &status, &blobHash, &outputHash, &timestamp, &executorID, &metaJSON, &signature, &merkleRoot); err != nil {
		return nil, err
	}
	parsedTime := parseTime(timestamp)

	var meta map[string]any
	if metaJSON.Valid && metaJSON.String != "" {
		_ = json.Unmarshal([]byte(metaJSON.String), &meta)
	}

	return &contracts.Receipt{
		ReceiptID:           receiptID,
		DecisionID:          decisionID,
		ExternalReferenceID: externalID.String,
		EffectID:            effectID,
		Status:              status,
		Timestamp:           parsedTime,
		BlobHash:            blobHash,
		OutputHash:          outputHash,
		ExecutorID:          executorID.String,
		Metadata:            meta,
		Signature:           signature.String,
		MerkleRoot:          merkleRoot.String,
	}, nil
}

func parseTime(value string) time.Time {
	if value == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return t
	}
	if t, err := time.Parse(time.RFC3339, value); err == nil {
		return t
	}
	return time.Time{}
}
