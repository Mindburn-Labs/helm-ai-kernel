package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"

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
		lamport_clock INTEGER NOT NULL DEFAULT 0,
		args_hash TEXT NOT NULL DEFAULT ''
	);`
	if _, err := s.db.ExecContext(context.Background(), query); err != nil {
		return err
	}
	if err := s.ensureColumn("args_hash", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	indexes := []string{
		`CREATE INDEX IF NOT EXISTS idx_receipts_executor_id ON receipts(executor_id)`,
		`CREATE INDEX IF NOT EXISTS idx_receipts_decision_id ON receipts(decision_id)`,
		`CREATE INDEX IF NOT EXISTS idx_receipts_executor_lamport ON receipts(executor_id, lamport_clock)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_receipts_executor_lamport_unique ON receipts(executor_id, lamport_clock) WHERE executor_id IS NOT NULL AND executor_id <> '' AND lamport_clock > 0`,
		`CREATE INDEX IF NOT EXISTS idx_receipts_lamport_timestamp ON receipts(lamport_clock, timestamp)`,
		`CREATE INDEX IF NOT EXISTS idx_receipts_timestamp ON receipts(timestamp)`,
	}
	for _, stmt := range indexes {
		if _, err := s.db.ExecContext(context.Background(), stmt); err != nil {
			return err
		}
	}
	return nil
}

func (s *SQLiteReceiptStore) ensureColumn(name, definition string) error {
	rows, err := s.db.QueryContext(context.Background(), `PRAGMA table_info(receipts)`)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var (
			cid        int
			columnName string
			columnType string
			notNull    int
			defaultVal sql.NullString
			pk         int
		)
		if err := rows.Scan(&cid, &columnName, &columnType, &notNull, &defaultVal, &pk); err != nil {
			return err
		}
		if strings.EqualFold(columnName, name) {
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}

	_, err = s.db.ExecContext(context.Background(), fmt.Sprintf("ALTER TABLE receipts ADD COLUMN %s %s", name, definition))
	return err
}

func (s *SQLiteReceiptStore) Get(ctx context.Context, decisionID string) (*contracts.Receipt, error) {
	query := `
        SELECT receipt_id, decision_id, effect_id, external_reference_id, status, blob_hash, output_hash, timestamp, executor_id, metadata, signature, merkle_root, prev_hash, lamport_clock, args_hash
        FROM receipts
        WHERE decision_id = ?
    `
	return s.queryOne(ctx, query, decisionID)
}

func (s *SQLiteReceiptStore) GetByReceiptID(ctx context.Context, receiptID string) (*contracts.Receipt, error) {
	query := `
        SELECT receipt_id, decision_id, effect_id, external_reference_id, status, blob_hash, output_hash, timestamp, executor_id, metadata, signature, merkle_root, prev_hash, lamport_clock, args_hash
        FROM receipts
        WHERE receipt_id = ?
    `
	return s.queryOne(ctx, query, receiptID)
}

func (s *SQLiteReceiptStore) List(ctx context.Context, limit int) ([]*contracts.Receipt, error) {
	query := `
        SELECT receipt_id, decision_id, effect_id, external_reference_id, status, blob_hash, output_hash, timestamp, executor_id, metadata, signature, merkle_root, prev_hash, lamport_clock, args_hash
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

func (s *SQLiteReceiptStore) ListByAgent(ctx context.Context, agentID string, since uint64, limit int) ([]*contracts.Receipt, error) {
	query := `
        SELECT receipt_id, decision_id, effect_id, external_reference_id, status, blob_hash, output_hash, timestamp, executor_id, metadata, signature, merkle_root, prev_hash, lamport_clock, args_hash
        FROM receipts
        WHERE executor_id = ? AND lamport_clock > ?
        ORDER BY lamport_clock ASC, timestamp ASC
        LIMIT ?
    `
	rows, err := s.db.QueryContext(ctx, query, agentID, since, limit)
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

func (s *SQLiteReceiptStore) ListSince(ctx context.Context, since uint64, limit int) ([]*contracts.Receipt, error) {
	query := `
        SELECT receipt_id, decision_id, effect_id, external_reference_id, status, blob_hash, output_hash, timestamp, executor_id, metadata, signature, merkle_root, prev_hash, lamport_clock, args_hash
        FROM receipts
        WHERE lamport_clock > ?
        ORDER BY lamport_clock ASC, timestamp ASC
        LIMIT ?
    `
	rows, err := s.db.QueryContext(ctx, query, since, limit)
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
	return insertSQLiteReceipt(ctx, s.db, r)
}

func insertSQLiteReceipt(ctx context.Context, execer sqlExecer, r *contracts.Receipt) error {
	query := `INSERT INTO receipts (
		receipt_id, decision_id, effect_id, external_reference_id, status, blob_hash, output_hash, timestamp, executor_id, metadata, signature, merkle_root, prev_hash, lamport_clock, args_hash
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	metaJSON, err := json.Marshal(r.Metadata)
	if err != nil {
		return fmt.Errorf("marshal receipt metadata: %w", err)
	}
	timestamp := r.Timestamp.UTC().Format(time.RFC3339Nano)

	_, err = execer.ExecContext(ctx, query,
		r.ReceiptID, r.DecisionID, r.EffectID, r.ExternalReferenceID, r.Status, r.BlobHash, r.OutputHash, timestamp, r.ExecutorID, string(metaJSON), r.Signature, r.MerkleRoot, r.PrevHash, r.LamportClock, r.ArgsHash,
	)
	if err != nil {
		return fmt.Errorf("failed to insert receipt: %w", err)
	}
	return nil
}

func (s *SQLiteReceiptStore) AppendCausal(ctx context.Context, sessionID string, build CausalReceiptBuilder) error {
	if build == nil {
		return fmt.Errorf("causal receipt builder is nil")
	}
	if sessionID == "" {
		return fmt.Errorf("session id is required")
	}
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("open receipt connection: %w", err)
	}
	defer func() { _ = conn.Close() }()

	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return fmt.Errorf("begin receipt transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
		}
	}()

	last, err := queryLastSQLiteReceipt(ctx, conn, sessionID)
	if err != nil {
		return err
	}
	receipt, err := buildNextCausalReceipt(sessionID, last, build)
	if err != nil {
		return err
	}
	if err := insertSQLiteReceipt(ctx, conn, receipt); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return fmt.Errorf("commit receipt transaction: %w", err)
	}
	committed = true
	return nil
}

// GetLastForSession returns the most recent receipt for a session for causal DAG chaining.
func (s *SQLiteReceiptStore) GetLastForSession(ctx context.Context, sessionID string) (*contracts.Receipt, error) {
	return queryLastSQLiteReceipt(ctx, s.db, sessionID)
}

func queryLastSQLiteReceipt(ctx context.Context, queryer sqlQueryer, sessionID string) (*contracts.Receipt, error) {
	query := `
        SELECT receipt_id, decision_id, effect_id, external_reference_id, status, blob_hash, output_hash, timestamp, executor_id, metadata, signature, merkle_root, prev_hash, lamport_clock, args_hash
        FROM receipts
        WHERE executor_id = ?
        ORDER BY lamport_clock DESC
        LIMIT 1
    `
	r, err := scanSQLiteReceipt(queryer.QueryRowContext(ctx, query, sessionID))
	if err != nil {
		if err == sql.ErrNoRows {
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
		prevHash   sql.NullString
		lamport    uint64
		argsHash   sql.NullString
	)
	err := row.Scan(&receiptID, &decisionID, &effectID, &externalID, &status, &blobHash, &outputHash, &timestamp, &executorID, &metaJSON, &signature, &merkleRoot, &prevHash, &lamport, &argsHash)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("receipt not found")
		}
		return nil, err
	}
	return receiptFromSQLiteFields(receiptID, decisionID, effectID, externalID, status, blobHash, outputHash, timestamp, executorID, metaJSON, signature, merkleRoot, prevHash, lamport, argsHash)
}

type sqliteScanner interface {
	Scan(dest ...any) error
}

func scanSQLiteReceipt(scanner sqliteScanner) (*contracts.Receipt, error) {
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
		prevHash   sql.NullString
		lamport    uint64
		argsHash   sql.NullString
	)
	if err := scanner.Scan(&receiptID, &decisionID, &effectID, &externalID, &status, &blobHash, &outputHash, &timestamp, &executorID, &metaJSON, &signature, &merkleRoot, &prevHash, &lamport, &argsHash); err != nil {
		return nil, err
	}
	return receiptFromSQLiteFields(receiptID, decisionID, effectID, externalID, status, blobHash, outputHash, timestamp, executorID, metaJSON, signature, merkleRoot, prevHash, lamport, argsHash)
}

func receiptFromSQLiteFields(receiptID, decisionID, effectID string, externalID sql.NullString, status, blobHash, outputHash, timestamp string, executorID, metaJSON, signature, merkleRoot, prevHash sql.NullString, lamport uint64, argsHash sql.NullString) (*contracts.Receipt, error) {
	parsedTime := parseTime(timestamp)

	var meta map[string]any
	if metaJSON.Valid && metaJSON.String != "" && metaJSON.String != "null" {
		if err := json.Unmarshal([]byte(metaJSON.String), &meta); err != nil {
			return nil, fmt.Errorf("decode receipt metadata: %w", err)
		}
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
		PrevHash:            prevHash.String,
		LamportClock:        lamport,
		ArgsHash:            argsHash.String,
	}, nil
}

func scanReceiptRow(rows *sql.Rows) (*contracts.Receipt, error) {
	return scanSQLiteReceipt(rows)
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
