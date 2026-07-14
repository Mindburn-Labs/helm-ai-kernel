package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"

	_ "modernc.org/sqlite"
)

type SQLiteReceiptStore struct {
	db      *sql.DB
	writeMu sync.Mutex
}

// sqliteReceiptSynchronousPragma is deliberately FULL rather than NORMAL.
// Setup lifecycle receipts become authority for an installed native-client
// binding, so a successful COMMIT must survive a power-loss boundary before
// config, binding, and recovery cleanup may advance.
const sqliteReceiptSynchronousPragma = "PRAGMA synchronous=FULL;"

const (
	sqliteReceiptInitAttempts = 8
	sqliteReceiptInitBackoff  = 25 * time.Millisecond
)

// sqliteReceiptColumns is the projection kept alongside the canonical receipt
// envelope for indexing and backwards-compatible reads. The envelope is the
// authoritative representation for newly written receipts because
// ReceiptChainHash covers fields beyond this query projection.
const sqliteReceiptColumns = `receipt_id, decision_id, effect_id, external_reference_id, status, blob_hash, output_hash, timestamp, executor_id, metadata, signature, merkle_root, prev_hash, lamport_clock, args_hash, log_id, leaf_index, transparency, receipt_envelope`

func NewSQLiteReceiptStore(db *sql.DB) (*SQLiteReceiptStore, error) {
	s := &SQLiteReceiptStore{db: db}

	// SQLite remains the dependency-free local default. Keep one pooled
	// connection because writes are serialized and SQLite has one writer.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(1 * time.Hour)

	pragmas := []struct {
		stmt string
		name string
	}{
		{"PRAGMA busy_timeout=5000;", "set busy timeout"},
		{"PRAGMA journal_mode=WAL;", "enable WAL"},
		{sqliteReceiptSynchronousPragma, "set synchronous mode"},
		{"PRAGMA temp_store=MEMORY;", "set temp store"},
		{"PRAGMA wal_autocheckpoint=1000;", "set WAL autocheckpoint"},
	}
	for _, pragma := range pragmas {
		if err := retrySQLiteReceiptInit(func() error {
			_, err := db.Exec(pragma.stmt)
			return err
		}); err != nil {
			return nil, fmt.Errorf("%s: %w", pragma.name, err)
		}
	}
	if err := s.migrate(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *SQLiteReceiptStore) migrate() error {
	return retrySQLiteReceiptInit(s.migrateOnce)
}

func (s *SQLiteReceiptStore) migrateOnce() error {
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
		args_hash TEXT NOT NULL DEFAULT '',
		log_id TEXT NOT NULL DEFAULT '',
		leaf_index INTEGER NOT NULL DEFAULT 0,
		transparency TEXT,
		receipt_envelope TEXT NOT NULL DEFAULT ''
	);`
	if _, err := s.db.ExecContext(context.Background(), query); err != nil {
		return err
	}
	if err := s.ensureColumn("args_hash", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureColumn("log_id", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureColumn("leaf_index", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := s.ensureColumn("transparency", "TEXT"); err != nil {
		return err
	}
	if err := s.ensureColumn("receipt_envelope", "TEXT NOT NULL DEFAULT ''"); err != nil {
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

// retrySQLiteReceiptInit handles the short exclusive-lock window while a
// second process enables WAL or creates indexes in the same authority store.
// Receipt initialization is idempotent, so retrying the whole migration is
// safe; non-contention errors fail immediately.
func retrySQLiteReceiptInit(operation func() error) error {
	var err error
	for attempt := 0; attempt < sqliteReceiptInitAttempts; attempt++ {
		if err = operation(); err == nil {
			return nil
		}
		if !isSQLiteReceiptBusy(err) || attempt == sqliteReceiptInitAttempts-1 {
			return err
		}
		time.Sleep(time.Duration(attempt+1) * sqliteReceiptInitBackoff)
	}
	return err
}

func isSQLiteReceiptBusy(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "sqlite_busy") ||
		strings.Contains(message, "sqlite_locked") ||
		strings.Contains(message, "database is locked") ||
		strings.Contains(message, "database schema is locked") ||
		strings.Contains(message, "database table is locked") ||
		strings.Contains(message, "database is busy")
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
	query := `SELECT ` + sqliteReceiptColumns + ` FROM receipts WHERE decision_id = ?`
	return s.queryOne(ctx, query, decisionID)
}

func (s *SQLiteReceiptStore) GetByReceiptID(ctx context.Context, receiptID string) (*contracts.Receipt, error) {
	query := `SELECT ` + sqliteReceiptColumns + ` FROM receipts WHERE receipt_id = ?`
	return s.queryOne(ctx, query, receiptID)
}

func (s *SQLiteReceiptStore) List(ctx context.Context, limit int) ([]*contracts.Receipt, error) {
	query := `SELECT ` + sqliteReceiptColumns + ` FROM receipts ORDER BY timestamp DESC LIMIT ?`
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
	query := `SELECT ` + sqliteReceiptColumns + ` FROM receipts WHERE executor_id = ? AND lamport_clock > ? ORDER BY lamport_clock ASC, timestamp ASC LIMIT ?`
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
	query := `SELECT ` + sqliteReceiptColumns + ` FROM receipts WHERE lamport_clock > ? ORDER BY lamport_clock ASC, timestamp ASC LIMIT ?`
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
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return insertSQLiteReceipt(ctx, s.db, r)
}

func insertSQLiteReceipt(ctx context.Context, execer sqlExecer, r *contracts.Receipt) error {
	query := `INSERT INTO receipts (
		receipt_id, decision_id, effect_id, external_reference_id, status, blob_hash, output_hash, timestamp, executor_id, metadata, signature, merkle_root, prev_hash, lamport_clock, args_hash, log_id, leaf_index, transparency, receipt_envelope
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	metaJSON, err := json.Marshal(r.Metadata)
	if err != nil {
		return fmt.Errorf("marshal receipt metadata: %w", err)
	}
	transparencyJSON, err := encodeTransparencyAnchor(r)
	if err != nil {
		return err
	}
	envelope, err := canonicalize.JCS(r)
	if err != nil {
		return fmt.Errorf("canonicalize receipt envelope: %w", err)
	}
	timestamp := r.Timestamp.UTC().Format(time.RFC3339Nano)

	_, err = execer.ExecContext(ctx, query,
		r.ReceiptID, r.DecisionID, r.EffectID, r.ExternalReferenceID, r.Status, r.BlobHash, r.OutputHash, timestamp, r.ExecutorID, string(metaJSON), r.Signature, r.MerkleRoot, r.PrevHash, r.LamportClock, r.ArgsHash, r.LogID, r.LeafIndex, nullableJSON(transparencyJSON), string(envelope),
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
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

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

	last, err := queryLastSQLiteCausalReceipt(ctx, conn, sessionID)
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
	query := `SELECT ` + sqliteReceiptColumns + ` FROM receipts WHERE executor_id = ? ORDER BY lamport_clock DESC LIMIT 1`
	r, err := scanSQLiteReceipt(queryer.QueryRowContext(ctx, query, sessionID))
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return r, nil
}

// queryLastSQLiteCausalReceipt refuses to extend a legacy row whose omitted
// contract fields cannot be reconstructed. Reading legacy receipts remains
// supported, but inventing a new PrevHash from a lossy projection would create
// an unverifiable causal edge.
func queryLastSQLiteCausalReceipt(ctx context.Context, queryer sqlQueryer, sessionID string) (*contracts.Receipt, error) {
	last, err := queryLastSQLiteReceipt(ctx, queryer, sessionID)
	if err != nil || last == nil {
		return last, err
	}
	var envelope sql.NullString
	if err := queryer.QueryRowContext(ctx, `SELECT receipt_envelope FROM receipts WHERE executor_id = ? ORDER BY lamport_clock DESC LIMIT 1`, sessionID).Scan(&envelope); err != nil {
		return nil, err
	}
	if !envelope.Valid || envelope.String == "" {
		return nil, fmt.Errorf("cannot append causal receipt after legacy receipt without a canonical envelope")
	}
	return last, nil
}

func (s *SQLiteReceiptStore) queryOne(ctx context.Context, query string, arg any) (*contracts.Receipt, error) {
	row := s.db.QueryRowContext(ctx, query, arg)
	var (
		receiptID    string
		decisionID   string
		effectID     string
		externalID   sql.NullString
		status       string
		blobHash     string
		outputHash   string
		timestamp    string
		executorID   sql.NullString
		metaJSON     sql.NullString
		signature    sql.NullString
		merkleRoot   sql.NullString
		prevHash     sql.NullString
		lamport      uint64
		argsHash     sql.NullString
		logID        sql.NullString
		leafIndex    uint64
		transparency sql.NullString
		envelope     sql.NullString
	)
	err := row.Scan(&receiptID, &decisionID, &effectID, &externalID, &status, &blobHash, &outputHash, &timestamp, &executorID, &metaJSON, &signature, &merkleRoot, &prevHash, &lamport, &argsHash, &logID, &leafIndex, &transparency, &envelope)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("receipt not found")
		}
		return nil, err
	}
	return receiptFromSQLiteFields(receiptID, decisionID, effectID, externalID, status, blobHash, outputHash, timestamp, executorID, metaJSON, signature, merkleRoot, prevHash, lamport, argsHash, logID, leafIndex, transparency, envelope)
}

type sqliteScanner interface {
	Scan(dest ...any) error
}

func scanSQLiteReceipt(scanner sqliteScanner) (*contracts.Receipt, error) {
	var (
		receiptID    string
		decisionID   string
		effectID     string
		externalID   sql.NullString
		status       string
		blobHash     string
		outputHash   string
		timestamp    string
		executorID   sql.NullString
		metaJSON     sql.NullString
		signature    sql.NullString
		merkleRoot   sql.NullString
		prevHash     sql.NullString
		lamport      uint64
		argsHash     sql.NullString
		logID        sql.NullString
		leafIndex    uint64
		transparency sql.NullString
		envelope     sql.NullString
	)
	if err := scanner.Scan(&receiptID, &decisionID, &effectID, &externalID, &status, &blobHash, &outputHash, &timestamp, &executorID, &metaJSON, &signature, &merkleRoot, &prevHash, &lamport, &argsHash, &logID, &leafIndex, &transparency, &envelope); err != nil {
		return nil, err
	}
	return receiptFromSQLiteFields(receiptID, decisionID, effectID, externalID, status, blobHash, outputHash, timestamp, executorID, metaJSON, signature, merkleRoot, prevHash, lamport, argsHash, logID, leafIndex, transparency, envelope)
}

func receiptFromSQLiteFields(receiptID, decisionID, effectID string, externalID sql.NullString, status, blobHash, outputHash, timestamp string, executorID, metaJSON, signature, merkleRoot, prevHash sql.NullString, lamport uint64, argsHash sql.NullString, logID sql.NullString, leafIndex uint64, transparency, envelope sql.NullString) (*contracts.Receipt, error) {
	parsedTime := parseTime(timestamp)

	var meta map[string]any
	if metaJSON.Valid && metaJSON.String != "" && metaJSON.String != "null" {
		if err := json.Unmarshal([]byte(metaJSON.String), &meta); err != nil {
			return nil, fmt.Errorf("decode receipt metadata: %w", err)
		}
	}

	receipt := &contracts.Receipt{
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
		LogID:               logID.String,
		LeafIndex:           leafIndex,
	}
	if transparency.Valid {
		if err := decodeTransparencyAnchor([]byte(transparency.String), receipt); err != nil {
			return nil, err
		}
	}
	return receiptFromSQLiteEnvelope(envelope, receipt, metaJSON, transparency)
}

// receiptFromSQLiteEnvelope restores the canonical receipt representation
// written by current stores. The indexed columns remain for lookup and legacy
// databases, but cannot on their own reproduce ReceiptChainHash because that
// hash covers the full Receipt contract.
func receiptFromSQLiteEnvelope(envelope sql.NullString, projected *contracts.Receipt, metadata, transparency sql.NullString) (*contracts.Receipt, error) {
	if !envelope.Valid || envelope.String == "" {
		return projected, nil
	}

	decoder := json.NewDecoder(strings.NewReader(envelope.String))
	decoder.UseNumber()
	var receipt contracts.Receipt
	if err := decoder.Decode(&receipt); err != nil {
		return nil, fmt.Errorf("decode receipt envelope: %w", err)
	}
	canonical, err := canonicalize.JCS(&receipt)
	if err != nil {
		return nil, fmt.Errorf("canonicalize receipt envelope: %w", err)
	}
	if !bytes.Equal(canonical, []byte(envelope.String)) {
		return nil, fmt.Errorf("receipt envelope is not canonical")
	}
	if err := validateSQLiteReceiptEnvelopeProjection(&receipt, projected, metadata, transparency); err != nil {
		return nil, err
	}
	return &receipt, nil
}

// validateSQLiteReceiptEnvelopeProjection makes an envelope/index mismatch a
// read error instead of allowing a query to return one receipt while causal
// chaining hashes another.
func validateSQLiteReceiptEnvelopeProjection(envelope, projected *contracts.Receipt, metadata, transparency sql.NullString) error {
	if envelope == nil || projected == nil {
		return fmt.Errorf("receipt envelope and projection are required")
	}
	if envelope.ReceiptID != projected.ReceiptID ||
		envelope.DecisionID != projected.DecisionID ||
		envelope.EffectID != projected.EffectID ||
		envelope.ExternalReferenceID != projected.ExternalReferenceID ||
		envelope.Status != projected.Status ||
		envelope.BlobHash != projected.BlobHash ||
		envelope.OutputHash != projected.OutputHash ||
		!envelope.Timestamp.Equal(projected.Timestamp) ||
		envelope.ExecutorID != projected.ExecutorID ||
		envelope.Signature != projected.Signature ||
		envelope.MerkleRoot != projected.MerkleRoot ||
		envelope.PrevHash != projected.PrevHash ||
		envelope.LamportClock != projected.LamportClock ||
		envelope.ArgsHash != projected.ArgsHash ||
		envelope.LogID != projected.LogID ||
		envelope.LeafIndex != projected.LeafIndex {
		return fmt.Errorf("receipt envelope does not match indexed columns")
	}
	metadataMatches, err := sqliteReceiptJSONMatchesRaw(envelope.Metadata, metadata)
	if err != nil {
		return fmt.Errorf("canonicalize receipt metadata: %w", err)
	}
	if !metadataMatches {
		return fmt.Errorf("receipt envelope metadata does not match indexed columns")
	}
	transparencyMatches, err := sqliteReceiptJSONMatchesRaw(envelope.Transparency, transparency)
	if err != nil {
		return fmt.Errorf("canonicalize receipt transparency: %w", err)
	}
	if !transparencyMatches {
		return fmt.Errorf("receipt envelope transparency does not match indexed columns")
	}
	return nil
}

func sqliteReceiptJSONMatchesRaw(value any, raw sql.NullString) (bool, error) {
	valueCanonical, err := canonicalize.JCS(value)
	if err != nil {
		return false, err
	}
	if !raw.Valid || raw.String == "" {
		return bytes.Equal(valueCanonical, []byte("null")), nil
	}
	decoder := json.NewDecoder(strings.NewReader(raw.String))
	decoder.UseNumber()
	var stored any
	if err := decoder.Decode(&stored); err != nil {
		return false, err
	}
	storedCanonical, err := canonicalize.JCS(stored)
	if err != nil {
		return false, err
	}
	return bytes.Equal(valueCanonical, storedCanonical), nil
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
