package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// ReceiptStore defines the interface for persisting and retrieving execution receipts.
type ReceiptStore interface {
	Get(ctx context.Context, decisionID string) (*contracts.Receipt, error)
	GetByReceiptID(ctx context.Context, receiptID string) (*contracts.Receipt, error)
	List(ctx context.Context, limit int) ([]*contracts.Receipt, error)
	ListSince(ctx context.Context, since uint64, limit int) ([]*contracts.Receipt, error)
	ListByAgent(ctx context.Context, agentID string, since uint64, limit int) ([]*contracts.Receipt, error)
	ListBySession(ctx context.Context, sessionID string, since uint64, limit int) ([]*contracts.Receipt, error)
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
	db           *sql.DB
	locksMu      sync.Mutex
	sessionLocks map[string]*sync.Mutex
}

func NewPostgresReceiptStore(db *sql.DB) *PostgresReceiptStore {
	return &PostgresReceiptStore{
		db:           db,
		sessionLocks: map[string]*sync.Mutex{},
	}
}

func (s *PostgresReceiptStore) Init(ctx context.Context) error {
	query := `
		CREATE SEQUENCE IF NOT EXISTS receipts_stream_sequence;
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
			session_id TEXT DEFAULT '',
			metadata JSONB,
			signature TEXT,
			merkle_root TEXT,
			prev_hash TEXT,
			lamport_clock BIGINT,
			stream_sequence BIGINT NOT NULL DEFAULT nextval('receipts_stream_sequence'),
			output_hash TEXT DEFAULT '',
			args_hash TEXT DEFAULT '',
			blob_hash TEXT DEFAULT '',
			log_id TEXT DEFAULT '',
			leaf_index BIGINT DEFAULT 0,
			transparency JSONB,
			receipt_envelope JSONB
		);
		ALTER TABLE receipts ADD COLUMN IF NOT EXISTS effect_id TEXT;
		ALTER TABLE receipts ADD COLUMN IF NOT EXISTS external_reference_id TEXT;
		ALTER TABLE receipts ADD COLUMN IF NOT EXISTS session_id TEXT DEFAULT '';
		ALTER TABLE receipts ADD COLUMN IF NOT EXISTS stream_sequence BIGINT;
		ALTER TABLE receipts ALTER COLUMN stream_sequence SET DEFAULT nextval('receipts_stream_sequence');
		UPDATE receipts SET stream_sequence = nextval('receipts_stream_sequence') WHERE stream_sequence IS NULL;
		SELECT setval(
			'receipts_stream_sequence',
			GREATEST(COALESCE((SELECT MAX(stream_sequence) FROM receipts), 1), 1),
			EXISTS(SELECT 1 FROM receipts WHERE stream_sequence IS NOT NULL)
		);
		ALTER TABLE receipts ADD COLUMN IF NOT EXISTS metadata JSONB;
		ALTER TABLE receipts ADD COLUMN IF NOT EXISTS signature TEXT;
		ALTER TABLE receipts ADD COLUMN IF NOT EXISTS merkle_root TEXT;
		ALTER TABLE receipts ADD COLUMN IF NOT EXISTS output_hash TEXT DEFAULT '';
		ALTER TABLE receipts ADD COLUMN IF NOT EXISTS args_hash TEXT DEFAULT '';
		ALTER TABLE receipts ADD COLUMN IF NOT EXISTS blob_hash TEXT DEFAULT '';
		ALTER TABLE receipts ADD COLUMN IF NOT EXISTS log_id TEXT DEFAULT '';
		ALTER TABLE receipts ADD COLUMN IF NOT EXISTS leaf_index BIGINT DEFAULT 0;
		ALTER TABLE receipts ADD COLUMN IF NOT EXISTS transparency JSONB;
		ALTER TABLE receipts ADD COLUMN IF NOT EXISTS receipt_envelope JSONB;
		CREATE INDEX IF NOT EXISTS idx_receipts_executor_id ON receipts(executor_id);
		CREATE INDEX IF NOT EXISTS idx_receipts_decision_id ON receipts(decision_id);
		CREATE INDEX IF NOT EXISTS idx_receipts_executor_lamport ON receipts(executor_id, lamport_clock);
		CREATE INDEX IF NOT EXISTS idx_receipts_session_lamport ON receipts(session_id, lamport_clock);
		CREATE INDEX IF NOT EXISTS idx_receipts_executor_lamport_desc ON receipts(executor_id, lamport_clock DESC);
		-- Lamport clocks are scoped to a signed session. Retire the historic
		-- executor-based uniqueness guard before installing the correct one.
		DROP INDEX IF EXISTS idx_receipts_executor_lamport_unique;
		CREATE UNIQUE INDEX IF NOT EXISTS idx_receipts_session_lamport_unique ON receipts(session_id, lamport_clock)
			WHERE session_id IS NOT NULL AND session_id <> '' AND lamport_clock > 0;
		CREATE UNIQUE INDEX IF NOT EXISTS idx_receipts_stream_sequence_unique ON receipts(stream_sequence)
			WHERE stream_sequence IS NOT NULL;
		CREATE INDEX IF NOT EXISTS idx_receipts_lamport_timestamp ON receipts(lamport_clock, timestamp);
		CREATE INDEX IF NOT EXISTS idx_receipts_timestamp ON receipts(timestamp);
	`
	_, err := s.db.ExecContext(ctx, query)
	return err
}

// receiptColumns is the canonical column list for receipt queries.
const receiptColumns = `receipt_id, decision_id, COALESCE(effect_id, execution_intent_id, '') AS effect_id, COALESCE(external_reference_id, '') AS external_reference_id, status, blob_hash, output_hash, timestamp, COALESCE(executor_id, '') AS executor_id, metadata, signature, merkle_root, COALESCE(prev_hash, '') AS prev_hash, COALESCE(lamport_clock, 0) AS lamport_clock, COALESCE(stream_sequence, 0) AS stream_sequence, args_hash, COALESCE(log_id, '') AS log_id, COALESCE(leaf_index, 0) AS leaf_index, transparency, COALESCE(session_id, '') AS session_id, receipt_envelope`

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
	query := `SELECT ` + receiptColumns + ` FROM receipts WHERE executor_id = $1 AND stream_sequence > $2 ORDER BY stream_sequence ASC LIMIT $3`
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

// ListBySession returns receipts from one signed session. Unlike executor_id,
// SessionID is part of the v2 receipt envelope and defines the causal chain.
// Historic records predate SessionID; they are readable under their executor
// ID only for migration/export compatibility and are never mixed into a v2
// signed session chain.
func (s *PostgresReceiptStore) ListBySession(ctx context.Context, sessionID string, since uint64, limit int) ([]*contracts.Receipt, error) {
	query := `SELECT ` + receiptColumns + ` FROM receipts WHERE (COALESCE(session_id, '') = $1 OR (COALESCE(session_id, '') = '' AND executor_id = $1)) AND stream_sequence > $2 ORDER BY stream_sequence ASC LIMIT $3`
	rows, err := s.db.QueryContext(ctx, query, sessionID, since, limit)
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
	query := `SELECT ` + receiptColumns + ` FROM receipts WHERE stream_sequence > $1 ORDER BY stream_sequence ASC LIMIT $2`
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
	var transparency []byte
	var envelope []byte
	err := s.Scan(
		&r.ReceiptID, &r.DecisionID, &r.EffectID, &r.ExternalReferenceID, &r.Status,
		&r.BlobHash, &r.OutputHash, &r.Timestamp, &r.ExecutorID, &metadata, &signature,
		&merkleRoot, &r.PrevHash, &r.LamportClock, &r.StreamSequence, &r.ArgsHash, &r.LogID, &r.LeafIndex, &transparency, &r.SessionID, &envelope,
	)
	if err != nil {
		return nil, err
	}
	if len(metadata) > 0 && string(metadata) != "null" {
		if err := json.Unmarshal(metadata, &r.Metadata); err != nil {
			return nil, fmt.Errorf("decode receipt metadata: %w", err)
		}
	}
	if err := decodeTransparencyAnchor(transparency, &r); err != nil {
		return nil, err
	}
	r.Signature = signature.String
	r.MerkleRoot = merkleRoot.String
	if len(envelope) > 0 && string(envelope) != "null" {
		return decodePersistedReceiptEnvelope(envelope, r)
	}
	return &r, nil
}

// encodeReceiptEnvelope persists the complete receipt contract alongside its
// indexed SQL columns. Versioned signatures cover fields far beyond the
// historic column set; rehydrating a v2 receipt from only those columns would
// silently change its signed preimage and break both verification and causal
// chaining. Legacy rows deliberately have a NULL envelope and continue to be
// read through the historic column path.
func encodeReceiptEnvelope(r *contracts.Receipt) ([]byte, error) {
	if r == nil {
		return nil, fmt.Errorf("receipt envelope requires a receipt")
	}
	envelope, err := canonicalize.JCS(r)
	if err != nil {
		return nil, fmt.Errorf("marshal receipt envelope: %w", err)
	}
	return envelope, nil
}

func decodePersistedReceiptEnvelope(raw []byte, indexed contracts.Receipt) (*contracts.Receipt, error) {
	var receipt contracts.Receipt
	if err := json.Unmarshal(raw, &receipt); err != nil {
		return nil, fmt.Errorf("decode receipt envelope: %w", err)
	}
	// The indexed columns drive lookup, ordering, and causal locks. Refuse a
	// mixed row rather than returning an envelope whose signed identity does
	// not match the row selected by those indexes.
	if receipt.ReceiptID != indexed.ReceiptID ||
		receipt.DecisionID != indexed.DecisionID ||
		receipt.EffectID != indexed.EffectID ||
		receipt.ExecutorID != indexed.ExecutorID ||
		receipt.SessionID != indexed.SessionID ||
		receipt.LamportClock != indexed.LamportClock ||
		receipt.Signature != indexed.Signature {
		return nil, fmt.Errorf("persisted receipt envelope does not match indexed receipt identity %q", indexed.ReceiptID)
	}
	// The feed cursor is storage-owned and intentionally excluded from the
	// signed JSON envelope. Preserve the SQL value after envelope rehydration
	// so pagination and SSE never fall back to the session-local Lamport clock.
	receipt.StreamSequence = indexed.StreamSequence
	return &receipt, nil
}

// decodeTransparencyAnchor deserializes the persisted transparency anchor JSON
// onto the receipt. An absent/null column leaves Transparency nil.
func decodeTransparencyAnchor(raw []byte, r *contracts.Receipt) error {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var anchor contracts.TransparencyAnchor
	if err := json.Unmarshal(raw, &anchor); err != nil {
		return fmt.Errorf("decode receipt transparency: %w", err)
	}
	r.Transparency = &anchor
	return nil
}

// encodeTransparencyAnchor serializes the receipt's transparency anchor as
// canonical JSON for persistence. A nil anchor yields a nil byte slice so the
// column is stored as SQL NULL.
func encodeTransparencyAnchor(r *contracts.Receipt) ([]byte, error) {
	if r.Transparency == nil {
		return nil, nil
	}
	encoded, err := canonicalize.JCS(r.Transparency)
	if err != nil {
		return nil, fmt.Errorf("marshal receipt transparency: %w", err)
	}
	return encoded, nil
}

// nullableJSON maps an empty JSON payload to a nil driver value so the column
// is persisted as SQL NULL rather than an empty/invalid JSON string.
func nullableJSON(raw []byte) any {
	if len(raw) == 0 {
		return nil
	}
	return string(raw)
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
			receipt_id, decision_id, effect_id, external_reference_id, status, result, timestamp, executor_id, session_id,
			metadata, signature, merkle_root, prev_hash, lamport_clock, output_hash, args_hash, blob_hash,
			log_id, leaf_index, transparency, receipt_envelope
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20::jsonb, $21::jsonb)
	`
	metaJSON, err := json.Marshal(r.Metadata)
	if err != nil {
		return fmt.Errorf("marshal receipt metadata: %w", err)
	}
	transparencyJSON, err := encodeTransparencyAnchor(r)
	if err != nil {
		return err
	}
	envelope, err := encodeReceiptEnvelope(r)
	if err != nil {
		return err
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
		r.SessionID,
		string(metaJSON),
		r.Signature,
		r.MerkleRoot,
		r.PrevHash,
		r.LamportClock,
		r.OutputHash,
		r.ArgsHash,
		r.BlobHash,
		r.LogID,
		r.LeafIndex,
		nullableJSON(transparencyJSON),
		nullableJSON(envelope),
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
	localLock := s.sessionLock(sessionID)
	localLock.Lock()
	defer localLock.Unlock()

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

// GetLastForSession returns the most recent receipt for a signed session for causal DAG chaining.
func (s *PostgresReceiptStore) GetLastForSession(ctx context.Context, sessionID string) (*contracts.Receipt, error) {
	return queryLastPostgresReceipt(ctx, s.db, sessionID)
}

func (s *PostgresReceiptStore) sessionLock(sessionID string) *sync.Mutex {
	s.locksMu.Lock()
	defer s.locksMu.Unlock()
	if s.sessionLocks == nil {
		s.sessionLocks = map[string]*sync.Mutex{}
	}
	lock := s.sessionLocks[sessionID]
	if lock == nil {
		lock = &sync.Mutex{}
		s.sessionLocks[sessionID] = lock
	}
	return lock
}

func cloneReceipt(r *contracts.Receipt) *contracts.Receipt {
	if r == nil {
		return nil
	}
	if envelope, err := encodeReceiptEnvelope(r); err == nil {
		if cloned, err := decodePersistedReceiptEnvelope(envelope, *r); err == nil {
			return cloned
		}
	}
	clone := *r
	return &clone
}

type sqlQueryer interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func queryLastPostgresReceipt(ctx context.Context, queryer sqlQueryer, sessionID string) (*contracts.Receipt, error) {
	query := `SELECT ` + receiptColumns + ` FROM receipts WHERE COALESCE(session_id, '') = $1 ORDER BY lamport_clock DESC LIMIT 1`
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
	// The callback is allowed to sign the receipt before it returns. Never
	// mutate a field that is part of the v2 signing envelope afterwards: doing
	// so would persist a receipt whose signature cannot verify. The caller must
	// bind the session before signing, and the store only validates that binding
	// while it owns the causal-chain lock.
	if receipt.ExecutorID == "" {
		return nil, fmt.Errorf("receipt executor_id is required for locked session %q", sessionID)
	}
	if receipt.SessionID == "" {
		return nil, fmt.Errorf("receipt session_id is required for locked session %q", sessionID)
	}
	if receipt.SessionID != sessionID {
		return nil, fmt.Errorf("receipt session %q does not match locked session %q", receipt.SessionID, sessionID)
	}
	if receipt.LamportClock != lamport {
		return nil, fmt.Errorf("receipt lamport %d does not match assigned lamport %d", receipt.LamportClock, lamport)
	}
	if receipt.PrevHash != prevHash {
		return nil, fmt.Errorf("receipt prev_hash %q does not match assigned prev_hash %q", receipt.PrevHash, prevHash)
	}
	return receipt, nil
}
