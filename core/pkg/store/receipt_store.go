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
	db            *sql.DB
	lastMu        sync.Mutex
	lastBySession map[string]*contracts.Receipt
	locksMu       sync.Mutex
	sessionLocks  map[string]*sync.Mutex
}

func NewPostgresReceiptStore(db *sql.DB) *PostgresReceiptStore {
	return &PostgresReceiptStore{
		db:            db,
		lastBySession: map[string]*contracts.Receipt{},
		sessionLocks:  map[string]*sync.Mutex{},
	}
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
			signature_version TEXT DEFAULT '',
			merkle_root TEXT,
			prev_hash TEXT,
			lamport_clock BIGINT,
			output_hash TEXT DEFAULT '',
			args_hash TEXT DEFAULT '',
			blob_hash TEXT DEFAULT '',
			emergency_activation_id TEXT DEFAULT '',
			emergency_delegation_session_id TEXT DEFAULT '',
			emergency_scope_hash TEXT DEFAULT '',
			safe_dep_state TEXT DEFAULT '',
			safe_dep_reason_code TEXT DEFAULT '',
			log_id TEXT DEFAULT '',
			leaf_index BIGINT DEFAULT 0,
			transparency JSONB
		);
		ALTER TABLE receipts ADD COLUMN IF NOT EXISTS effect_id TEXT;
		ALTER TABLE receipts ADD COLUMN IF NOT EXISTS external_reference_id TEXT;
		ALTER TABLE receipts ADD COLUMN IF NOT EXISTS metadata JSONB;
		ALTER TABLE receipts ADD COLUMN IF NOT EXISTS signature TEXT;
		ALTER TABLE receipts ADD COLUMN IF NOT EXISTS signature_version TEXT DEFAULT '';
		ALTER TABLE receipts ADD COLUMN IF NOT EXISTS merkle_root TEXT;
		ALTER TABLE receipts ADD COLUMN IF NOT EXISTS output_hash TEXT DEFAULT '';
		ALTER TABLE receipts ADD COLUMN IF NOT EXISTS args_hash TEXT DEFAULT '';
		ALTER TABLE receipts ADD COLUMN IF NOT EXISTS blob_hash TEXT DEFAULT '';
		ALTER TABLE receipts ADD COLUMN IF NOT EXISTS emergency_activation_id TEXT DEFAULT '';
		ALTER TABLE receipts ADD COLUMN IF NOT EXISTS emergency_delegation_session_id TEXT DEFAULT '';
		ALTER TABLE receipts ADD COLUMN IF NOT EXISTS emergency_scope_hash TEXT DEFAULT '';
		ALTER TABLE receipts ADD COLUMN IF NOT EXISTS safe_dep_state TEXT DEFAULT '';
		ALTER TABLE receipts ADD COLUMN IF NOT EXISTS safe_dep_reason_code TEXT DEFAULT '';
		ALTER TABLE receipts ADD COLUMN IF NOT EXISTS log_id TEXT DEFAULT '';
		ALTER TABLE receipts ADD COLUMN IF NOT EXISTS leaf_index BIGINT DEFAULT 0;
		ALTER TABLE receipts ADD COLUMN IF NOT EXISTS transparency JSONB;
		CREATE INDEX IF NOT EXISTS idx_receipts_executor_id ON receipts(executor_id);
		CREATE INDEX IF NOT EXISTS idx_receipts_decision_id ON receipts(decision_id);
		CREATE INDEX IF NOT EXISTS idx_receipts_executor_lamport ON receipts(executor_id, lamport_clock);
		CREATE INDEX IF NOT EXISTS idx_receipts_executor_lamport_desc ON receipts(executor_id, lamport_clock DESC);
		CREATE UNIQUE INDEX IF NOT EXISTS idx_receipts_executor_lamport_unique ON receipts(executor_id, lamport_clock)
			WHERE executor_id IS NOT NULL AND executor_id <> '' AND lamport_clock > 0;
		CREATE INDEX IF NOT EXISTS idx_receipts_lamport_timestamp ON receipts(lamport_clock, timestamp);
		CREATE INDEX IF NOT EXISTS idx_receipts_timestamp ON receipts(timestamp);
	`
	_, err := s.db.ExecContext(ctx, query)
	return err
}

// receiptColumns is the canonical column list for receipt queries.
const receiptColumns = `receipt_id, decision_id, COALESCE(effect_id, execution_intent_id, '') AS effect_id, COALESCE(external_reference_id, '') AS external_reference_id, status, blob_hash, output_hash, timestamp, COALESCE(executor_id, '') AS executor_id, metadata, signature, COALESCE(signature_version, '') AS signature_version, merkle_root, COALESCE(prev_hash, '') AS prev_hash, COALESCE(lamport_clock, 0) AS lamport_clock, args_hash, COALESCE(emergency_activation_id, '') AS emergency_activation_id, COALESCE(emergency_delegation_session_id, '') AS emergency_delegation_session_id, COALESCE(emergency_scope_hash, '') AS emergency_scope_hash, COALESCE(safe_dep_state, '') AS safe_dep_state, COALESCE(safe_dep_reason_code, '') AS safe_dep_reason_code, COALESCE(log_id, '') AS log_id, COALESCE(leaf_index, 0) AS leaf_index, transparency`

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
	var transparency []byte
	err := s.Scan(
		&r.ReceiptID, &r.DecisionID, &r.EffectID, &r.ExternalReferenceID, &r.Status,
		&r.BlobHash, &r.OutputHash, &r.Timestamp, &r.ExecutorID, &metadata, &signature,
		&r.SignatureVersion, &merkleRoot, &r.PrevHash, &r.LamportClock, &r.ArgsHash,
		&r.EmergencyActivationID, &r.EmergencyDelegationSessionID, &r.EmergencyScopeHash,
		&r.SafeDepState, &r.SafeDepReasonCode, &r.LogID, &r.LeafIndex, &transparency,
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
	return &r, nil
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
	if err := insertPostgresReceipt(ctx, s.db, r); err != nil {
		return err
	}
	s.rememberLastReceipt(r)
	return nil
}

type sqlExecer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func insertPostgresReceipt(ctx context.Context, execer sqlExecer, r *contracts.Receipt) error {
	query := `
		INSERT INTO receipts (
			receipt_id, decision_id, effect_id, external_reference_id, status, result, timestamp, executor_id,
			metadata, signature, signature_version, merkle_root, prev_hash, lamport_clock, output_hash, args_hash, blob_hash,
			emergency_activation_id, emergency_delegation_session_id, emergency_scope_hash, safe_dep_state, safe_dep_reason_code,
			log_id, leaf_index, transparency
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25::jsonb)
	`
	metaJSON, err := json.Marshal(r.Metadata)
	if err != nil {
		return fmt.Errorf("marshal receipt metadata: %w", err)
	}
	transparencyJSON, err := encodeTransparencyAnchor(r)
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
		string(metaJSON),
		r.Signature,
		r.SignatureVersion,
		r.MerkleRoot,
		r.PrevHash,
		r.LamportClock,
		r.OutputHash,
		r.ArgsHash,
		r.BlobHash,
		r.EmergencyActivationID,
		r.EmergencyDelegationSessionID,
		r.EmergencyScopeHash,
		r.SafeDepState,
		r.SafeDepReasonCode,
		r.LogID,
		r.LeafIndex,
		nullableJSON(transparencyJSON),
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

	if last := s.cachedLastReceipt(sessionID); last != nil {
		receipt, err := buildNextCausalReceipt(sessionID, last, build)
		if err != nil {
			return err
		}
		if err := insertPostgresReceipt(ctx, s.db, receipt); err != nil {
			s.forgetLastReceipt(sessionID)
			return err
		}
		s.rememberLastReceipt(receipt)
		return nil
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
	s.rememberLastReceipt(receipt)
	return nil
}

// GetLastForSession returns the most recent receipt for a session (by executor_id) for causal DAG chaining.
func (s *PostgresReceiptStore) GetLastForSession(ctx context.Context, sessionID string) (*contracts.Receipt, error) {
	return queryLastPostgresReceipt(ctx, s.db, sessionID)
}

func (s *PostgresReceiptStore) cachedLastReceipt(sessionID string) *contracts.Receipt {
	s.lastMu.Lock()
	defer s.lastMu.Unlock()
	return cloneReceipt(s.lastBySession[sessionID])
}

func (s *PostgresReceiptStore) rememberLastReceipt(r *contracts.Receipt) {
	if r == nil || r.ExecutorID == "" || r.LamportClock == 0 {
		return
	}
	s.lastMu.Lock()
	defer s.lastMu.Unlock()
	if s.lastBySession == nil {
		s.lastBySession = map[string]*contracts.Receipt{}
	}
	current := s.lastBySession[r.ExecutorID]
	if current == nil || r.LamportClock >= current.LamportClock {
		s.lastBySession[r.ExecutorID] = cloneReceipt(r)
	}
}

func (s *PostgresReceiptStore) forgetLastReceipt(sessionID string) {
	s.lastMu.Lock()
	defer s.lastMu.Unlock()
	delete(s.lastBySession, sessionID)
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
	clone := *r
	if r.Metadata != nil {
		clone.Metadata = make(map[string]any, len(r.Metadata))
		for k, v := range r.Metadata {
			clone.Metadata[k] = v
		}
	}
	return &clone
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
