package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

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
// session chain and assigned its next Lamport clock and previous hash. It is
// an alias so consumers can detect the optional atomic append capability
// without importing this package (which would create an executor/store cycle).
type CausalReceiptBuilder = func(previous *contracts.Receipt, lamport uint64, prevHash string) (*contracts.Receipt, error)

// TenantScopedCausalReceiptAppender allocates a causal receipt position under
// a durable tenant-qualified lookup key. The receipt's signed SessionID stays
// caller-visible; only the database key is qualified.
type TenantScopedCausalReceiptAppender interface {
	AppendCausalScoped(ctx context.Context, tenantID, sessionID string, build CausalReceiptBuilder) error
}

// TenantScopedReceiptReader exposes read operations that are constrained by an
// authenticated tenant and a V5 signed receipt session. Public runtime routes
// must use this capability instead of executor-oriented legacy queries.
// Implementations intentionally exclude unscoped and pre-V5 receipts: their
// tenant provenance cannot be reconstructed safely at read time.
type TenantScopedReceiptReader interface {
	GetByReceiptIDForTenant(ctx context.Context, tenantID, receiptID string) (*contracts.Receipt, error)
	ListByTenant(ctx context.Context, tenantID string, since uint64, limit int) ([]*contracts.Receipt, error)
	ListByTenantSession(ctx context.Context, tenantID, sessionID string, since uint64, limit int) ([]*contracts.Receipt, error)
}

// TenantReceiptCursor is the stable opaque position for a tenant-wide V5
// receipt listing. ReceiptID resolves to the store's durable append sequence;
// LamportClock and Timestamp remain in the v1 cursor wire format for
// compatibility, but cannot order receipts across signed sessions.
type TenantReceiptCursor struct {
	LamportClock uint64
	Timestamp    time.Time
	ReceiptID    string
}

// TenantScopedReceiptCursorReader is an additive capability for tenant-wide
// keyset pagination. Runtime tenant routes must require this interface rather
// than falling back to the legacy scalar-Lamport ListByTenant method, because
// a scalar cursor can skip equal-clock receipts from other signed sessions.
type TenantScopedReceiptCursorReader interface {
	ListByTenantCursor(ctx context.Context, tenantID string, cursor TenantReceiptCursor, limit int) ([]*contracts.Receipt, error)
}

// ReceiptTimestampNormalizer exposes a store's durable timestamp precision to
// producers. A producer must normalize before it signs or anchors a receipt
// whose chain hash will later be reloaded from that store.
type ReceiptTimestampNormalizer interface {
	NormalizeReceiptTimestamp(time.Time) time.Time
}

// causalReceiptSessionID selects the durable lookup scope without changing the
// receipt envelope. V5 signs SessionID; legacy receipts retain ExecutorID as
// their historical causal scope.
func causalReceiptSessionID(r *contracts.Receipt) string {
	if r == nil {
		return ""
	}
	if r.SignatureVersion == contracts.ReceiptSignatureV5 {
		return r.SessionID
	}
	return r.ExecutorID
}

// causalReceiptScopeKey keeps an authenticated tenant out of the signed
// receipt envelope while giving durable stores an unambiguous lookup key. The
// length framing avoids collisions between arbitrary tenant/session strings.
func causalReceiptScopeKey(tenantID, sessionID string) string {
	return fmt.Sprintf("tenant:%d:%s:session:%d:%s", len(tenantID), tenantID, len(sessionID), sessionID)
}

// causalReceiptTenantScopePrefix is the stable, length-framed prefix shared
// by every authenticated session for a tenant. It is used only in durable
// lookup predicates; the signed receipt envelope keeps the external session
// identifier unchanged.
func causalReceiptTenantScopePrefix(tenantID string) string {
	return fmt.Sprintf("tenant:%d:%s:session:", len(tenantID), tenantID)
}

const backfillCausalReceiptSessionsSQL = `
	UPDATE receipts
	SET causal_session_id = CASE
		WHEN COALESCE(signature_version, '') = 'receipt.v5' THEN COALESCE(session_id, '')
		ELSE COALESCE(executor_id, '')
	END
	WHERE COALESCE(causal_session_id, '') = '';
`

// backfillReceiptDecisionHashSQL recovers the V5 semantic decision hash from
// the metadata field that the first V5 API writers already persisted. Rows
// without that trusted source intentionally remain empty: read paths reject
// them instead of silently returning an incomplete required V5 field.
const backfillReceiptDecisionHashSQL = `
	UPDATE receipts
	SET decision_hash = metadata->>'decision_hash'
	WHERE COALESCE(signature_version, '') = 'receipt.v5'
	  AND COALESCE(decision_hash, '') = ''
	  AND metadata IS NOT NULL
	  AND NULLIF(metadata->>'decision_hash', '') IS NOT NULL;
`

// Historical receipts did not persist a tenant-wide append position. Give
// those rows one deterministic baseline before new receipts receive the
// database sequence default. Timestamp and receipt ID are only a migration
// tie-breaker; all post-migration tenant cursor reads use append_sequence.
const backfillReceiptAppendSequenceSQL = `
	WITH missing AS (
		SELECT receipt_id,
			COALESCE((SELECT MAX(append_sequence) FROM receipts), 0)
				+ ROW_NUMBER() OVER (ORDER BY timestamp ASC NULLS FIRST, receipt_id ASC) AS append_sequence
		FROM receipts
		WHERE COALESCE(append_sequence, 0) = 0
	)
	UPDATE receipts AS target
	SET append_sequence = missing.append_sequence
	FROM missing
	WHERE target.receipt_id = missing.receipt_id;
`

const syncReceiptAppendSequenceSQL = `
	SELECT setval(
		'receipts_append_sequence_seq',
		COALESCE((SELECT MAX(append_sequence) + 1 FROM receipts), 1),
		false
	);
`

// PostgresReceiptStore is a durable SQL-based implementation.
type PostgresReceiptStore struct {
	db *sql.DB
}

func NewPostgresReceiptStore(db *sql.DB) *PostgresReceiptStore {
	return &PostgresReceiptStore{db: db}
}

func (s *PostgresReceiptStore) Init(ctx context.Context) error {
	schemaQuery := `
		CREATE SEQUENCE IF NOT EXISTS receipts_append_sequence_seq AS BIGINT;
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
			decision_hash TEXT DEFAULT '',
			args_hash TEXT DEFAULT '',
			signature_version TEXT DEFAULT '',
			verdict TEXT DEFAULT '',
			reason_code TEXT DEFAULT '',
			policy_hash TEXT DEFAULT '',
			session_id TEXT DEFAULT '',
			causal_session_id TEXT DEFAULT '',
			blob_hash TEXT DEFAULT '',
			log_id TEXT DEFAULT '',
			leaf_index BIGINT DEFAULT 0,
			transparency JSONB,
			key_id TEXT DEFAULT '',
			public_key_set JSONB,
			signature_profile TEXT DEFAULT '',
			signature_algorithm TEXT DEFAULT '',
			correlation_id TEXT DEFAULT '',
			append_sequence BIGINT NOT NULL DEFAULT nextval('receipts_append_sequence_seq')
		);
		ALTER TABLE receipts ADD COLUMN IF NOT EXISTS effect_id TEXT;
		ALTER TABLE receipts ADD COLUMN IF NOT EXISTS external_reference_id TEXT;
		ALTER TABLE receipts ADD COLUMN IF NOT EXISTS metadata JSONB;
		ALTER TABLE receipts ADD COLUMN IF NOT EXISTS signature TEXT;
		ALTER TABLE receipts ADD COLUMN IF NOT EXISTS merkle_root TEXT;
		ALTER TABLE receipts ADD COLUMN IF NOT EXISTS output_hash TEXT DEFAULT '';
		ALTER TABLE receipts ADD COLUMN IF NOT EXISTS decision_hash TEXT DEFAULT '';
		ALTER TABLE receipts ADD COLUMN IF NOT EXISTS args_hash TEXT DEFAULT '';
		ALTER TABLE receipts ADD COLUMN IF NOT EXISTS signature_version TEXT DEFAULT '';
		ALTER TABLE receipts ADD COLUMN IF NOT EXISTS verdict TEXT DEFAULT '';
		ALTER TABLE receipts ADD COLUMN IF NOT EXISTS reason_code TEXT DEFAULT '';
		ALTER TABLE receipts ADD COLUMN IF NOT EXISTS policy_hash TEXT DEFAULT '';
		ALTER TABLE receipts ADD COLUMN IF NOT EXISTS session_id TEXT DEFAULT '';
		ALTER TABLE receipts ADD COLUMN IF NOT EXISTS causal_session_id TEXT DEFAULT '';
		ALTER TABLE receipts ADD COLUMN IF NOT EXISTS blob_hash TEXT DEFAULT '';
		ALTER TABLE receipts ADD COLUMN IF NOT EXISTS key_id TEXT DEFAULT '';
		ALTER TABLE receipts ADD COLUMN IF NOT EXISTS public_key_set JSONB;
		ALTER TABLE receipts ADD COLUMN IF NOT EXISTS signature_profile TEXT DEFAULT '';
		ALTER TABLE receipts ADD COLUMN IF NOT EXISTS signature_algorithm TEXT DEFAULT '';
		ALTER TABLE receipts ADD COLUMN IF NOT EXISTS correlation_id TEXT DEFAULT '';
		ALTER TABLE receipts ADD COLUMN IF NOT EXISTS append_sequence BIGINT;
		ALTER TABLE receipts ALTER COLUMN append_sequence SET DEFAULT nextval('receipts_append_sequence_seq');
		ALTER SEQUENCE receipts_append_sequence_seq OWNED BY receipts.append_sequence;
		ALTER TABLE receipts ADD COLUMN IF NOT EXISTS log_id TEXT DEFAULT '';
		ALTER TABLE receipts ADD COLUMN IF NOT EXISTS leaf_index BIGINT DEFAULT 0;
		ALTER TABLE receipts ADD COLUMN IF NOT EXISTS transparency JSONB;
	`
	if _, err := s.db.ExecContext(ctx, schemaQuery); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, backfillReceiptDecisionHashSQL); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, backfillCausalReceiptSessionsSQL); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, backfillReceiptAppendSequenceSQL); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, syncReceiptAppendSequenceSQL); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `ALTER TABLE receipts ALTER COLUMN append_sequence SET NOT NULL`); err != nil {
		return err
	}
	indexQuery := `
		CREATE INDEX IF NOT EXISTS idx_receipts_executor_id ON receipts(executor_id);
		CREATE INDEX IF NOT EXISTS idx_receipts_decision_id ON receipts(decision_id);
		CREATE INDEX IF NOT EXISTS idx_receipts_executor_lamport ON receipts(executor_id, lamport_clock);
		CREATE INDEX IF NOT EXISTS idx_receipts_executor_lamport_desc ON receipts(executor_id, lamport_clock DESC);
		DROP INDEX IF EXISTS idx_receipts_executor_lamport_unique;
		DROP INDEX IF EXISTS idx_receipts_session_lamport_unique;
		DROP INDEX IF EXISTS idx_receipts_session_lamport_desc;
		CREATE UNIQUE INDEX IF NOT EXISTS idx_receipts_causal_session_lamport_unique ON receipts(causal_session_id, lamport_clock)
			WHERE causal_session_id IS NOT NULL AND causal_session_id <> '' AND lamport_clock > 0;
		CREATE INDEX IF NOT EXISTS idx_receipts_causal_session_lamport_desc ON receipts(causal_session_id, lamport_clock DESC);
		CREATE INDEX IF NOT EXISTS idx_receipts_lamport_timestamp ON receipts(lamport_clock, timestamp);
		CREATE INDEX IF NOT EXISTS idx_receipts_timestamp ON receipts(timestamp);
		CREATE UNIQUE INDEX IF NOT EXISTS idx_receipts_append_sequence_unique ON receipts(append_sequence);
	`
	_, err := s.db.ExecContext(ctx, indexQuery)
	return err
}

// receiptColumns is the canonical column list for receipt queries.
const receiptColumns = `receipt_id, decision_id, COALESCE(effect_id, execution_intent_id, '') AS effect_id, COALESCE(external_reference_id, '') AS external_reference_id, status, blob_hash, output_hash, COALESCE(decision_hash, '') AS decision_hash, timestamp, COALESCE(executor_id, '') AS executor_id, metadata, signature, merkle_root, COALESCE(prev_hash, '') AS prev_hash, COALESCE(lamport_clock, 0) AS lamport_clock, args_hash, COALESCE(signature_version, '') AS signature_version, COALESCE(verdict, '') AS verdict, COALESCE(reason_code, '') AS reason_code, COALESCE(policy_hash, '') AS policy_hash, COALESCE(session_id, '') AS session_id, COALESCE(log_id, '') AS log_id, COALESCE(leaf_index, 0) AS leaf_index, transparency, COALESCE(key_id, '') AS key_id, public_key_set, COALESCE(signature_profile, '') AS signature_profile, COALESCE(signature_algorithm, '') AS signature_algorithm, COALESCE(correlation_id, '') AS correlation_id`

func (s *PostgresReceiptStore) Get(ctx context.Context, decisionID string) (*contracts.Receipt, error) {
	query := `SELECT ` + receiptColumns + ` FROM receipts WHERE decision_id = $1`
	return s.queryOne(ctx, query, decisionID)
}

func (s *PostgresReceiptStore) GetByReceiptID(ctx context.Context, receiptID string) (*contracts.Receipt, error) {
	query := `SELECT ` + receiptColumns + ` FROM receipts WHERE receipt_id = $1`
	return s.queryOne(ctx, query, receiptID)
}

// GetByReceiptIDForTenant returns only a V5 receipt persisted through the
// authenticated tenant scope. Legacy/unscoped receipts fail closed rather than
// being guessed into a tenant from caller-controlled data.
func (s *PostgresReceiptStore) GetByReceiptIDForTenant(ctx context.Context, tenantID, receiptID string) (*contracts.Receipt, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, fmt.Errorf("tenant id is required")
	}
	prefix := causalReceiptTenantScopePrefix(tenantID)
	query := `SELECT ` + receiptColumns + ` FROM receipts
		WHERE receipt_id = $1
		  AND signature_version = $2
		  AND COALESCE(session_id, '') <> ''
		  AND left(causal_session_id, char_length($3)) = $3`
	return s.queryOne(ctx, query, receiptID, contracts.ReceiptSignatureV5, prefix)
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

// ListByTenant lists only V5 receipts with durable authenticated tenant
// provenance. It deliberately does not fall back to executor_id.
func (s *PostgresReceiptStore) ListByTenant(ctx context.Context, tenantID string, since uint64, limit int) ([]*contracts.Receipt, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, fmt.Errorf("tenant id is required")
	}
	prefix := causalReceiptTenantScopePrefix(tenantID)
	query := `SELECT ` + receiptColumns + ` FROM receipts
		WHERE signature_version = $1
		  AND COALESCE(session_id, '') <> ''
		  AND left(causal_session_id, char_length($2)) = $2
		  AND lamport_clock > $3
		ORDER BY lamport_clock ASC, timestamp ASC LIMIT $4`
	return s.queryReceipts(ctx, query, contracts.ReceiptSignatureV5, prefix, since, limit)
}

// ListByTenantCursor returns V5 receipts in durable append order. The opaque
// cursor's receipt ID is resolved inside the authenticated tenant scope, so
// later session genesis receipts are never compared to another session's
// Lamport clock.
func (s *PostgresReceiptStore) ListByTenantCursor(ctx context.Context, tenantID string, cursor TenantReceiptCursor, limit int) ([]*contracts.Receipt, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, fmt.Errorf("tenant id is required")
	}
	cursor.ReceiptID = strings.TrimSpace(cursor.ReceiptID)
	if cursor.ReceiptID != "" && cursor.Timestamp.IsZero() {
		return nil, fmt.Errorf("tenant receipt cursor timestamp is required")
	}
	prefix := causalReceiptTenantScopePrefix(tenantID)
	query := `SELECT ` + receiptColumns + ` FROM receipts
		WHERE signature_version = $1
		  AND COALESCE(session_id, '') <> ''
		  AND left(causal_session_id, char_length($2)) = $2`
	args := []any{contracts.ReceiptSignatureV5, prefix}
	if cursor.ReceiptID != "" {
		query += `
		  AND append_sequence > (
			SELECT cursor_receipt.append_sequence
			FROM receipts AS cursor_receipt
			WHERE cursor_receipt.receipt_id = $3
			  AND cursor_receipt.signature_version = $1
			  AND COALESCE(cursor_receipt.session_id, '') <> ''
			  AND left(cursor_receipt.causal_session_id, char_length($2)) = $2
		)`
		args = append(args, cursor.ReceiptID)
	}
	query += fmt.Sprintf("\n\t\tORDER BY append_sequence ASC LIMIT $%d", len(args)+1)
	args = append(args, limit)
	return s.queryReceipts(ctx, query, args...)
}

// ListByTenantSession returns the receipt chain keyed by the signed
// Receipt.SessionID inside an authenticated tenant scope.
func (s *PostgresReceiptStore) ListByTenantSession(ctx context.Context, tenantID, sessionID string, since uint64, limit int) ([]*contracts.Receipt, error) {
	tenantID = strings.TrimSpace(tenantID)
	sessionID = strings.TrimSpace(sessionID)
	if tenantID == "" {
		return nil, fmt.Errorf("tenant id is required")
	}
	if sessionID == "" {
		return nil, fmt.Errorf("session id is required")
	}
	query := `SELECT ` + receiptColumns + ` FROM receipts
		WHERE causal_session_id = $1
		  AND session_id = $2
		  AND signature_version = $3
		  AND lamport_clock > $4
		ORDER BY lamport_clock ASC, timestamp ASC LIMIT $5`
	return s.queryReceipts(ctx, query, causalReceiptScopeKey(tenantID, sessionID), sessionID, contracts.ReceiptSignatureV5, since, limit)
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

func (s *PostgresReceiptStore) queryReceipts(ctx context.Context, query string, args ...any) ([]*contracts.Receipt, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
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
	var publicKeySet []byte
	err := s.Scan(
		&r.ReceiptID, &r.DecisionID, &r.EffectID, &r.ExternalReferenceID, &r.Status,
		&r.BlobHash, &r.OutputHash, &r.DecisionHash, &r.Timestamp, &r.ExecutorID, &metadata, &signature,
		&merkleRoot, &r.PrevHash, &r.LamportClock, &r.ArgsHash, &r.SignatureVersion, &r.Verdict, &r.ReasonCode, &r.PolicyHash, &r.SessionID, &r.LogID, &r.LeafIndex, &transparency,
		&r.KeyID, &publicKeySet, &r.SignatureProfile, &r.SignatureAlgorithm, &r.CorrelationID,
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
	// The signer's own identity must survive persistence: without these columns
	// a signature covering them could never match a reloaded receipt, which is
	// what blocked the v5 envelope (F-05).
	if len(publicKeySet) > 0 && string(publicKeySet) != "null" {
		if err := json.Unmarshal(publicKeySet, &r.PublicKeySet); err != nil {
			return nil, fmt.Errorf("decode receipt public_key_set: %w", err)
		}
	}
	r.Signature = signature.String
	r.MerkleRoot = merkleRoot.String
	if err := restoreOrRejectV5DecisionHash(&r); err != nil {
		return nil, err
	}
	return &r, nil
}

// restoreOrRejectV5DecisionHash makes the V5 semantic decision hash durable
// across the storage gap that predated its dedicated column. The metadata
// fallback is deliberately limited to the exact value persisted by early V5
// API writers; output_hash is not a safe general substitute. A V5 row that
// cannot be recovered is not a complete receipt and must fail closed.
func restoreOrRejectV5DecisionHash(r *contracts.Receipt) error {
	if r == nil || r.SignatureVersion != contracts.ReceiptSignatureV5 {
		return nil
	}
	if r.DecisionHash = strings.TrimSpace(r.DecisionHash); r.DecisionHash != "" {
		return nil
	}
	if r.Metadata != nil {
		if value, ok := r.Metadata["decision_hash"].(string); ok {
			if value = strings.TrimSpace(value); value != "" {
				r.DecisionHash = value
				return nil
			}
		}
	}
	return fmt.Errorf("receipt %q declares %s but has no durable decision_hash; apply 004_add_receipt_decision_hash.sql and restore it from a trusted decision record", r.ReceiptID, contracts.ReceiptSignatureV5)
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

func (s *PostgresReceiptStore) queryOne(ctx context.Context, query string, args ...any) (*contracts.Receipt, error) {
	row := s.db.QueryRowContext(ctx, query, args...)
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
	s.normalizeReceiptTimestamp(r)
	if err := insertPostgresReceipt(ctx, s.db, r); err != nil {
		return err
	}
	return nil
}

type sqlExecer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func insertPostgresReceipt(ctx context.Context, execer sqlExecer, r *contracts.Receipt) error {
	return insertPostgresReceiptWithCausalSession(ctx, execer, r, causalReceiptSessionID(r))
}

func insertPostgresReceiptWithCausalSession(ctx context.Context, execer sqlExecer, r *contracts.Receipt, causalSessionID string) error {
	if err := restoreOrRejectV5DecisionHash(r); err != nil {
		return err
	}
	query := `
		INSERT INTO receipts (
			receipt_id, decision_id, effect_id, external_reference_id, status, result, timestamp, executor_id,
			metadata, signature, merkle_root, prev_hash, lamport_clock, output_hash, decision_hash, args_hash, blob_hash,
			signature_version, verdict, reason_code, policy_hash, session_id, causal_session_id, log_id, leaf_index, transparency,
			key_id, public_key_set, signature_profile, signature_algorithm, correlation_id
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26::jsonb,
			$27, $28::jsonb, $29, $30, $31)
	`
	metaJSON, err := json.Marshal(r.Metadata)
	if err != nil {
		return fmt.Errorf("marshal receipt metadata: %w", err)
	}
	transparencyJSON, err := encodeTransparencyAnchor(r)
	if err != nil {
		return err
	}
	publicKeySetJSON, err := encodePublicKeySet(r)
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
		r.MerkleRoot,
		r.PrevHash,
		r.LamportClock,
		r.OutputHash,
		r.DecisionHash,
		r.ArgsHash,
		r.BlobHash,
		r.SignatureVersion,
		r.Verdict,
		r.ReasonCode,
		r.PolicyHash,
		r.SessionID,
		causalSessionID,
		r.LogID,
		r.LeafIndex,
		nullableJSON(transparencyJSON),
		r.KeyID,
		nullableJSON(publicKeySetJSON),
		r.SignatureProfile,
		r.SignatureAlgorithm,
		r.CorrelationID,
	)
	if err != nil {
		return fmt.Errorf("failed to insert receipt: %w", err)
	}
	return nil
}

func (s *PostgresReceiptStore) AppendCausal(ctx context.Context, sessionID string, build CausalReceiptBuilder) error {
	return s.appendCausal(ctx, sessionID, sessionID, build)
}

// AppendCausalScoped preserves the external SessionID in the signed receipt
// while serializing and indexing the chain by its authenticated tenant scope.
func (s *PostgresReceiptStore) AppendCausalScoped(ctx context.Context, tenantID, sessionID string, build CausalReceiptBuilder) error {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return fmt.Errorf("tenant id is required")
	}
	if strings.TrimSpace(sessionID) == "" {
		return fmt.Errorf("session id is required")
	}
	return s.appendCausal(ctx, causalReceiptScopeKey(tenantID, sessionID), sessionID, build)
}

func (s *PostgresReceiptStore) appendCausal(ctx context.Context, causalSessionID, externalSessionID string, build CausalReceiptBuilder) error {
	if build == nil {
		return fmt.Errorf("causal receipt builder is nil")
	}
	if strings.TrimSpace(externalSessionID) == "" {
		return fmt.Errorf("session id is required")
	}
	// Every append, including a local cache hit from a prior process lifetime,
	// must allocate its position from PostgreSQL. The xact-scoped advisory lock
	// serializes writers across store instances before the durable predecessor is
	// read, built, signed, and inserted.
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
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, causalSessionID); err != nil {
		return fmt.Errorf("lock receipt session %s: %w", causalSessionID, err)
	}
	last, err := queryLastPostgresReceipt(ctx, tx, causalSessionID)
	if err != nil {
		return err
	}
	receipt, err := buildNextCausalReceiptScoped(causalSessionID, externalSessionID, last, build)
	if err != nil {
		return err
	}
	s.normalizeReceiptTimestamp(receipt)
	if err := insertPostgresReceiptWithCausalSession(ctx, tx, receipt, causalSessionID); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit receipt transaction: %w", err)
	}
	committed = true
	return nil
}

// GetLastForSession returns the most recent receipt for a signed session_id for causal DAG chaining.
func (s *PostgresReceiptStore) GetLastForSession(ctx context.Context, sessionID string) (*contracts.Receipt, error) {
	return queryLastPostgresReceipt(ctx, s.db, sessionID)
}

// NormalizeReceiptTimestamp matches PostgreSQL TIMESTAMPTZ microsecond
// precision. It is intentionally exported as a capability, not a global
// policy: SQLite preserves RFC3339 nanoseconds.
func (s *PostgresReceiptStore) NormalizeReceiptTimestamp(timestamp time.Time) time.Time {
	return timestamp.UTC().Truncate(time.Microsecond)
}

func (s *PostgresReceiptStore) normalizeReceiptTimestamp(r *contracts.Receipt) {
	if r != nil {
		r.Timestamp = s.NormalizeReceiptTimestamp(r.Timestamp)
	}
}

type sqlQueryer interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func queryLastPostgresReceipt(ctx context.Context, queryer sqlQueryer, sessionID string) (*contracts.Receipt, error) {
	query := `SELECT ` + receiptColumns + ` FROM receipts WHERE causal_session_id = $1 ORDER BY lamport_clock DESC LIMIT 1`
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
	return buildNextCausalReceiptScoped(sessionID, sessionID, previous, build)
}

func buildNextCausalReceiptScoped(causalSessionID, externalSessionID string, previous *contracts.Receipt, build CausalReceiptBuilder) (*contracts.Receipt, error) {
	lamport := uint64(1)
	prevHash := ""
	if previous != nil {
		lamport = previous.LamportClock + 1
		hash, err := contracts.ReceiptChainHash(previous)
		if err != nil {
			return nil, fmt.Errorf("hash previous receipt for %s: %w", causalSessionID, err)
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
	// The builder signs the receipt it returns, so assigning a field here would
	// mutate an already-signed object and invalidate any signature that covers
	// it. V5 must set its signed SessionID; legacy receipts keep ExecutorID as
	// their causal identity.
	receiptSessionID := causalReceiptSessionID(receipt)
	if receiptSessionID == "" {
		return nil, fmt.Errorf("causal receipt builder returned no causal session id for session %q", causalSessionID)
	}
	if receiptSessionID != externalSessionID {
		return nil, fmt.Errorf("receipt causal session %q does not match signed session %q", receiptSessionID, externalSessionID)
	}
	if receipt.LamportClock != lamport {
		return nil, fmt.Errorf("receipt lamport %d does not match assigned lamport %d", receipt.LamportClock, lamport)
	}
	if receipt.PrevHash != prevHash {
		return nil, fmt.Errorf("receipt prev_hash %q does not match assigned prev_hash %q", receipt.PrevHash, prevHash)
	}
	return receipt, nil
}

// encodePublicKeySet serialises the receipt's published verification keys for
// storage. A nil map is stored as SQL NULL rather than "null" so a reloaded
// receipt is byte-identical to the one that was signed.
func encodePublicKeySet(r *contracts.Receipt) ([]byte, error) {
	if len(r.PublicKeySet) == 0 {
		return nil, nil
	}
	data, err := json.Marshal(r.PublicKeySet)
	if err != nil {
		return nil, fmt.Errorf("marshal receipt public_key_set: %w", err)
	}
	return data, nil
}
