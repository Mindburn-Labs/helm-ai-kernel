package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"

	_ "modernc.org/sqlite"
)

type SQLiteReceiptStore struct {
	db      *sql.DB
	writeMu sync.Mutex
}

// backfillSQLiteReceiptDecisionHashSQL is the SQLite counterpart to the
// PostgreSQL recovery query. It only trusts the decision_hash value early V5
// API writers placed in metadata; unrecoverable rows remain empty and are
// rejected on read rather than being silently projected as complete receipts.
const backfillSQLiteReceiptDecisionHashSQL = `
	UPDATE receipts
	SET decision_hash = json_extract(metadata, '$.decision_hash')
	WHERE COALESCE(signature_version, '') = 'receipt.v5'
	  AND COALESCE(decision_hash, '') = ''
	  AND metadata IS NOT NULL
	  AND json_valid(metadata)
	  AND NULLIF(json_extract(metadata, '$.decision_hash'), '') IS NOT NULL;
`

// SQLite preserves the insertion order of this rowid table. Existing receipt
// rows predate append_sequence, so use that durable local order once; new
// writes allocate max(append_sequence)+1 while SQLite serializes writers.
const backfillSQLiteReceiptAppendSequenceSQL = `
	UPDATE receipts
	SET append_sequence = rowid
	WHERE COALESCE(append_sequence, 0) = 0;
`

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
		{"PRAGMA journal_mode=WAL;", "enable WAL"},
		{"PRAGMA synchronous=NORMAL;", "set synchronous mode"},
		{"PRAGMA busy_timeout=5000;", "set busy timeout"},
		{"PRAGMA temp_store=MEMORY;", "set temp store"},
		{"PRAGMA wal_autocheckpoint=1000;", "set WAL autocheckpoint"},
	}
	for _, pragma := range pragmas {
		if _, err := db.Exec(pragma.stmt); err != nil {
			return nil, fmt.Errorf("%s: %w", pragma.name, err)
		}
	}
	if err := s.migrate(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *SQLiteReceiptStore) migrate() error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	query := `
    CREATE TABLE IF NOT EXISTS receipts (
        receipt_id TEXT PRIMARY KEY,
        decision_id TEXT,
        effect_id TEXT,
        external_reference_id TEXT,
		status TEXT,
		blob_hash TEXT,
		output_hash TEXT,
		decision_hash TEXT NOT NULL DEFAULT '',
		timestamp DATETIME,
		executor_id TEXT,
		metadata JSON,
		signature TEXT,
		merkle_root TEXT,
		prev_hash TEXT NOT NULL DEFAULT '',
		lamport_clock INTEGER NOT NULL DEFAULT 0,
		args_hash TEXT NOT NULL DEFAULT '',
		signature_version TEXT NOT NULL DEFAULT '',
		verdict TEXT NOT NULL DEFAULT '',
		reason_code TEXT NOT NULL DEFAULT '',
		policy_hash TEXT NOT NULL DEFAULT '',
		session_id TEXT NOT NULL DEFAULT '',
		causal_session_id TEXT NOT NULL DEFAULT '',
		log_id TEXT NOT NULL DEFAULT '',
		leaf_index INTEGER NOT NULL DEFAULT 0,
		transparency TEXT,
		key_id TEXT NOT NULL DEFAULT '',
		public_key_set TEXT,
		signature_profile TEXT NOT NULL DEFAULT '',
		signature_algorithm TEXT NOT NULL DEFAULT '',
		correlation_id TEXT NOT NULL DEFAULT '',
		receipt_envelope TEXT,
		chain_hash TEXT NOT NULL DEFAULT '',
		append_sequence INTEGER NOT NULL DEFAULT 0
	);`
	if _, err := s.db.ExecContext(context.Background(), query); err != nil {
		return err
	}
	if err := s.ensureColumn("args_hash", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureColumn("decision_hash", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureColumn("signature_version", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureColumn("verdict", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureColumn("reason_code", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureColumn("policy_hash", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureColumn("session_id", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureColumn("causal_session_id", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureColumn("log_id", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureColumn("leaf_index", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := s.ensureColumn("key_id", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureColumn("public_key_set", "TEXT"); err != nil {
		return err
	}
	if err := s.ensureColumn("signature_profile", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureColumn("signature_algorithm", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureColumn("correlation_id", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureColumn("receipt_envelope", "TEXT"); err != nil {
		return err
	}
	if err := s.ensureColumn("chain_hash", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureColumn("append_sequence", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := s.ensureColumn("transparency", "TEXT"); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(context.Background(), backfillSQLiteReceiptDecisionHashSQL); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(context.Background(), backfillCausalReceiptSessionsSQL); err != nil {
		return err
	}
	if err := s.backfillSQLiteReceiptEnvelopes(context.Background()); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(context.Background(), backfillSQLiteReceiptAppendSequenceSQL); err != nil {
		return err
	}
	indexes := []string{
		`CREATE INDEX IF NOT EXISTS idx_receipts_executor_id ON receipts(executor_id)`,
		`CREATE INDEX IF NOT EXISTS idx_receipts_decision_id ON receipts(decision_id)`,
		`CREATE INDEX IF NOT EXISTS idx_receipts_executor_lamport ON receipts(executor_id, lamport_clock)`,
		`DROP INDEX IF EXISTS idx_receipts_executor_lamport_unique`,
		`DROP INDEX IF EXISTS idx_receipts_session_lamport_unique`,
		`DROP INDEX IF EXISTS idx_receipts_session_lamport_desc`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_receipts_causal_session_lamport_unique ON receipts(causal_session_id, lamport_clock) WHERE causal_session_id IS NOT NULL AND causal_session_id <> '' AND lamport_clock > 0`,
		`CREATE INDEX IF NOT EXISTS idx_receipts_causal_session_lamport_desc ON receipts(causal_session_id, lamport_clock DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_receipts_lamport_timestamp ON receipts(lamport_clock, timestamp)`,
		`CREATE INDEX IF NOT EXISTS idx_receipts_timestamp ON receipts(timestamp)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_receipts_append_sequence_unique ON receipts(append_sequence) WHERE append_sequence > 0`,
		`CREATE TRIGGER IF NOT EXISTS receipts_append_sequence_after_insert
		AFTER INSERT ON receipts
		FOR EACH ROW WHEN COALESCE(NEW.append_sequence, 0) = 0
		BEGIN
			UPDATE receipts
			SET append_sequence = (
				SELECT COALESCE(MAX(append_sequence), 0) + 1
				FROM receipts
				WHERE rowid <> NEW.rowid
			)
			WHERE rowid = NEW.rowid;
		END`,
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

// sqliteReceiptColumns keeps every receipt read path aligned with the durable
// representation. A V5 signature binds the governance fields after args_hash,
// so omitting any one of them on read would make a stored receipt unverifiable.
const sqliteReceiptColumns = `receipt_id, decision_id, effect_id, external_reference_id, status, blob_hash, output_hash, COALESCE(decision_hash, '') AS decision_hash, timestamp, executor_id, metadata, signature, merkle_root, prev_hash, lamport_clock, args_hash, COALESCE(signature_version, '') AS signature_version, COALESCE(verdict, '') AS verdict, COALESCE(reason_code, '') AS reason_code, COALESCE(policy_hash, '') AS policy_hash, COALESCE(session_id, '') AS session_id, log_id, leaf_index, transparency, COALESCE(key_id, '') AS key_id, public_key_set, COALESCE(signature_profile, '') AS signature_profile, COALESCE(signature_algorithm, '') AS signature_algorithm, COALESCE(correlation_id, '') AS correlation_id, receipt_envelope, COALESCE(chain_hash, '') AS chain_hash`

func (s *SQLiteReceiptStore) Get(ctx context.Context, decisionID string) (*contracts.Receipt, error) {
	query := `
		SELECT ` + sqliteReceiptColumns + `
        FROM receipts
        WHERE decision_id = ?
    `
	return s.queryOne(ctx, query, decisionID)
}

// GetByDecisionIDForTenant returns only a V5 receipt whose durable causal
// scope belongs to the authenticated tenant.
func (s *SQLiteReceiptStore) GetByDecisionIDForTenant(ctx context.Context, tenantID, decisionID string) (*contracts.Receipt, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, fmt.Errorf("tenant id is required")
	}
	prefix := causalReceiptTenantScopePrefix(tenantID)
	query := `
		SELECT ` + sqliteReceiptColumns + `
		FROM receipts
		WHERE decision_id = ?
		  AND signature_version = ?
		  AND COALESCE(session_id, '') <> ''
		  AND substr(causal_session_id, 1, length(?)) = ?
	`
	receipt, err := scanSQLiteReceipt(s.db.QueryRowContext(ctx, query, decisionID, contracts.ReceiptSignatureV5, prefix, prefix))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return receipt, err
}

func (s *SQLiteReceiptStore) GetByReceiptID(ctx context.Context, receiptID string) (*contracts.Receipt, error) {
	query := `
		SELECT ` + sqliteReceiptColumns + `
        FROM receipts
        WHERE receipt_id = ?
    `
	return s.queryOne(ctx, query, receiptID)
}

// GetCanonicalReceiptByID returns a complete receipt envelope only after its
// canonical chain hash is reproduced from the stored envelope. It deliberately
// rejects historical projection-only rows whose missing fields cannot be
// reconstructed, while GetByReceiptID continues to expose those projections
// for operational compatibility.
func (s *SQLiteReceiptStore) GetCanonicalReceiptByID(ctx context.Context, receiptID string) (*contracts.Receipt, error) {
	query := `
		SELECT ` + sqliteReceiptColumns + `
		FROM receipts
		WHERE receipt_id = ?
	`
	return s.queryCanonicalOne(ctx, query, receiptID)
}

// GetByReceiptIDForTenant returns only a V5 receipt persisted through the
// authenticated tenant scope. Unscoped legacy records are intentionally not
// surfaced by public tenant routes.
func (s *SQLiteReceiptStore) GetByReceiptIDForTenant(ctx context.Context, tenantID, receiptID string) (*contracts.Receipt, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, fmt.Errorf("tenant id is required")
	}
	prefix := causalReceiptTenantScopePrefix(tenantID)
	query := `
		SELECT ` + sqliteReceiptColumns + `
		FROM receipts
		WHERE receipt_id = ?
		  AND signature_version = ?
		  AND COALESCE(session_id, '') <> ''
		  AND substr(causal_session_id, 1, length(?)) = ?
	`
	return s.queryOne(ctx, query, receiptID, contracts.ReceiptSignatureV5, prefix, prefix)
}

// GetCanonicalReceiptByIDForTenant is the authenticated-scope form of
// GetCanonicalReceiptByID. It never promotes an unscoped legacy row into
// tenant evidence.
func (s *SQLiteReceiptStore) GetCanonicalReceiptByIDForTenant(ctx context.Context, tenantID, receiptID string) (*contracts.Receipt, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, fmt.Errorf("tenant id is required")
	}
	prefix := causalReceiptTenantScopePrefix(tenantID)
	query := `
		SELECT ` + sqliteReceiptColumns + `
		FROM receipts
		WHERE receipt_id = ?
		  AND signature_version = ?
		  AND COALESCE(session_id, '') <> ''
		  AND substr(causal_session_id, 1, length(?)) = ?
	`
	return s.queryCanonicalOne(ctx, query, receiptID, contracts.ReceiptSignatureV5, prefix, prefix)
}

// CountReceipts returns the total number of durably stored receipts.
func (s *SQLiteReceiptStore) CountReceipts(ctx context.Context) (int, error) {
	var count int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM receipts`).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

func (s *SQLiteReceiptStore) List(ctx context.Context, limit int) ([]*contracts.Receipt, error) {
	query := `
		SELECT ` + sqliteReceiptColumns + `
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
		SELECT ` + sqliteReceiptColumns + `
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

// ListByTenant lists only V5 receipts with durable authenticated tenant
// provenance. It deliberately never uses executor_id as a public read scope.
func (s *SQLiteReceiptStore) ListByTenant(ctx context.Context, tenantID string, since uint64, limit int) ([]*contracts.Receipt, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, fmt.Errorf("tenant id is required")
	}
	prefix := causalReceiptTenantScopePrefix(tenantID)
	query := `
		SELECT ` + sqliteReceiptColumns + `
		FROM receipts
		WHERE signature_version = ?
		  AND COALESCE(session_id, '') <> ''
		  AND substr(causal_session_id, 1, length(?)) = ?
		  AND lamport_clock > ?
		ORDER BY lamport_clock ASC, timestamp ASC
		LIMIT ?
	`
	return s.queryReceipts(ctx, query, contracts.ReceiptSignatureV5, prefix, prefix, since, limit)
}

// ListByTenantCursor returns V5 receipts in durable append order. The opaque
// cursor's receipt ID is resolved inside the authenticated tenant scope, so
// later session genesis receipts are never compared to another session's
// Lamport clock.
func (s *SQLiteReceiptStore) ListByTenantCursor(ctx context.Context, tenantID string, cursor TenantReceiptCursor, limit int) ([]*contracts.Receipt, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, fmt.Errorf("tenant id is required")
	}
	cursor.ReceiptID = strings.TrimSpace(cursor.ReceiptID)
	if cursor.ReceiptID != "" && cursor.Timestamp.IsZero() {
		return nil, fmt.Errorf("tenant receipt cursor timestamp is required")
	}
	prefix := causalReceiptTenantScopePrefix(tenantID)
	var appendSequence int64
	if cursor.ReceiptID != "" {
		cursorQuery := `SELECT append_sequence FROM receipts
			WHERE receipt_id = ?
			  AND signature_version = ?
			  AND COALESCE(session_id, '') <> ''
			  AND substr(causal_session_id, 1, length(?)) = ?`
		if err := s.db.QueryRowContext(ctx, cursorQuery, cursor.ReceiptID, contracts.ReceiptSignatureV5, prefix, prefix).Scan(&appendSequence); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, fmt.Errorf("tenant receipt cursor %q is invalid for authenticated tenant", cursor.ReceiptID)
			}
			return nil, fmt.Errorf("resolve tenant receipt cursor: %w", err)
		}
	}
	query := `
		SELECT ` + sqliteReceiptColumns + `
		FROM receipts
		WHERE signature_version = ?
		  AND COALESCE(session_id, '') <> ''
		  AND substr(causal_session_id, 1, length(?)) = ?`
	args := []any{contracts.ReceiptSignatureV5, prefix, prefix}
	if cursor.ReceiptID != "" {
		query += `
		  AND append_sequence > ?`
		args = append(args, appendSequence)
	}
	query += `
		ORDER BY append_sequence ASC
		LIMIT ?
	`
	args = append(args, limit)
	return s.queryReceipts(ctx, query, args...)
}

// ListByTenantSession returns the receipt chain keyed by the signed
// Receipt.SessionID inside an authenticated tenant scope.
func (s *SQLiteReceiptStore) ListByTenantSession(ctx context.Context, tenantID, sessionID string, since uint64, limit int) ([]*contracts.Receipt, error) {
	tenantID = strings.TrimSpace(tenantID)
	sessionID = strings.TrimSpace(sessionID)
	if tenantID == "" {
		return nil, fmt.Errorf("tenant id is required")
	}
	if sessionID == "" {
		return nil, fmt.Errorf("session id is required")
	}
	query := `
		SELECT ` + sqliteReceiptColumns + `
		FROM receipts
		WHERE causal_session_id = ?
		  AND session_id = ?
		  AND signature_version = ?
		  AND lamport_clock > ?
		ORDER BY lamport_clock ASC, timestamp ASC
		LIMIT ?
	`
	return s.queryReceipts(ctx, query, causalReceiptScopeKey(tenantID, sessionID), sessionID, contracts.ReceiptSignatureV5, since, limit)
}

func (s *SQLiteReceiptStore) ListSince(ctx context.Context, since uint64, limit int) ([]*contracts.Receipt, error) {
	query := `
		SELECT ` + sqliteReceiptColumns + `
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

func (s *SQLiteReceiptStore) queryReceipts(ctx context.Context, query string, args ...any) ([]*contracts.Receipt, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
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
	return insertSQLiteReceiptWithCausalSession(ctx, execer, r, causalReceiptSessionID(r))
}

func insertSQLiteReceiptWithCausalSession(ctx context.Context, execer sqlExecer, r *contracts.Receipt, causalSessionID string) error {
	if err := restoreOrRejectV5DecisionHash(r); err != nil {
		return err
	}
	query := `INSERT INTO receipts (
		receipt_id, decision_id, effect_id, external_reference_id, status, blob_hash, output_hash, decision_hash, timestamp, executor_id, metadata, signature, merkle_root, prev_hash, lamport_clock, args_hash, signature_version, verdict, reason_code, policy_hash, session_id, causal_session_id, log_id, leaf_index, transparency, key_id, public_key_set, signature_profile, signature_algorithm, correlation_id, receipt_envelope, chain_hash, append_sequence
	) SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, COALESCE(MAX(append_sequence), 0) + 1 FROM receipts`

	metaJSON, err := json.Marshal(r.Metadata)
	if err != nil {
		return fmt.Errorf("marshal receipt metadata: %w", err)
	}
	chainHash, err := durableReceiptChainHash(r)
	if err != nil {
		return err
	}
	receiptEnvelope, err := durableReceiptEnvelope(r)
	if err != nil {
		return err
	}
	transparencyJSON, err := encodeTransparencyAnchor(r)
	if err != nil {
		return err
	}
	publicKeySetJSON, err := encodePublicKeySet(r)
	if err != nil {
		return err
	}
	timestamp := r.Timestamp.UTC().Format(time.RFC3339Nano)

	_, err = execer.ExecContext(ctx, query,
		r.ReceiptID, r.DecisionID, r.EffectID, r.ExternalReferenceID, r.Status, r.BlobHash, r.OutputHash, r.DecisionHash, timestamp, r.ExecutorID, string(metaJSON), r.Signature, r.MerkleRoot, r.PrevHash, r.LamportClock, r.ArgsHash, r.SignatureVersion, r.Verdict, r.ReasonCode, r.PolicyHash, r.SessionID, causalSessionID, r.LogID, r.LeafIndex, nullableJSON(transparencyJSON), r.KeyID, nullableJSON(publicKeySetJSON), r.SignatureProfile, r.SignatureAlgorithm, r.CorrelationID, string(receiptEnvelope), chainHash,
	)
	if err != nil {
		return fmt.Errorf("failed to insert receipt: %w", err)
	}
	return nil
}

func (s *SQLiteReceiptStore) AppendCausal(ctx context.Context, sessionID string, build CausalReceiptBuilder) error {
	return s.appendCausal(ctx, sessionID, sessionID, build)
}

// PreflightCausalAppend rejects a session whose durable predecessor cannot be
// linked before an external effect is dispatched. It does not reserve a chain
// position; AppendCausal performs the authoritative final allocation.
func (s *SQLiteReceiptStore) PreflightCausalAppend(ctx context.Context, sessionID string) error {
	if strings.TrimSpace(sessionID) == "" {
		return fmt.Errorf("session id is required")
	}
	return s.preflightCausalAppend(ctx, sessionID)
}

// PreflightCausalAppendScoped is the tenant-qualified variant of
// PreflightCausalAppend.
func (s *SQLiteReceiptStore) PreflightCausalAppendScoped(ctx context.Context, tenantID, sessionID string) error {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return fmt.Errorf("tenant id is required")
	}
	if strings.TrimSpace(sessionID) == "" {
		return fmt.Errorf("session id is required")
	}
	return s.preflightCausalAppend(ctx, causalReceiptScopeKey(tenantID, sessionID))
}

// AppendCausalScoped keeps the signed receipt session caller-visible while the
// durable chain key includes the authenticated tenant identity.
func (s *SQLiteReceiptStore) AppendCausalScoped(ctx context.Context, tenantID, sessionID string, build CausalReceiptBuilder) error {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return fmt.Errorf("tenant id is required")
	}
	if strings.TrimSpace(sessionID) == "" {
		return fmt.Errorf("session id is required")
	}
	return s.appendCausal(ctx, causalReceiptScopeKey(tenantID, sessionID), sessionID, build)
}

func (s *SQLiteReceiptStore) preflightCausalAppend(ctx context.Context, causalSessionID string) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("open receipt connection: %w", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return fmt.Errorf("begin receipt preflight transaction: %w", err)
	}
	defer func() { _, _ = conn.ExecContext(context.Background(), "ROLLBACK") }()
	last, lastChainHash, err := queryLastSQLiteReceiptWithChainHash(ctx, conn, causalSessionID)
	if err != nil {
		return err
	}
	return requirePersistedCausalPredecessor(causalSessionID, last, lastChainHash)
}

func (s *SQLiteReceiptStore) appendCausal(ctx context.Context, causalSessionID, externalSessionID string, build CausalReceiptBuilder) error {
	if build == nil {
		return fmt.Errorf("causal receipt builder is nil")
	}
	if strings.TrimSpace(externalSessionID) == "" {
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

	last, lastChainHash, err := queryLastSQLiteReceiptWithChainHash(ctx, conn, causalSessionID)
	if err != nil {
		return err
	}
	receipt, err := buildNextCausalReceiptScoped(causalSessionID, externalSessionID, last, lastChainHash, build)
	if err != nil {
		return err
	}
	if err := insertSQLiteReceiptWithCausalSession(ctx, conn, receipt, causalSessionID); err != nil {
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
	receipt, _, err := queryLastSQLiteReceiptWithChainHash(ctx, queryer, sessionID)
	return receipt, err
}

func queryLastSQLiteReceiptWithChainHash(ctx context.Context, queryer sqlQueryer, sessionID string) (*contracts.Receipt, string, error) {
	query := `
		SELECT ` + sqliteReceiptColumns + `
        FROM receipts
		WHERE causal_session_id = ?
        ORDER BY lamport_clock DESC
        LIMIT 1
    `
	r, chainHash, err := scanSQLiteReceiptWithChainHash(queryer.QueryRowContext(ctx, query, sessionID))
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, "", nil
		}
		return nil, "", err
	}
	return r, chainHash, nil
}

func (s *SQLiteReceiptStore) queryOne(ctx context.Context, query string, args ...any) (*contracts.Receipt, error) {
	receipt, err := scanSQLiteReceipt(s.db.QueryRowContext(ctx, query, args...))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("receipt not found")
		}
		return nil, err
	}
	return receipt, nil
}

func (s *SQLiteReceiptStore) queryCanonicalOne(ctx context.Context, query string, args ...any) (*contracts.Receipt, error) {
	receipt, err := scanCanonicalSQLiteReceipt(s.db.QueryRowContext(ctx, query, args...))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("receipt not found")
		}
		return nil, err
	}
	return receipt, nil
}

type sqliteScanner interface {
	Scan(dest ...any) error
}

func scanSQLiteReceipt(scanner sqliteScanner) (*contracts.Receipt, error) {
	receipt, _, err := scanSQLiteReceiptWithChainHash(scanner)
	return receipt, err
}

func scanSQLiteReceiptWithChainHash(scanner sqliteScanner) (*contracts.Receipt, string, error) {
	return scanSQLiteReceiptWithChainHashMode(scanner, false)
}

func scanCanonicalSQLiteReceipt(scanner sqliteScanner) (*contracts.Receipt, error) {
	receipt, _, err := scanSQLiteReceiptWithChainHashMode(scanner, true)
	return receipt, err
}

func scanSQLiteReceiptWithChainHashMode(scanner sqliteScanner, requireCanonicalEnvelope bool) (*contracts.Receipt, string, error) {
	var (
		receiptID        string
		decisionID       string
		effectID         string
		externalID       sql.NullString
		status           string
		blobHash         string
		outputHash       string
		decisionHash     sql.NullString
		timestamp        string
		executorID       sql.NullString
		metaJSON         sql.NullString
		signature        sql.NullString
		merkleRoot       sql.NullString
		prevHash         sql.NullString
		lamport          uint64
		argsHash         sql.NullString
		signatureVersion sql.NullString
		verdict          sql.NullString
		reasonCode       sql.NullString
		policyHash       sql.NullString
		sessionID        sql.NullString
		logID            sql.NullString
		leafIndex        uint64
		transparency     sql.NullString
		keyID            sql.NullString
		publicKeySet     sql.NullString
		sigProfile       sql.NullString
		sigAlgorithm     sql.NullString
		correlationID    sql.NullString
		receiptEnvelope  sql.NullString
		chainHash        sql.NullString
	)
	if err := scanner.Scan(&receiptID, &decisionID, &effectID, &externalID, &status, &blobHash, &outputHash, &decisionHash, &timestamp, &executorID, &metaJSON, &signature, &merkleRoot, &prevHash, &lamport, &argsHash, &signatureVersion, &verdict, &reasonCode, &policyHash, &sessionID, &logID, &leafIndex, &transparency, &keyID, &publicKeySet, &sigProfile, &sigAlgorithm, &correlationID, &receiptEnvelope, &chainHash); err != nil {
		return nil, "", err
	}
	receipt, err := receiptFromSQLiteFields(receiptID, decisionID, effectID, externalID, status, blobHash, outputHash, decisionHash, timestamp, executorID, metaJSON, signature, merkleRoot, prevHash, lamport, argsHash, signatureVersion, verdict, reasonCode, policyHash, sessionID, logID, leafIndex, transparency, keyID, publicKeySet, sigProfile, sigAlgorithm, correlationID)
	if err != nil {
		return nil, "", err
	}
	var (
		restored   *contracts.Receipt
		restoreErr error
	)
	if requireCanonicalEnvelope {
		restored, restoreErr = restoreCanonicalReceiptEnvelope(receipt, []byte(receiptEnvelope.String), chainHash.String)
	} else {
		restored, restoreErr = restoreReceiptEnvelope(receipt, []byte(receiptEnvelope.String), chainHash.String)
	}
	if restoreErr != nil {
		return nil, "", restoreErr
	}
	return restored, strings.TrimSpace(chainHash.String), nil
}

// backfillSQLiteReceiptEnvelopes performs only provable envelope recovery.
// Its immediate transaction protects the candidate scan and conditional write
// as one local migration step while ordinary readers remain projection-safe.
func (s *SQLiteReceiptStore) backfillSQLiteReceiptEnvelopes(ctx context.Context) error {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("open receipt envelope backfill connection: %w", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		return fmt.Errorf("lock receipt envelope backfill: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.Background(), `ROLLBACK`)
		}
	}()
	rows, err := conn.QueryContext(ctx, `SELECT receipt_id FROM receipts
		WHERE (receipt_envelope IS NULL OR trim(receipt_envelope) = '' OR receipt_envelope = 'null')
		  AND trim(COALESCE(chain_hash, '')) <> ''`)
	if err != nil {
		return fmt.Errorf("select receipt envelope backfill candidates: %w", err)
	}
	var receiptIDs []string
	for rows.Next() {
		var receiptID string
		if scanErr := rows.Scan(&receiptID); scanErr != nil {
			_ = rows.Close()
			return fmt.Errorf("scan receipt envelope backfill candidate: %w", scanErr)
		}
		receiptIDs = append(receiptIDs, receiptID)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return fmt.Errorf("iterate receipt envelope backfill candidates: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close receipt envelope backfill candidates: %w", err)
	}
	var candidates []receiptEnvelopeBackfill
	for _, receiptID := range receiptIDs {
		receipt, chainHash, scanErr := scanSQLiteReceiptWithChainHash(conn.QueryRowContext(ctx, `SELECT `+sqliteReceiptColumns+` FROM receipts WHERE receipt_id = ?`, receiptID))
		if scanErr != nil {
			// Best-effort recovery must not turn an unrelated legacy data gap
			// into an initialization outage. Strict proof reads reject it later.
			continue
		}
		if candidate, ok := receiptEnvelopeBackfillForProjection(receipt, chainHash); ok {
			candidates = append(candidates, candidate)
		}
	}
	for _, candidate := range candidates {
		if _, err := conn.ExecContext(ctx, `UPDATE receipts
			SET receipt_envelope = ?
			WHERE receipt_id = ?
			  AND (receipt_envelope IS NULL OR trim(receipt_envelope) = '' OR receipt_envelope = 'null')
			  AND chain_hash = ?`, string(candidate.envelope), candidate.receiptID, candidate.chainHash); err != nil {
			return fmt.Errorf("backfill canonical receipt envelope %q: %w", candidate.receiptID, err)
		}
	}
	if _, err := conn.ExecContext(ctx, `COMMIT`); err != nil {
		return fmt.Errorf("commit receipt envelope backfill: %w", err)
	}
	committed = true
	return nil
}

func receiptFromSQLiteFields(receiptID, decisionID, effectID string, externalID sql.NullString, status, blobHash, outputHash string, decisionHash sql.NullString, timestamp string, executorID, metaJSON, signature, merkleRoot, prevHash sql.NullString, lamport uint64, argsHash, signatureVersion, verdict, reasonCode, policyHash, sessionID, logID sql.NullString, leafIndex uint64, transparency sql.NullString,
	keyID, publicKeySet, sigProfile, sigAlgorithm, correlationID sql.NullString) (*contracts.Receipt, error) {
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
		DecisionHash:        decisionHash.String,
		ExecutorID:          executorID.String,
		Metadata:            meta,
		Signature:           signature.String,
		MerkleRoot:          merkleRoot.String,
		PrevHash:            prevHash.String,
		LamportClock:        lamport,
		ArgsHash:            argsHash.String,
		SignatureVersion:    signatureVersion.String,
		Verdict:             verdict.String,
		ReasonCode:          reasonCode.String,
		PolicyHash:          policyHash.String,
		SessionID:           sessionID.String,
		LogID:               logID.String,
		LeafIndex:           leafIndex,
		// Signer identity must survive persistence, otherwise a signature
		// covering it can never match a reloaded receipt (F-05).
		KeyID:              keyID.String,
		SignatureProfile:   sigProfile.String,
		SignatureAlgorithm: sigAlgorithm.String,
		CorrelationID:      correlationID.String,
	}
	if publicKeySet.Valid && publicKeySet.String != "" && publicKeySet.String != "null" {
		if err := json.Unmarshal([]byte(publicKeySet.String), &receipt.PublicKeySet); err != nil {
			return nil, fmt.Errorf("decode receipt public_key_set: %w", err)
		}
	}
	if transparency.Valid {
		if err := decodeTransparencyAnchor([]byte(transparency.String), receipt); err != nil {
			return nil, err
		}
	}
	if err := restoreOrRejectV5DecisionHash(receipt); err != nil {
		return nil, err
	}
	return receipt, nil
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
