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
		correlation_id TEXT NOT NULL DEFAULT ''
	);`
	if _, err := s.db.ExecContext(context.Background(), query); err != nil {
		return err
	}
	if err := s.ensureColumn("args_hash", "TEXT NOT NULL DEFAULT ''"); err != nil {
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
	if err := s.ensureColumn("transparency", "TEXT"); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(context.Background(), backfillCausalReceiptSessionsSQL); err != nil {
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
const sqliteReceiptColumns = `receipt_id, decision_id, effect_id, external_reference_id, status, blob_hash, output_hash, timestamp, executor_id, metadata, signature, merkle_root, prev_hash, lamport_clock, args_hash, COALESCE(signature_version, '') AS signature_version, COALESCE(verdict, '') AS verdict, COALESCE(reason_code, '') AS reason_code, COALESCE(policy_hash, '') AS policy_hash, COALESCE(session_id, '') AS session_id, log_id, leaf_index, transparency, COALESCE(key_id, '') AS key_id, public_key_set, COALESCE(signature_profile, '') AS signature_profile, COALESCE(signature_algorithm, '') AS signature_algorithm, COALESCE(correlation_id, '') AS correlation_id`

func (s *SQLiteReceiptStore) Get(ctx context.Context, decisionID string) (*contracts.Receipt, error) {
	query := `
		SELECT ` + sqliteReceiptColumns + `
        FROM receipts
        WHERE decision_id = ?
    `
	return s.queryOne(ctx, query, decisionID)
}

func (s *SQLiteReceiptStore) GetByReceiptID(ctx context.Context, receiptID string) (*contracts.Receipt, error) {
	query := `
		SELECT ` + sqliteReceiptColumns + `
        FROM receipts
        WHERE receipt_id = ?
    `
	return s.queryOne(ctx, query, receiptID)
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
		  AND substr(causal_session_id, 1, ?) = ?
	`
	return s.queryOne(ctx, query, receiptID, contracts.ReceiptSignatureV5, len(prefix), prefix)
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
		  AND substr(causal_session_id, 1, ?) = ?
		  AND lamport_clock > ?
		ORDER BY lamport_clock ASC, timestamp ASC
		LIMIT ?
	`
	return s.queryReceipts(ctx, query, contracts.ReceiptSignatureV5, len(prefix), prefix, since, limit)
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
	query := `INSERT INTO receipts (
		receipt_id, decision_id, effect_id, external_reference_id, status, blob_hash, output_hash, timestamp, executor_id, metadata, signature, merkle_root, prev_hash, lamport_clock, args_hash, signature_version, verdict, reason_code, policy_hash, session_id, causal_session_id, log_id, leaf_index, transparency, key_id, public_key_set, signature_profile, signature_algorithm, correlation_id
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

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
	timestamp := r.Timestamp.UTC().Format(time.RFC3339Nano)

	_, err = execer.ExecContext(ctx, query,
		r.ReceiptID, r.DecisionID, r.EffectID, r.ExternalReferenceID, r.Status, r.BlobHash, r.OutputHash, timestamp, r.ExecutorID, string(metaJSON), r.Signature, r.MerkleRoot, r.PrevHash, r.LamportClock, r.ArgsHash, r.SignatureVersion, r.Verdict, r.ReasonCode, r.PolicyHash, r.SessionID, causalSessionID, r.LogID, r.LeafIndex, nullableJSON(transparencyJSON), r.KeyID, nullableJSON(publicKeySetJSON), r.SignatureProfile, r.SignatureAlgorithm, r.CorrelationID,
	)
	if err != nil {
		return fmt.Errorf("failed to insert receipt: %w", err)
	}
	return nil
}

func (s *SQLiteReceiptStore) AppendCausal(ctx context.Context, sessionID string, build CausalReceiptBuilder) error {
	return s.appendCausal(ctx, sessionID, sessionID, build)
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

	last, err := queryLastSQLiteReceipt(ctx, conn, causalSessionID)
	if err != nil {
		return err
	}
	receipt, err := buildNextCausalReceiptScoped(causalSessionID, externalSessionID, last, build)
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
	query := `
		SELECT ` + sqliteReceiptColumns + `
        FROM receipts
		WHERE causal_session_id = ?
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

type sqliteScanner interface {
	Scan(dest ...any) error
}

func scanSQLiteReceipt(scanner sqliteScanner) (*contracts.Receipt, error) {
	var (
		receiptID        string
		decisionID       string
		effectID         string
		externalID       sql.NullString
		status           string
		blobHash         string
		outputHash       string
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
	)
	if err := scanner.Scan(&receiptID, &decisionID, &effectID, &externalID, &status, &blobHash, &outputHash, &timestamp, &executorID, &metaJSON, &signature, &merkleRoot, &prevHash, &lamport, &argsHash, &signatureVersion, &verdict, &reasonCode, &policyHash, &sessionID, &logID, &leafIndex, &transparency, &keyID, &publicKeySet, &sigProfile, &sigAlgorithm, &correlationID); err != nil {
		return nil, err
	}
	return receiptFromSQLiteFields(receiptID, decisionID, effectID, externalID, status, blobHash, outputHash, timestamp, executorID, metaJSON, signature, merkleRoot, prevHash, lamport, argsHash, signatureVersion, verdict, reasonCode, policyHash, sessionID, logID, leafIndex, transparency, keyID, publicKeySet, sigProfile, sigAlgorithm, correlationID)
}

func receiptFromSQLiteFields(receiptID, decisionID, effectID string, externalID sql.NullString, status, blobHash, outputHash, timestamp string, executorID, metaJSON, signature, merkleRoot, prevHash sql.NullString, lamport uint64, argsHash, signatureVersion, verdict, reasonCode, policyHash, sessionID, logID sql.NullString, leafIndex uint64, transparency sql.NullString,
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
