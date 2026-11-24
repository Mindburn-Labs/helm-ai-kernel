package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// receiptColumns is the canonical column list for receipt queries.
const receiptColumns = `receipt_id, decision_id, COALESCE(effect_id, execution_intent_id, '') AS effect_id, COALESCE(external_reference_id, '') AS external_reference_id, status, blob_hash, output_hash, COALESCE(decision_hash, '') AS decision_hash, timestamp, COALESCE(executor_id, '') AS executor_id, metadata, signature, merkle_root, COALESCE(prev_hash, '') AS prev_hash, COALESCE(lamport_clock, 0) AS lamport_clock, args_hash, COALESCE(signature_version, '') AS signature_version, COALESCE(verdict, '') AS verdict, COALESCE(reason_code, '') AS reason_code, COALESCE(policy_hash, '') AS policy_hash, COALESCE(session_id, '') AS session_id, COALESCE(log_id, '') AS log_id, COALESCE(leaf_index, 0) AS leaf_index, transparency, COALESCE(key_id, '') AS key_id, public_key_set, COALESCE(signature_profile, '') AS signature_profile, COALESCE(signature_algorithm, '') AS signature_algorithm, COALESCE(correlation_id, '') AS correlation_id, receipt_envelope, COALESCE(chain_hash, '') AS chain_hash`

func (s *PostgresReceiptStore) Get(ctx context.Context, decisionID string) (*contracts.Receipt, error) {
	query := `SELECT ` + receiptColumns + ` FROM receipts WHERE decision_id = $1`
	return s.queryOne(ctx, query, decisionID)
}

// GetByDecisionIDForTenant returns only a V5 receipt whose durable causal
// scope belongs to the authenticated tenant.
func (s *PostgresReceiptStore) GetByDecisionIDForTenant(ctx context.Context, tenantID, decisionID string) (*contracts.Receipt, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, fmt.Errorf("tenant id is required")
	}
	prefix := causalReceiptTenantScopePrefix(tenantID)
	query := `SELECT ` + receiptColumns + ` FROM receipts
		WHERE decision_id = $1
		  AND signature_version = $2
		  AND COALESCE(session_id, '') <> ''
		  AND left(causal_session_id, char_length($3)) = $3`
	receipt, err := scanReceipt(s.db.QueryRowContext(ctx, query, decisionID, contracts.ReceiptSignatureV5, prefix))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return receipt, err
}

func (s *PostgresReceiptStore) GetByReceiptID(ctx context.Context, receiptID string) (*contracts.Receipt, error) {
	query := `SELECT ` + receiptColumns + ` FROM receipts WHERE receipt_id = $1`
	return s.queryOne(ctx, query, receiptID)
}

// GetCanonicalReceiptByID returns a complete receipt envelope only after its
// canonical chain hash is reproduced from the stored envelope. It deliberately
// rejects historical projection-only rows whose missing fields cannot be
// reconstructed, while GetByReceiptID continues to expose those projections
// for operational compatibility.
func (s *PostgresReceiptStore) GetCanonicalReceiptByID(ctx context.Context, receiptID string) (*contracts.Receipt, error) {
	query := `SELECT ` + receiptColumns + ` FROM receipts WHERE receipt_id = $1`
	return s.queryCanonicalOne(ctx, query, receiptID)
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

// GetCanonicalReceiptByIDForTenant is the authenticated-scope form of
// GetCanonicalReceiptByID. It never promotes an unscoped legacy row into
// tenant evidence.
func (s *PostgresReceiptStore) GetCanonicalReceiptByIDForTenant(ctx context.Context, tenantID, receiptID string) (*contracts.Receipt, error) {
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
	return s.queryCanonicalOne(ctx, query, receiptID, contracts.ReceiptSignatureV5, prefix)
}

// CountReceipts returns the total number of durably stored receipts.
func (s *PostgresReceiptStore) CountReceipts(ctx context.Context) (int, error) {
	var count int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM receipts`).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
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

func (s *PostgresReceiptStore) ListLatestByTenant(ctx context.Context, tenantID string, limit int) ([]*contracts.Receipt, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, fmt.Errorf("tenant id is required")
	}
	prefix := causalReceiptTenantScopePrefix(tenantID)
	query := `SELECT ` + receiptColumns + ` FROM receipts
		WHERE signature_version = $1
		  AND COALESCE(session_id, '') <> ''
		  AND left(causal_session_id, char_length($2)) = $2
		ORDER BY timestamp DESC, append_sequence DESC LIMIT $3`
	return s.queryReceipts(ctx, query, contracts.ReceiptSignatureV5, prefix, limit)
}

func (s *PostgresReceiptStore) ListLatestOnboardingByTenant(ctx context.Context, tenantID string) ([]*contracts.Receipt, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, fmt.Errorf("tenant id is required")
	}
	prefix := causalReceiptTenantScopePrefix(tenantID)
	query := `WITH ranked AS (
		SELECT receipts.*,
			ROW_NUMBER() OVER (
				PARTITION BY metadata->>'onboarding_step'
				ORDER BY timestamp DESC, append_sequence DESC
			) AS onboarding_rank
		FROM receipts
		WHERE signature_version = $1
		  AND COALESCE(session_id, '') <> ''
		  AND left(causal_session_id, char_length($2)) = $2
		  AND NULLIF(metadata->>'onboarding_step', '') IS NOT NULL
	)
	SELECT ` + receiptColumns + ` FROM ranked
	WHERE onboarding_rank = 1
	ORDER BY timestamp DESC, append_sequence DESC`
	return s.queryReceipts(ctx, query, contracts.ReceiptSignatureV5, prefix)
}

// ListByTenantCursor returns V5 receipts in durable append order. The opaque
// cursor's receipt ID is resolved inside the authenticated tenant scope, so
// later session genesis receipts are never compared to another session's
// Lamport clock.
func (s *PostgresReceiptStore) ListByTenantCursor(ctx context.Context, tenantID string, cursor TenantReceiptCursor, limit int) ([]*contracts.Receipt, error) {
	return s.listByTenantCursor(ctx, tenantID, cursor, ReceiptQueryFilter{}, limit)
}

// ListByTenantCursorFiltered is ListByTenantCursor narrowed by an optional
// ReceiptQueryFilter. It keeps the identical authenticated tenant scope and
// durable append-order keyset pagination; the filter only removes rows, so a
// zero-value filter is byte-for-byte equivalent to ListByTenantCursor.
func (s *PostgresReceiptStore) ListByTenantCursorFiltered(ctx context.Context, tenantID string, cursor TenantReceiptCursor, filter ReceiptQueryFilter, limit int) ([]*contracts.Receipt, error) {
	return s.listByTenantCursor(ctx, tenantID, cursor, filter, limit)
}

func (s *PostgresReceiptStore) listByTenantCursor(ctx context.Context, tenantID string, cursor TenantReceiptCursor, filter ReceiptQueryFilter, limit int) ([]*contracts.Receipt, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, fmt.Errorf("tenant id is required")
	}
	appendSequence, hasCursor, err := s.resolveTenantCursorAppendSequence(ctx, tenantID, cursor)
	if err != nil {
		return nil, err
	}
	prefix := causalReceiptTenantScopePrefix(tenantID)
	query := `SELECT ` + receiptColumns + ` FROM receipts
		WHERE signature_version = $1
		  AND COALESCE(session_id, '') <> ''
		  AND left(causal_session_id, char_length($2)) = $2`
	args := []any{contracts.ReceiptSignatureV5, prefix}
	if hasCursor {
		args = append(args, appendSequence)
		query += fmt.Sprintf("\n\t\t  AND append_sequence > $%d", len(args))
	}
	query, args = appendReceiptFilterPredicatesPostgres(query, args, filter)
	args = append(args, limit)
	query += fmt.Sprintf("\n\t\tORDER BY append_sequence ASC LIMIT $%d", len(args))
	return s.queryReceipts(ctx, query, args...)
}

// resolveTenantCursorAppendSequence maps an opaque tenant cursor to its durable
// append position inside the authenticated tenant scope. An empty cursor
// returns hasCursor=false; a cursor that does not resolve within the tenant is
// rejected rather than silently treated as the start of the listing.
func (s *PostgresReceiptStore) resolveTenantCursorAppendSequence(ctx context.Context, tenantID string, cursor TenantReceiptCursor) (int64, bool, error) {
	cursor.ReceiptID = strings.TrimSpace(cursor.ReceiptID)
	if cursor.ReceiptID == "" {
		return 0, false, nil
	}
	if cursor.Timestamp.IsZero() {
		return 0, false, fmt.Errorf("tenant receipt cursor timestamp is required")
	}
	prefix := causalReceiptTenantScopePrefix(tenantID)
	cursorQuery := `SELECT append_sequence FROM receipts
			WHERE receipt_id = $1
			  AND signature_version = $2
			  AND COALESCE(session_id, '') <> ''
			  AND left(causal_session_id, char_length($3)) = $3`
	var appendSequence int64
	if err := s.db.QueryRowContext(ctx, cursorQuery, cursor.ReceiptID, contracts.ReceiptSignatureV5, prefix).Scan(&appendSequence); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, false, fmt.Errorf("tenant receipt cursor %q is invalid for authenticated tenant", cursor.ReceiptID)
		}
		return 0, false, fmt.Errorf("resolve tenant receipt cursor: %w", err)
	}
	return appendSequence, true, nil
}

// appendReceiptFilterPredicatesPostgres weaves the optional ReceiptQueryFilter
// dimensions into a tenant-scoped query as additional AND predicates, using
// $-placeholders that continue from the caller's current argument list. Each
// predicate matches an indexed projection column. A returned canonical envelope
// must match all five filter projections at the shared restore boundary.
func appendReceiptFilterPredicatesPostgres(query string, args []any, filter ReceiptQueryFilter) (string, []any) {
	addEq := func(column, value string) {
		args = append(args, value)
		query += fmt.Sprintf("\n\t\t  AND %s = $%d", column, len(args))
	}
	if v := strings.TrimSpace(filter.Verdict); v != "" {
		addEq("verdict", v)
	}
	if v := strings.TrimSpace(filter.ReasonCode); v != "" {
		addEq("reason_code", v)
	}
	if v := strings.TrimSpace(filter.Executor); v != "" {
		addEq("executor_id", v)
	}
	if v := strings.TrimSpace(filter.Effect); v != "" {
		addEq("effect_id", v)
	}
	if !filter.From.IsZero() {
		args = append(args, filter.From.UTC())
		query += fmt.Sprintf("\n\t\t  AND timestamp >= $%d", len(args))
	}
	if !filter.To.IsZero() {
		args = append(args, filter.To.UTC())
		query += fmt.Sprintf("\n\t\t  AND timestamp < $%d", len(args))
	}
	return query, args
}

// ListByTenantSession returns the receipt chain keyed by the signed
// Receipt.SessionID inside an authenticated tenant scope.
func (s *PostgresReceiptStore) ListByTenantSession(ctx context.Context, tenantID, sessionID string, since uint64, limit int) ([]*contracts.Receipt, error) {
	return s.listByTenantSession(ctx, tenantID, sessionID, since, ReceiptQueryFilter{}, limit)
}

// ListByTenantSessionFiltered is ListByTenantSession narrowed by an optional
// ReceiptQueryFilter over the same signed session chain. A zero-value filter is
// equivalent to ListByTenantSession.
func (s *PostgresReceiptStore) ListByTenantSessionFiltered(ctx context.Context, tenantID, sessionID string, since uint64, filter ReceiptQueryFilter, limit int) ([]*contracts.Receipt, error) {
	return s.listByTenantSession(ctx, tenantID, sessionID, since, filter, limit)
}

func (s *PostgresReceiptStore) listByTenantSession(ctx context.Context, tenantID, sessionID string, since uint64, filter ReceiptQueryFilter, limit int) ([]*contracts.Receipt, error) {
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
		  AND lamport_clock > $4`
	args := []any{causalReceiptScopeKey(tenantID, sessionID), sessionID, contracts.ReceiptSignatureV5, since}
	query, args = appendReceiptFilterPredicatesPostgres(query, args, filter)
	args = append(args, limit)
	query += fmt.Sprintf("\n\t\tORDER BY lamport_clock ASC, timestamp ASC LIMIT $%d", len(args))
	return s.queryReceipts(ctx, query, args...)
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

func (s *PostgresReceiptStore) queryCanonicalOne(ctx context.Context, query string, args ...any) (*contracts.Receipt, error) {
	row := s.db.QueryRowContext(ctx, query, args...)
	r, err := scanCanonicalReceipt(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("receipt not found")
		}
		return nil, err
	}
	return r, nil
}

// GetLastForSession returns the most recent receipt for a signed session_id for causal DAG chaining.
func (s *PostgresReceiptStore) GetLastForSession(ctx context.Context, sessionID string) (*contracts.Receipt, error) {
	return queryLastPostgresReceipt(ctx, s.db, sessionID)
}

type sqlQueryer interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func queryLastPostgresReceipt(ctx context.Context, queryer sqlQueryer, sessionID string) (*contracts.Receipt, error) {
	receipt, _, err := queryLastPostgresReceiptWithChainHash(ctx, queryer, sessionID)
	return receipt, err
}

func queryLastPostgresReceiptWithChainHash(ctx context.Context, queryer sqlQueryer, sessionID string) (*contracts.Receipt, string, error) {
	query := `SELECT ` + receiptColumns + ` FROM receipts WHERE causal_session_id = $1 ORDER BY lamport_clock DESC LIMIT 1`
	row := queryer.QueryRowContext(ctx, query, sessionID)
	r, chainHash, err := scanReceiptWithChainHash(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, "", nil // No previous receipt for this session — genesis
		}
		return nil, "", err
	}
	return r, chainHash, nil
}
