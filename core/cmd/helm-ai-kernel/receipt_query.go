package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/api"
	helmauth "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/auth"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/store"
)

func authenticatedReceiptTenantID(ctx context.Context) (string, error) {
	principal, err := helmauth.GetPrincipal(ctx)
	if err != nil || principal == nil {
		return "", fmt.Errorf("authenticated tenant principal is required")
	}
	tenantID := strings.TrimSpace(principal.GetTenantID())
	if tenantID == "" {
		return "", fmt.Errorf("authenticated tenant id is required")
	}
	return tenantID, nil
}

func authenticatedReceiptTenantScope(r *http.Request, svc *Services) (string, error) {
	tenantID, err := authenticatedReceiptTenantID(r.Context())
	if err != nil {
		return "", err
	}
	if _, err := bindRuntimeScope(r, svc, tenantID, workspaceMustBeAsserted); err != nil {
		return "", err
	}
	return tenantID, nil
}

func requestedReceiptSessionID(r *http.Request) (string, error) {
	sessionID := strings.TrimSpace(r.URL.Query().Get("session_id"))
	if sessionID != "" {
		return api.NormalizePublicSessionID(sessionID)
	}
	// Retain the old query spelling as an alias only. It is interpreted as a
	// signed session ID, never as an executor filter.
	agent := strings.TrimSpace(r.URL.Query().Get("agent"))
	if agent == "" {
		return "", nil
	}
	return api.NormalizePublicSessionID(agent)
}

func tenantScopedReceiptReader(svc *Services) (store.TenantScopedReceiptReader, error) {
	if svc == nil || svc.ReceiptStore == nil {
		return nil, fmt.Errorf("receipt store unavailable")
	}
	reader, ok := svc.ReceiptStore.(store.TenantScopedReceiptReader)
	if !ok {
		return nil, fmt.Errorf("receipt store lacks tenant-scoped V5 read capability")
	}
	return reader, nil
}

func tenantScopedReceiptFilterReader(svc *Services) (store.TenantScopedReceiptFilterReader, error) {
	if svc == nil || svc.ReceiptStore == nil {
		return nil, fmt.Errorf("receipt store unavailable")
	}
	reader, ok := svc.ReceiptStore.(store.TenantScopedReceiptFilterReader)
	if !ok {
		return nil, fmt.Errorf("receipt store lacks tenant-scoped predicate-query capability")
	}
	return reader, nil
}

// listReceiptsForCursor selects the tenant-scoped reader path. A non-empty
// filter routes through the predicate-query capability; an empty filter keeps
// the exact prior behaviour (and does not require the filter capability), so
// the SSE tail loop is unaffected.
func listReceiptsForCursor(ctx context.Context, svc *Services, tenantID, sessionID string, cursor store.TenantReceiptCursor, filter store.ReceiptQueryFilter, limit int) ([]*contracts.Receipt, error) {
	if strings.TrimSpace(sessionID) != "" {
		if !filter.IsZero() {
			reader, err := tenantScopedReceiptFilterReader(svc)
			if err != nil {
				return nil, err
			}
			return reader.ListByTenantSessionFiltered(ctx, tenantID, sessionID, cursor.LamportClock, filter, limit)
		}
		reader, err := tenantScopedReceiptReader(svc)
		if err != nil {
			return nil, err
		}
		return reader.ListByTenantSession(ctx, tenantID, sessionID, cursor.LamportClock, limit)
	}
	if svc == nil || svc.ReceiptStore == nil {
		return nil, fmt.Errorf("receipt store unavailable")
	}
	if !filter.IsZero() {
		reader, ok := svc.ReceiptStore.(store.TenantScopedReceiptFilterReader)
		if !ok {
			return nil, fmt.Errorf("receipt store lacks tenant-wide predicate-query capability")
		}
		return reader.ListByTenantCursorFiltered(ctx, tenantID, cursor, filter, limit)
	}
	reader, ok := svc.ReceiptStore.(store.TenantScopedReceiptCursorReader)
	if !ok {
		return nil, fmt.Errorf("receipt store lacks tenant-wide keyset cursor capability")
	}
	return reader.ListByTenantCursor(ctx, tenantID, cursor, limit)
}

// parseReceiptQueryFilter reads the optional predicate dimensions from the
// query string so a caller can answer "everything denied for reason X in
// period Y" in one request. Time bounds are RFC3339Nano with at most nine
// fractional-second digits (from inclusive, to exclusive). principal/executor
// and effect/resource are accepted as synonyms. Absent params impose no
// constraint on that dimension.
func parseReceiptQueryFilter(r *http.Request) (store.ReceiptQueryFilter, error) {
	q := r.URL.Query()
	executor := strings.TrimSpace(q.Get("principal"))
	if executor == "" {
		executor = strings.TrimSpace(q.Get("executor"))
	}
	effect := strings.TrimSpace(q.Get("effect"))
	if effect == "" {
		effect = strings.TrimSpace(q.Get("resource"))
	}
	filter := store.ReceiptQueryFilter{
		Verdict:    strings.TrimSpace(q.Get("verdict")),
		ReasonCode: strings.TrimSpace(q.Get("reason_code")),
		Executor:   executor,
		Effect:     effect,
	}
	from, err := parseReceiptFilterTime(q.Get("from"))
	if err != nil {
		return store.ReceiptQueryFilter{}, fmt.Errorf("invalid from timestamp: %w", err)
	}
	to, err := parseReceiptFilterTime(q.Get("to"))
	if err != nil {
		return store.ReceiptQueryFilter{}, fmt.Errorf("invalid to timestamp: %w", err)
	}
	filter.From = from
	filter.To = to
	if !filter.From.IsZero() && !filter.To.IsZero() && !filter.To.After(filter.From) {
		return store.ReceiptQueryFilter{}, fmt.Errorf("to must be after from")
	}
	return filter, nil
}

func parseReceiptFilterTime(raw string) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, nil
	}
	const formatError = "must be RFC3339Nano with at most 9 fractional digits"
	if strings.ContainsRune(raw, ',') {
		return time.Time{}, fmt.Errorf(formatError)
	}
	if dot := strings.IndexByte(raw, '.'); dot >= 0 {
		fractionalDigits := 0
		for i := dot + 1; i < len(raw) && raw[i] >= '0' && raw[i] <= '9'; i++ {
			fractionalDigits++
		}
		if fractionalDigits > 9 {
			return time.Time{}, fmt.Errorf(formatError)
		}
	}
	parsed, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return time.Time{}, fmt.Errorf(formatError)
	}
	return parsed.UTC(), nil
}

func receiptForTenant(ctx context.Context, svc *Services, tenantID, receiptID string) (*contracts.Receipt, error) {
	reader, err := tenantScopedReceiptReader(svc)
	if err != nil {
		return nil, err
	}
	return reader.GetByReceiptIDForTenant(ctx, tenantID, receiptID)
}

const tenantReceiptCursorVersionPrefix = "v1."

type tenantReceiptCursorWire struct {
	LamportClock uint64 `json:"l"`
	Timestamp    string `json:"t"`
	ReceiptID    string `json:"r"`
}

// parseReceiptCursor preserves scalar Lamport cursors for one signed session.
// Tenant-wide listings require an opaque composite cursor because each session
// owns its own Lamport clock.
func parseReceiptCursor(raw, sessionID string) (store.TenantReceiptCursor, error) {
	raw = strings.TrimSpace(raw)
	if strings.TrimSpace(sessionID) != "" {
		return parseSessionReceiptCursor(raw)
	}
	if raw == "" {
		return store.TenantReceiptCursor{}, nil
	}
	if !strings.HasPrefix(raw, tenantReceiptCursorVersionPrefix) {
		return store.TenantReceiptCursor{}, fmt.Errorf("tenant-wide receipt cursor must be an opaque v1 cursor")
	}
	encoded := strings.TrimPrefix(raw, tenantReceiptCursorVersionPrefix)
	if encoded == "" {
		return store.TenantReceiptCursor{}, fmt.Errorf("tenant-wide receipt cursor payload is required")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return store.TenantReceiptCursor{}, fmt.Errorf("decode tenant-wide receipt cursor: %w", err)
	}
	var wire tenantReceiptCursorWire
	if err := json.Unmarshal(decoded, &wire); err != nil {
		return store.TenantReceiptCursor{}, fmt.Errorf("decode tenant-wide receipt cursor payload: %w", err)
	}
	wire.ReceiptID = strings.TrimSpace(wire.ReceiptID)
	if wire.ReceiptID == "" || strings.TrimSpace(wire.Timestamp) == "" {
		return store.TenantReceiptCursor{}, fmt.Errorf("tenant-wide receipt cursor is incomplete")
	}
	timestamp, err := time.Parse(time.RFC3339Nano, wire.Timestamp)
	if err != nil || timestamp.IsZero() {
		return store.TenantReceiptCursor{}, fmt.Errorf("tenant-wide receipt cursor timestamp is invalid")
	}
	return store.TenantReceiptCursor{LamportClock: wire.LamportClock, Timestamp: timestamp.UTC(), ReceiptID: wire.ReceiptID}, nil
}

func parseSessionReceiptCursor(raw string) (store.TenantReceiptCursor, error) {
	raw = strings.TrimSpace(strings.TrimPrefix(raw, "lamport:"))
	if raw == "" {
		return store.TenantReceiptCursor{}, nil
	}
	lamport, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return store.TenantReceiptCursor{}, err
	}
	return store.TenantReceiptCursor{LamportClock: lamport}, nil
}

func receiptCursorForReceipt(sessionID string, receipt *contracts.Receipt) (store.TenantReceiptCursor, error) {
	if receipt == nil {
		return store.TenantReceiptCursor{}, fmt.Errorf("receipt cursor requires a receipt")
	}
	cursor := store.TenantReceiptCursor{LamportClock: receipt.LamportClock}
	if strings.TrimSpace(sessionID) != "" {
		return cursor, nil
	}
	cursor.ReceiptID = strings.TrimSpace(receipt.ReceiptID)
	cursor.Timestamp = receipt.Timestamp.UTC()
	if cursor.ReceiptID == "" || cursor.Timestamp.IsZero() {
		return store.TenantReceiptCursor{}, fmt.Errorf("tenant-wide receipt cursor requires receipt id and timestamp")
	}
	return cursor, nil
}

func formatReceiptCursor(sessionID string, cursor store.TenantReceiptCursor) (string, error) {
	if strings.TrimSpace(sessionID) != "" {
		if cursor.LamportClock == 0 {
			return "", nil
		}
		return fmt.Sprintf("lamport:%d", cursor.LamportClock), nil
	}
	cursor.ReceiptID = strings.TrimSpace(cursor.ReceiptID)
	if cursor.ReceiptID == "" || cursor.Timestamp.IsZero() {
		return "", fmt.Errorf("tenant-wide receipt cursor is incomplete")
	}
	payload, err := json.Marshal(tenantReceiptCursorWire{
		LamportClock: cursor.LamportClock,
		Timestamp:    cursor.Timestamp.UTC().Format(time.RFC3339Nano),
		ReceiptID:    cursor.ReceiptID,
	})
	if err != nil {
		return "", fmt.Errorf("encode tenant-wide receipt cursor: %w", err)
	}
	return tenantReceiptCursorVersionPrefix + base64.RawURLEncoding.EncodeToString(payload), nil
}

func nextReceiptCursor(sessionID string, receipts []*contracts.Receipt) (string, error) {
	if len(receipts) == 0 {
		return "", nil
	}
	cursor, err := receiptCursorForReceipt(sessionID, receipts[len(receipts)-1])
	if err != nil {
		return "", err
	}
	return formatReceiptCursor(sessionID, cursor)
}

func parseLimit(raw string, fallback, max int) int {
	limit := fallback
	if raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil {
			limit = parsed
		}
	}
	if limit <= 0 {
		return fallback
	}
	if limit > max {
		return max
	}
	return limit
}
