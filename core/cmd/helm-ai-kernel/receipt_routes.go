package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/api"
	helmauth "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/auth"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/guardian"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/store"
)

func registerReceiptRoutes(mux *http.ServeMux, svc *Services) {
	mux.HandleFunc("/api/v1/evaluate", protectRuntimeHandler(RouteAuthTenant, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			api.WriteMethodNotAllowed(w)
			return
		}
		if svc.Guardian == nil {
			api.WriteError(w, http.StatusServiceUnavailable, "Guardian unavailable", "guardian not initialized")
			return
		}
		// V0.8 retains the public direct-daemon action/resource envelope while
		// generated SDKs use the canonical V5 tool/effect_level/session_id
		// fields. Authentication remains authoritative for principal and tenant.
		var req api.EvaluateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			api.WriteBadRequest(w, "Invalid JSON body")
			return
		}
		principal, err := helmauth.GetPrincipal(r.Context())
		if err != nil || principal == nil {
			api.WriteForbidden(w, "Evaluate route requires authenticated tenant principal context")
			return
		}
		principalID := strings.TrimSpace(principal.GetID())
		tenantID := strings.TrimSpace(principal.GetTenantID())
		if principalID == "" || tenantID == "" {
			api.WriteForbidden(w, "Evaluate route requires authenticated tenant and principal identifiers")
			return
		}
		workspaceID := strings.TrimSpace(r.Header.Get(workspaceHeader))
		if svc.EmergencyStops != nil {
			configuredTenantID := strings.TrimSpace(os.Getenv(runtimeTenantIDEnv))
			if configuredTenantID == "" || tenantID != configuredTenantID {
				api.WriteForbidden(w, "Evaluate route tenant binding could not be verified")
				return
			}
			if workspaceID == "" {
				api.WriteForbidden(w, "Evaluate route requires an explicit authenticated workspace binding")
				return
			}
			if configuredWorkspaceID := configuredRuntimeWorkspaceID(); configuredWorkspaceID == "" || workspaceID != configuredWorkspaceID {
				api.WriteForbidden(w, "Evaluate route workspace binding could not be verified")
				return
			}
		}
		req.Tool = strings.TrimSpace(req.Tool)
		if req.Tool == "" {
			req.Tool = strings.TrimSpace(req.Action)
		}
		req.EffectLevel = strings.TrimSpace(req.EffectLevel)
		if req.EffectLevel == "" {
			req.EffectLevel = strings.TrimSpace(req.Resource)
		}
		if req.Tool == "" || req.EffectLevel == "" {
			api.WriteBadRequest(w, "Evaluate route requires tool and effect_level")
			return
		}
		req.SessionID = strings.TrimSpace(req.SessionID)
		if req.SessionID == "" && req.Context != nil {
			if legacySessionID, ok := req.Context["session_id"].(string); ok {
				req.SessionID = strings.TrimSpace(legacySessionID)
			}
		}
		if req.SessionID == "" {
			api.WriteBadRequest(w, "Evaluate route requires a non-blank session_id")
			return
		}
		if req.Context == nil {
			req.Context = make(map[string]interface{})
		}
		req.AgentID = principalID
		req.Context["principal_id"] = principalID
		req.Context["tenant_id"] = tenantID
		// The external session ID remains a signed field. Durable storage may
		// derive a private tenant-qualified ordering key from this authenticated
		// context, but that key is not part of the public API contract.
		req.Context["session_id"] = req.SessionID
		if req.Args != nil {
			req.Context["args"] = req.Args
		}
		if workspaceID != "" {
			req.Context["workspace_id"] = workspaceID
		}
		args, err := json.Marshal(req.Args)
		if err != nil {
			api.WriteBadRequest(w, "Invalid evaluate args")
			return
		}
		decision, err := svc.Guardian.EvaluateDecision(r.Context(), guardian.DecisionRequest{
			Principal: principalID,
			Action:    req.Tool,
			Resource:  req.EffectLevel,
			Context:   req.Context,
		})
		if err != nil {
			api.WriteInternal(w, err)
			return
		}
		if err := persistDecisionReceiptForTenant(r.Context(), svc, decision, principalID, tenantID, args, map[string]any{
			"source":   "api.evaluate",
			"action":   req.Tool,
			"resource": req.EffectLevel,
			"reason":   decision.Reason,
		}); err != nil {
			api.WriteInternal(w, err)
			return
		}
		receiptID := "rcpt_" + decision.ID
		receipt, err := receiptForTenant(r.Context(), svc, tenantID, receiptID)
		if err != nil {
			api.WriteInternal(w, fmt.Errorf("load persisted receipt %s: %w", receiptID, err))
			return
		}
		if receipt == nil {
			api.WriteInternal(w, fmt.Errorf("persisted receipt %s is unavailable", receiptID))
			return
		}
		policyRef := decision.PolicyVersion
		if policyRef == "" {
			policyRef = decision.PolicyContentHash
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(api.EvaluateResponse{
			Allow:              contracts.Verdict(decision.Verdict) == contracts.VerdictAllow,
			Verdict:            decision.Verdict,
			ReceiptID:          receipt.ReceiptID,
			DecisionID:         decision.ID,
			DecisionHash:       receipt.DecisionHash,
			ReasonCode:         decision.ReasonCode,
			PolicyRef:          policyRef,
			LamportClock:       receipt.LamportClock,
			ID:                 decision.ID,
			Action:             req.Tool,
			Resource:           req.EffectLevel,
			Reason:             decision.Reason,
			PolicyVersion:      decision.PolicyVersion,
			PolicyDecisionHash: decision.PolicyDecisionHash,
			Signature:          decision.Signature,
		})
	}))

	mux.HandleFunc("/api/v1/receipts/tail", protectRuntimeHandler(RouteAuthTenant, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			api.WriteMethodNotAllowed(w)
			return
		}
		if svc.ReceiptStore == nil {
			api.WriteError(w, http.StatusServiceUnavailable, "Receipt store unavailable", "receipt store not initialized")
			return
		}
		tenantID, err := authenticatedReceiptTenantID(r.Context())
		if err != nil {
			api.WriteForbidden(w, "Receipt route requires authenticated tenant principal context")
			return
		}
		sessionID := requestedReceiptSessionID(r)
		rawCursor := r.URL.Query().Get("since")
		if strings.TrimSpace(rawCursor) == "" {
			rawCursor = r.Header.Get("Last-Event-ID")
		}
		cursor, err := parseReceiptCursor(rawCursor, sessionID)
		if err != nil {
			api.WriteBadRequest(w, "Invalid since cursor")
			return
		}
		limit := parseLimit(r.URL.Query().Get("limit"), 100, 1000)

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		flusher, ok := w.(http.Flusher)
		if !ok {
			api.WriteError(w, http.StatusInternalServerError, "Streaming unsupported", "response writer cannot flush")
			return
		}

		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			receipts, err := listReceiptsForCursor(r.Context(), svc, tenantID, sessionID, cursor, limit)
			if err != nil {
				fmt.Fprintf(w, "event: error\ndata: %q\n\n", err.Error())
				flusher.Flush()
			} else {
				for _, receipt := range receipts {
					nextCursor, cursorErr := receiptCursorForReceipt(sessionID, receipt)
					if cursorErr != nil {
						fmt.Fprintf(w, "event: error\ndata: %q\n\n", cursorErr.Error())
						flusher.Flush()
						break
					}
					eventID, cursorErr := formatReceiptCursor(sessionID, nextCursor)
					if cursorErr != nil {
						fmt.Fprintf(w, "event: error\ndata: %q\n\n", cursorErr.Error())
						flusher.Flush()
						break
					}
					cursor = nextCursor
					data, _ := json.Marshal(receipt)
					fmt.Fprintf(w, "id: %s\nevent: receipt\ndata: %s\n\n", eventID, data)
					flusher.Flush()
				}
			}

			select {
			case <-r.Context().Done():
				return
			case <-ticker.C:
			}
		}
	}))

	mux.HandleFunc("/api/v1/receipts", protectRuntimeHandler(RouteAuthTenant, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			api.WriteMethodNotAllowed(w)
			return
		}
		if svc.ReceiptStore == nil {
			api.WriteError(w, http.StatusServiceUnavailable, "Receipt store unavailable", "receipt store not initialized")
			return
		}
		tenantID, err := authenticatedReceiptTenantID(r.Context())
		if err != nil {
			api.WriteForbidden(w, "Receipt route requires authenticated tenant principal context")
			return
		}
		limit := parseLimit(r.URL.Query().Get("limit"), 100, 1000)
		sessionID := requestedReceiptSessionID(r)
		cursor, err := parseReceiptCursor(r.URL.Query().Get("since"), sessionID)
		if err != nil {
			api.WriteBadRequest(w, "Invalid since cursor")
			return
		}
		receipts, err := listReceiptsForCursor(r.Context(), svc, tenantID, sessionID, cursor, limit+1)
		if err != nil {
			api.WriteInternal(w, err)
			return
		}
		hasMore := len(receipts) > limit
		if hasMore {
			receipts = receipts[:limit]
		}
		nextCursor, err := nextReceiptCursor(sessionID, receipts)
		if err != nil {
			api.WriteInternal(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"receipts":    receipts,
			"count":       len(receipts),
			"next_cursor": nextCursor,
			"has_more":    hasMore,
		})
	}))

	mux.HandleFunc("/api/v1/receipts/", protectRuntimeHandler(RouteAuthTenant, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			api.WriteMethodNotAllowed(w)
			return
		}
		if svc.ReceiptStore == nil {
			api.WriteError(w, http.StatusServiceUnavailable, "Receipt store unavailable", "receipt store not initialized")
			return
		}
		tenantID, err := authenticatedReceiptTenantID(r.Context())
		if err != nil {
			api.WriteForbidden(w, "Receipt route requires authenticated tenant principal context")
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/api/v1/receipts/")
		if id == "" || strings.Contains(id, "/") {
			api.WriteBadRequest(w, "Invalid receipt id")
			return
		}
		receipt, err := receiptForTenant(r.Context(), svc, tenantID, id)
		if err != nil {
			api.WriteError(w, http.StatusNotFound, "Receipt not found", err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(receipt)
	}))
}

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

func requestedReceiptSessionID(r *http.Request) string {
	sessionID := strings.TrimSpace(r.URL.Query().Get("session_id"))
	if sessionID != "" {
		return sessionID
	}
	// Retain the old query spelling as an alias only. It is interpreted as a
	// signed session ID, never as an executor filter.
	return strings.TrimSpace(r.URL.Query().Get("agent"))
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

func listReceiptsForCursor(ctx context.Context, svc *Services, tenantID, sessionID string, cursor store.TenantReceiptCursor, limit int) ([]*contracts.Receipt, error) {
	if strings.TrimSpace(sessionID) != "" {
		reader, err := tenantScopedReceiptReader(svc)
		if err != nil {
			return nil, err
		}
		return reader.ListByTenantSession(ctx, tenantID, sessionID, cursor.LamportClock, limit)
	}
	if svc == nil || svc.ReceiptStore == nil {
		return nil, fmt.Errorf("receipt store unavailable")
	}
	reader, ok := svc.ReceiptStore.(store.TenantScopedReceiptCursorReader)
	if !ok {
		return nil, fmt.Errorf("receipt store lacks tenant-wide keyset cursor capability")
	}
	return reader.ListByTenantCursor(ctx, tenantID, cursor, limit)
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

func persistDecisionReceipt(ctx context.Context, svc *Services, decision *contracts.DecisionRecord, agentID string, body []byte, metadata map[string]any) error {
	return persistDecisionReceiptForTenant(ctx, svc, decision, agentID, "", body, metadata)
}

// persistDecisionReceiptForTenant may use the tenant-qualified causal-store
// capability only when the caller supplies an independently authenticated
// tenant ID. Generic paths intentionally remain unscoped rather than deriving
// a durable namespace from caller-controlled decision context.
func persistDecisionReceiptForTenant(ctx context.Context, svc *Services, decision *contracts.DecisionRecord, agentID, authenticatedTenantID string, body []byte, metadata map[string]any) error {
	if svc == nil || svc.ReceiptStore == nil || decision == nil {
		return fmt.Errorf("receipt persistence unavailable")
	}
	agentID = strings.TrimSpace(agentID)
	if agentID == "" {
		agentID = "anonymous"
	}
	argsHash := sha256HexBytes(body)
	receiptID := "rcpt_" + decision.ID
	effectID := decision.Action
	if effectID == "" {
		if action, ok := metadata["action"].(string); ok {
			effectID = action
		}
	}
	timestamp := decision.Timestamp.UTC()
	if timestamp.IsZero() {
		timestamp = time.Now().UTC()
	}
	if svc.ReceiptSigner == nil {
		return fmt.Errorf("receipt signer unavailable")
	}
	decisionHash, hashErr := helmcrypto.DecisionSemanticHash(decision)
	if hashErr != nil {
		return fmt.Errorf("derive semantic decision hash: %w", hashErr)
	}
	sessionID := ""
	if decision.InputContext != nil {
		if value, ok := decision.InputContext["session_id"].(string); ok {
			sessionID = strings.TrimSpace(value)
		}
	}
	if sessionID == "" {
		sessionID = agentID
	}
	if normalizer, ok := svc.ReceiptStore.(store.ReceiptTimestampNormalizer); ok {
		// The timestamp is part of the signed V5 receipt. Normalize it before
		// signing and transparency anchoring so a durable reload retains the
		// same chain hash.
		timestamp = normalizer.NormalizeReceiptTimestamp(timestamp)
	}
	build := func(_ *contracts.Receipt, lamport uint64, prevHash string) (*contracts.Receipt, error) {
		receipt := &contracts.Receipt{
			ReceiptID:    receiptID,
			DecisionID:   decision.ID,
			EffectID:     effectID,
			Status:       decision.Verdict,
			BlobHash:     argsHash,
			OutputHash:   decisionHash,
			DecisionHash: decisionHash,
			Timestamp:    timestamp,
			ExecutorID:   agentID,
			Verdict:      decision.Verdict,
			ReasonCode:   decision.ReasonCode,
			PolicyHash:   decision.PolicyContentHash,
			SessionID:    sessionID,
			Metadata:     metadata,
			PrevHash:     prevHash,
			LamportClock: lamport,
			ArgsHash:     argsHash,
		}
		if err := svc.ReceiptSigner.SignReceipt(receipt); err != nil {
			return nil, fmt.Errorf("sign receipt %s: %w", receiptID, err)
		}
		// Anchor the signed receipt hash in the transparency log before it is
		// persisted. Fail-closed: an append failure aborts the builder, which
		// rolls back AppendCausal so no receipt is stored. Degrade mode is the
		// only escape and must be explicitly enabled in config.
		if err := anchorReceiptTransparency(svc, receipt); err != nil {
			return nil, err
		}
		return receipt, nil
	}
	var err error
	if scoped, ok := svc.ReceiptStore.(store.TenantScopedCausalReceiptAppender); ok && strings.TrimSpace(authenticatedTenantID) != "" {
		err = scoped.AppendCausalScoped(ctx, strings.TrimSpace(authenticatedTenantID), sessionID, build)
	} else {
		err = svc.ReceiptStore.AppendCausal(ctx, sessionID, build)
	}
	if err != nil {
		return fmt.Errorf("store receipt %s: %w", receiptID, err)
	}
	return nil
}

// TransparencyAppender is the subset of the receipt transparency log needed at
// issuance time: append a receipt-hash leaf and report its assigned index.
type TransparencyAppender interface {
	Append(leafInput []byte) (uint64, error)
}

// anchorReceiptTransparency appends the signed receipt's content hash to the
// transparency log and records the resulting leaf on the receipt. It is
// fail-closed by default: if the log is configured but the append fails,
// issuance is aborted. When svc.TranspLogDegrade is set, an append failure
// instead records a deferred anchor so the receipt can be backfilled later.
// A nil log leaves the receipt unanchored (no transparency configured).
func anchorReceiptTransparency(svc *Services, receipt *contracts.Receipt) error {
	if svc == nil || svc.TranspLog == nil {
		return nil
	}
	leafHashHex, err := contracts.ReceiptChainHash(receipt)
	if err != nil {
		return fmt.Errorf("transparency leaf hash for %s: %w", receipt.ReceiptID, err)
	}
	leafInput, err := hex.DecodeString(leafHashHex)
	if err != nil {
		return fmt.Errorf("decode transparency leaf hash for %s: %w", receipt.ReceiptID, err)
	}
	index, appendErr := svc.TranspLog.Append(leafInput)
	if appendErr != nil {
		if !svc.TranspLogDegrade {
			return fmt.Errorf("transparency log append for %s: %w", receipt.ReceiptID, appendErr)
		}
		receipt.LogID = svc.TranspLogID
		receipt.Transparency = &contracts.TransparencyAnchor{
			Backend:  "translog",
			LogID:    svc.TranspLogID,
			Deferred: true,
		}
		return nil
	}
	receipt.LogID = svc.TranspLogID
	receipt.LeafIndex = index
	receipt.Transparency = &contracts.TransparencyAnchor{
		Backend: "translog",
		LogID:   svc.TranspLogID,
	}
	return nil
}

func receiptLinkHash(receipt *contracts.Receipt) string {
	if hash, err := contracts.ReceiptChainHash(receipt); err == nil {
		return hash
	}
	if receipt.MerkleRoot != "" {
		return sha256HexBytes([]byte(receipt.MerkleRoot))
	}
	return sha256HexBytes([]byte(receipt.ReceiptID))
}

func sha256HexBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
