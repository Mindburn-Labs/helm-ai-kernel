package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/api"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/guardian"
)

func registerReceiptRoutes(mux *http.ServeMux, svc *Services) {
	mux.HandleFunc("/api/v1/evaluate", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			api.WriteMethodNotAllowed(w)
			return
		}
		if svc.Guardian == nil {
			api.WriteError(w, http.StatusServiceUnavailable, "Guardian unavailable", "guardian not initialized")
			return
		}
		var req guardian.DecisionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			api.WriteBadRequest(w, "Invalid JSON body")
			return
		}
		if req.Principal == "" {
			req.Principal = "anonymous"
		}
		decision, err := svc.Guardian.EvaluateDecision(r.Context(), req)
		if err != nil {
			api.WriteInternal(w, err)
			return
		}
		if err := persistDecisionReceipt(r.Context(), svc, decision, req.Principal, []byte(req.Action+":"+req.Resource), map[string]any{
			"source":   "api.evaluate",
			"action":   req.Action,
			"resource": req.Resource,
			"reason":   decision.Reason,
		}); err != nil {
			api.WriteInternal(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(decision)
	})

	mux.HandleFunc("/api/v1/receipts/tail", protectRuntimeHandler(RouteAuthTenant, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			api.WriteMethodNotAllowed(w)
			return
		}
		if svc.ReceiptStore == nil {
			api.WriteError(w, http.StatusServiceUnavailable, "Receipt store unavailable", "receipt store not initialized")
			return
		}
		agent := r.URL.Query().Get("agent")
		since, err := parseReceiptCursor(r.URL.Query().Get("since"))
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
		cursor := since
		for {
			receipts, err := listReceiptsForCursor(r.Context(), svc, agent, cursor, limit)
			if err != nil {
				fmt.Fprintf(w, "event: error\ndata: %q\n\n", err.Error())
				flusher.Flush()
			} else {
				for _, receipt := range receipts {
					if receipt.LamportClock > cursor {
						cursor = receipt.LamportClock
					}
					data, _ := json.Marshal(receipt)
					fmt.Fprintf(w, "id: %d\nevent: receipt\ndata: %s\n\n", receipt.LamportClock, data)
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
		limit := parseLimit(r.URL.Query().Get("limit"), 100, 1000)
		since, err := parseReceiptCursor(r.URL.Query().Get("since"))
		if err != nil {
			api.WriteBadRequest(w, "Invalid since cursor")
			return
		}
		receipts, err := listReceiptsForCursor(r.Context(), svc, r.URL.Query().Get("agent"), since, limit+1)
		if err != nil {
			api.WriteInternal(w, err)
			return
		}
		hasMore := len(receipts) > limit
		if hasMore {
			receipts = receipts[:limit]
		}
		nextCursor := nextReceiptCursor(receipts)
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
		id := strings.TrimPrefix(r.URL.Path, "/api/v1/receipts/")
		if id == "" || strings.Contains(id, "/") {
			api.WriteBadRequest(w, "Invalid receipt id")
			return
		}
		receipt, err := svc.ReceiptStore.GetByReceiptID(r.Context(), id)
		if err != nil {
			api.WriteError(w, http.StatusNotFound, "Receipt not found", err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(receipt)
	}))
}

func listReceiptsForCursor(ctx context.Context, svc *Services, agent string, since uint64, limit int) ([]*contracts.Receipt, error) {
	if agent != "" {
		return svc.ReceiptStore.ListByAgent(ctx, agent, since, limit)
	}
	return svc.ReceiptStore.ListSince(ctx, since, limit)
}

func parseReceiptCursor(raw string) (uint64, error) {
	raw = strings.TrimSpace(strings.TrimPrefix(raw, "lamport:"))
	if raw == "" {
		return 0, nil
	}
	return strconv.ParseUint(raw, 10, 64)
}

func nextReceiptCursor(receipts []*contracts.Receipt) string {
	var cursor uint64
	for _, receipt := range receipts {
		if receipt.LamportClock > cursor {
			cursor = receipt.LamportClock
		}
	}
	if cursor == 0 {
		return ""
	}
	return fmt.Sprintf("lamport:%d", cursor)
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
	err := svc.ReceiptStore.AppendCausal(ctx, agentID, func(_ *contracts.Receipt, lamport uint64, prevHash string) (*contracts.Receipt, error) {
		receipt := &contracts.Receipt{
			ReceiptID:    receiptID,
			DecisionID:   decision.ID,
			EffectID:     effectID,
			Status:       decision.Verdict,
			BlobHash:     argsHash,
			OutputHash:   decision.PolicyDecisionHash,
			Timestamp:    timestamp,
			ExecutorID:   agentID,
			Metadata:     metadata,
			PrevHash:     prevHash,
			LamportClock: lamport,
			ArgsHash:     argsHash,
		}
		if err := svc.ReceiptSigner.SignReceipt(receipt); err != nil {
			return nil, fmt.Errorf("sign receipt %s: %w", receiptID, err)
		}
		return receipt, nil
	})
	if err != nil {
		return fmt.Errorf("store receipt %s: %w", receiptID, err)
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
