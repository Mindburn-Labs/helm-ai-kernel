package main

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/api"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

func registerProofGraphContractRoutes(mux routeMux, svc *Services) {
	mux.HandleFunc("/api/v1/proofgraph/sessions", protectRuntimeHandler(RouteAuthTenant, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			api.WriteMethodNotAllowed(w)
			return
		}
		tenantID, err := authenticatedReceiptTenantID(r.Context())
		if err != nil {
			api.WriteForbidden(w, "ProofGraph route requires authenticated tenant principal context")
			return
		}
		receipts, err := canonicalContractReceipts(r.Context(), svc, tenantID, "", parseLimit(r.URL.Query().Get("limit"), 50, 1000))
		if err != nil {
			api.WriteInternalR(w, r, err)
			return
		}
		sessions := proofgraphSessions(receipts)
		offset := parseLimit(r.URL.Query().Get("offset"), 0, len(sessions))
		if offset > len(sessions) {
			offset = len(sessions)
		}
		writeContractJSON(w, http.StatusOK, sessions[offset:])
	}))

	mux.HandleFunc("/api/v1/proofgraph/sessions/", protectRuntimeHandler(RouteAuthTenant, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			api.WriteMethodNotAllowed(w)
			return
		}
		suffix := strings.TrimPrefix(r.URL.Path, "/api/v1/proofgraph/sessions/")
		sessionID, ok := strings.CutSuffix(suffix, "/receipts")
		if !ok {
			api.WriteNotFound(w, "proofgraph session route not found")
			return
		}
		var err error
		sessionID, err = api.NormalizePublicSessionID(sessionID)
		if err != nil {
			api.WriteNotFound(w, "proofgraph session route not found")
			return
		}
		tenantID, err := authenticatedReceiptTenantID(r.Context())
		if err != nil {
			api.WriteForbidden(w, "ProofGraph route requires authenticated tenant principal context")
			return
		}
		receipts, err := canonicalContractReceipts(r.Context(), svc, tenantID, sessionID, parseLimit(r.URL.Query().Get("limit"), 100, 1000))
		if err != nil {
			api.WriteInternalR(w, r, err)
			return
		}
		if len(receipts) == 0 {
			api.WriteNotFound(w, "session not found")
			return
		}
		writeContractJSON(w, http.StatusOK, receipts)
	}))

	mux.HandleFunc("/api/v1/proofgraph/receipts/", protectRuntimeHandler(RouteAuthTenant, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			api.WriteMethodNotAllowed(w)
			return
		}
		receiptRef := strings.TrimPrefix(r.URL.Path, "/api/v1/proofgraph/receipts/")
		if receiptRef == "" || strings.Contains(receiptRef, "/") {
			api.WriteBadRequest(w, "Invalid receipt reference")
			return
		}
		tenantID, err := authenticatedReceiptTenantID(r.Context())
		if err != nil {
			api.WriteForbidden(w, "ProofGraph route requires authenticated tenant principal context")
			return
		}
		receipt, err := findReceiptByReference(r.Context(), svc, tenantID, receiptRef)
		if err != nil {
			api.WriteNotFound(w, err.Error())
			return
		}
		writeContractJSON(w, http.StatusOK, receipt)
	}))
}

func proofgraphSessions(receipts []*contracts.Receipt) []map[string]any {
	bySession := make(map[string]map[string]any)
	for _, receipt := range receipts {
		sessionID := receipt.SessionID
		if strings.TrimSpace(sessionID) == "" {
			sessionID = "anonymous"
		}
		row, ok := bySession[sessionID]
		if !ok {
			row = map[string]any{
				"session_id":         sessionID,
				"created_at":         receipt.Timestamp.UTC().Format(time.RFC3339Nano),
				"receipt_count":      0,
				"last_lamport_clock": uint64(0),
			}
			bySession[sessionID] = row
		}
		row["receipt_count"] = row["receipt_count"].(int) + 1
		if receipt.LamportClock > row["last_lamport_clock"].(uint64) {
			row["last_lamport_clock"] = receipt.LamportClock
		}
		if createdAt, _ := time.Parse(time.RFC3339Nano, row["created_at"].(string)); !receipt.Timestamp.IsZero() && receipt.Timestamp.Before(createdAt) {
			row["created_at"] = receipt.Timestamp.UTC().Format(time.RFC3339Nano)
		}
	}
	sessions := make([]map[string]any, 0, len(bySession))
	for _, row := range bySession {
		sessions = append(sessions, row)
	}
	sort.Slice(sessions, func(i, j int) bool {
		return sessions[i]["session_id"].(string) < sessions[j]["session_id"].(string)
	})
	return sessions
}

func findReceiptByReference(ctx context.Context, svc *Services, tenantID, ref string) (*contracts.Receipt, error) {
	if svc == nil || svc.ReceiptStore == nil {
		return nil, fmt.Errorf("receipt store unavailable")
	}
	if receipt, err := canonicalReceiptForTenant(ctx, svc, tenantID, ref); err == nil {
		return receipt, nil
	}
	receipts, err := contractReceipts(ctx, svc, tenantID, "", 1000)
	if err != nil {
		return nil, err
	}
	for _, receipt := range receipts {
		if receiptLinkHash(receipt) == ref || receipt.Signature == ref || receipt.MerkleRoot == ref {
			return canonicalReceiptForTenant(ctx, svc, tenantID, receipt.ReceiptID)
		}
	}
	return nil, fmt.Errorf("receipt not found")
}
