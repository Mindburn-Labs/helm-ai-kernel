package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/tracing"
)

// The API server is an external ingress edge, so it must apply the
// adopt-or-mint rule of the pilot business-telemetry contract (§2.2):
// adopt a valid inbound X-Helm-Correlation-ID, mint otherwise, always echo
// the ID used, and stamp it into the stored receipt.

func evaluateWithHeader(t *testing.T, srv *Server, inbound string) (*httptest.ResponseRecorder, EvaluateResponse) {
	t.Helper()
	body := EvaluateRequest{
		Tool:        "read_file",
		Args:        map[string]any{"path": "/tmp/test.txt"},
		EffectLevel: "E0",
		SessionID:   "session-corr",
	}
	reqBody, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshaling request body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evaluate", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	if inbound != "" {
		req.Header.Set("X-Helm-Correlation-ID", inbound)
	}
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp EvaluateResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	return w, resp
}

func TestCorrelationEdge_AdoptsValidInboundAndStampsReceipt(t *testing.T) {
	srv := newTestServer(t)
	const inbound = "d2f1c3a4-5b6e-4f70-8a91-b2c3d4e5f601"

	w, resp := evaluateWithHeader(t, srv, inbound)

	if echoed := w.Header().Get("X-Helm-Correlation-ID"); echoed != inbound {
		t.Errorf("echoed correlation ID = %q, want adopted %q", echoed, inbound)
	}
	srv.mu.RLock()
	receipt := srv.receipts[resp.ReceiptID]
	srv.mu.RUnlock()
	if receipt == nil {
		t.Fatalf("receipt %q not stored", resp.ReceiptID)
	}
	if receipt.CorrelationID != inbound {
		t.Errorf("receipt.CorrelationID = %q, want %q", receipt.CorrelationID, inbound)
	}
}

func TestCorrelationEdge_MintsOnInvalidInbound(t *testing.T) {
	srv := newTestServer(t)
	const garbage = "not-a-uuid" // must never be adopted

	w, resp := evaluateWithHeader(t, srv, garbage)

	echoed := w.Header().Get("X-Helm-Correlation-ID")
	if echoed == garbage {
		t.Fatal("garbage inbound correlation ID was adopted")
	}
	if !tracing.IsValidCorrelationID(echoed) {
		t.Errorf("echoed minted ID %q is not canonically valid", echoed)
	}
	srv.mu.RLock()
	receipt := srv.receipts[resp.ReceiptID]
	srv.mu.RUnlock()
	if receipt == nil {
		t.Fatalf("receipt %q not stored", resp.ReceiptID)
	}
	if receipt.CorrelationID != echoed {
		t.Errorf("receipt.CorrelationID = %q, want echoed %q", receipt.CorrelationID, echoed)
	}
}
