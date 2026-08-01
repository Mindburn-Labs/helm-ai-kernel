package api

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/pdp"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	helmPDP := pdp.NewHelmPDP("test-v1", map[string]bool{
		"read_file":  true,
		"list_dir":   true,
		"write_file": true,
	})
	return NewServer(ServerConfig{PDP: helmPDP, Authenticator: testAPIAuthenticator})
}

func testAPIAuthenticator(_ *http.Request) (AuthenticatedPrincipal, error) {
	return AuthenticatedPrincipal{ID: "operator-1", TenantID: "tenant-a", Roles: []string{"admin"}}, nil
}

func TestEvaluate_Allow(t *testing.T) {
	srv := newTestServer(t)
	body := EvaluateRequest{
		Tool:        "read_file",
		Args:        map[string]any{"path": "/tmp/test.txt"},
		AgentID:     "agent-001",
		EffectLevel: "E0",
		SessionID:   "session-001",
	}
	reqBody, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/evaluate", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp EvaluateResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if !resp.Allow {
		t.Error("expected ALLOW for read_file")
	}
	if resp.ReceiptID == "" {
		t.Error("ReceiptID should be generated")
	}
	if resp.LamportClock == 0 {
		t.Error("LamportClock should be > 0")
	}
	if resp.DecisionHash == "" {
		t.Error("DecisionHash should be set")
	}
}

func TestFromCanonicalPreservesReceiptV5Fields(t *testing.T) {
	receipt := &contracts.Receipt{
		ReceiptID:        "receipt-v5",
		DecisionID:       "decision-v5",
		SignatureVersion: contracts.ReceiptSignatureV5,
		Verdict:          "DENY",
		ReasonCode:       "POLICY_VIOLATION",
		PolicyHash:       "sha256:policy",
		SessionID:        "session-v5",
	}
	dto := FromCanonical(receipt)
	if dto.SignatureVersion != contracts.ReceiptSignatureV5 || dto.Verdict != receipt.Verdict || dto.ReasonCode != receipt.ReasonCode || dto.PolicyHash != receipt.PolicyHash || dto.SessionID != receipt.SessionID {
		t.Fatalf("V5 receipt fields not preserved by API DTO: %+v", dto)
	}
}

func TestEvaluateStoresAndReturnsVerifiableV5Receipt(t *testing.T) {
	signer, err := helmcrypto.NewEd25519SignerFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize), "api-v5-test")
	if err != nil {
		t.Fatalf("new receipt signer: %v", err)
	}
	helmPDP := pdp.NewHelmPDP("api-v5-policy", map[string]bool{"E4": false})
	srv := NewServer(ServerConfig{
		PDP:           helmPDP,
		Authenticator: testAPIAuthenticator,
		ReceiptSigner: signer,
	})
	body := EvaluateRequest{
		Tool:        "delete_file",
		Args:        map[string]any{"path": "/tmp/example"},
		EffectLevel: "E4",
		SessionID:   "api-v5-session",
	}
	reqBody, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/evaluate", bytes.NewReader(reqBody)))
	if w.Code != http.StatusOK {
		t.Fatalf("evaluate status = %d: %s", w.Code, w.Body.String())
	}
	var evaluated EvaluateResponse
	if err := json.NewDecoder(w.Body).Decode(&evaluated); err != nil {
		t.Fatalf("decode evaluate: %v", err)
	}
	if evaluated.Allow {
		t.Fatal("expected denied decision")
	}

	srv.mu.RLock()
	stored := srv.receipts[evaluated.ReceiptID]
	srv.mu.RUnlock()
	if stored == nil {
		t.Fatal("evaluate did not retain a receipt")
	}
	valid, version, err := helmcrypto.VerifyReceiptSignature(signer.PublicKey(), stored)
	if err != nil || !valid || version != helmcrypto.ReceiptPreimageSignedFieldsV5 {
		t.Fatalf("stored receipt must use the shared V5 signing path: valid=%v version=%q err=%v receipt=%+v", valid, version, err, stored)
	}

	w = httptest.NewRecorder()
	srv.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/receipts/"+evaluated.ReceiptID, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("get receipt status = %d: %s", w.Code, w.Body.String())
	}
	raw := map[string]json.RawMessage{}
	if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode receipt JSON fields: %v", err)
	}
	for _, field := range []string{
		"signature_version", "verdict", "reason_code", "output_hash", "prev_hash", "lamport_clock", "args_hash", "policy_hash", "session_id",
		"signature", "signature_profile", "signature_algorithm", "key_id", "public_key_set",
	} {
		if _, ok := raw[field]; !ok {
			t.Fatalf("GET receipt omitted advertised V5 field %q: %s", field, w.Body.String())
		}
	}
	var received ReceiptDTO
	if err := json.Unmarshal(w.Body.Bytes(), &received); err != nil {
		t.Fatalf("decode receipt DTO: %v", err)
	}
	if received.SignatureVersion != contracts.ReceiptSignatureV5 || received.Verdict != string(contracts.VerdictDeny) || received.ReasonCode != string(contracts.ReasonPDPDeny) || received.PolicyHash != helmPDP.PolicyHash() || received.SessionID != body.SessionID {
		t.Fatalf("GET receipt did not preserve signed governance fields: %+v", received)
	}
	if received.SignatureProfile != helmcrypto.ReceiptProfileClassical || received.SignatureAlgorithm != helmcrypto.SigPrefixEd25519 || received.KeyID != "api-v5-test" || received.PublicKeySet[helmcrypto.SigPrefixEd25519] == "" {
		t.Fatalf("GET receipt did not expose signer verification material: %+v", received)
	}

	fromGET := &contracts.Receipt{
		ReceiptID:        received.ReceiptID,
		DecisionID:       received.DecisionID,
		EffectID:         received.EffectID,
		Status:           received.Status,
		OutputHash:       received.OutputHash,
		PrevHash:         received.PrevHash,
		LamportClock:     received.LamportClock,
		ArgsHash:         received.ArgsHash,
		SignatureVersion: received.SignatureVersion,
		Verdict:          received.Verdict,
		ReasonCode:       received.ReasonCode,
		PolicyHash:       received.PolicyHash,
		SessionID:        received.SessionID,
		Signature:        received.Signature,
	}
	valid, version, err = helmcrypto.VerifyReceiptSignature(received.PublicKeySet[helmcrypto.SigPrefixEd25519], fromGET)
	if err != nil || !valid || version != helmcrypto.ReceiptPreimageSignedFieldsV5 {
		t.Fatalf("GET receipt is not independently verifiable as V5: valid=%v version=%q err=%v dto=%+v", valid, version, err, received)
	}
}

func TestEvaluateFailsClosedWithoutProductionReceiptSigner(t *testing.T) {
	t.Setenv("HELM_PRODUCTION", "true")
	helmPDP := pdp.NewHelmPDP("test-v1", map[string]bool{"read_file": true})
	srv := NewServer(ServerConfig{PDP: helmPDP, Authenticator: testAPIAuthenticator})
	reqBody, err := json.Marshal(EvaluateRequest{Tool: "read_file", SessionID: "no-signer"})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/evaluate", bytes.NewReader(reqBody)))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("evaluate without a production signer = %d, want 503: %s", w.Code, w.Body.String())
	}
	if len(srv.receipts) != 0 {
		t.Fatalf("fail-closed signer path stored receipts: %+v", srv.receipts)
	}
}

func TestEvaluate_Deny(t *testing.T) {
	// HelmPDP checks rules by Resource (mapped from EffectLevel).
	// Create a PDP with E4 explicitly denied.
	denyPDP := pdp.NewHelmPDP("test-v1", map[string]bool{
		"E4": false, // deny E4 (irreversible)
	})
	srv := NewServer(ServerConfig{PDP: denyPDP, Authenticator: testAPIAuthenticator})

	body := EvaluateRequest{
		Tool:        "delete_file",
		AgentID:     "agent-001",
		EffectLevel: "E4", // maps to Resource, which is denied
	}
	reqBody, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/evaluate", bytes.NewReader(reqBody))
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	var resp EvaluateResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Allow {
		t.Error("expected DENY for E4 effect level")
	}
}

func TestEvaluate_RequiresAuthentication(t *testing.T) {
	helmPDP := pdp.NewHelmPDP("test-v1", map[string]bool{"read_file": true})
	srv := NewServer(ServerConfig{PDP: helmPDP})
	reqBody, _ := json.Marshal(EvaluateRequest{Tool: "read_file", AgentID: "attacker", SessionID: "s"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evaluate", bytes.NewReader(reqBody))
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected fail-closed 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestEvaluate_UsesAuthenticatedPrincipalNotCallerAgent(t *testing.T) {
	srv := newTestServer(t)
	reqBody, _ := json.Marshal(EvaluateRequest{Tool: "read_file", AgentID: "victim", SessionID: "s"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evaluate", bytes.NewReader(reqBody))
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var evalResp EvaluateResponse
	if err := json.NewDecoder(w.Body).Decode(&evalResp); err != nil {
		t.Fatalf("decode evaluate: %v", err)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/receipts/"+evalResp.ReceiptID, nil)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("receipt expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var receipt ReceiptDTO
	if err := json.NewDecoder(w.Body).Decode(&receipt); err != nil {
		t.Fatalf("decode receipt: %v", err)
	}
	if receipt.ExecutorID != "operator-1" {
		t.Fatalf("receipt executor should come from authenticated principal, got %q", receipt.ExecutorID)
	}
	if got := receipt.Metadata["tenant_id"]; got != "tenant-a" {
		t.Fatalf("receipt tenant metadata = %v, want tenant-a", got)
	}
}

func TestEvaluate_InvalidMethod(t *testing.T) {
	srv := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/evaluate", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestGetReceipt(t *testing.T) {
	srv := newTestServer(t)

	// Evaluate to create a receipt
	body := EvaluateRequest{Tool: "read_file", AgentID: "a", SessionID: "s"}
	reqBody, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evaluate", bytes.NewReader(reqBody))
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	var evalResp EvaluateResponse
	json.NewDecoder(w.Body).Decode(&evalResp)

	// Get the receipt
	req = httptest.NewRequest(http.MethodGet, "/api/v1/receipts/"+evalResp.ReceiptID, nil)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var receipt ReceiptDTO
	json.NewDecoder(w.Body).Decode(&receipt)
	if receipt.ReceiptID != evalResp.ReceiptID {
		t.Error("receipt ID mismatch")
	}
	if receipt.Signature == "" {
		t.Error("signature should be set")
	}
}

func TestGetReceipt_NotFound(t *testing.T) {
	srv := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/receipts/nonexistent", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestVerifyChain(t *testing.T) {
	srv := newTestServer(t)

	// Create 3 receipts in same session
	for i := 0; i < 3; i++ {
		body := EvaluateRequest{Tool: "read_file", AgentID: "a", SessionID: "test-session"}
		reqBody, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/evaluate", bytes.NewReader(reqBody))
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
	}

	// Verify chain
	req := httptest.NewRequest(http.MethodGet, "/api/v1/verify/test-session", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	var result map[string]any
	json.NewDecoder(w.Body).Decode(&result)
	if result["valid"] != true {
		t.Error("chain should be valid")
	}
	if result["receipts"].(float64) != 3 {
		t.Errorf("expected 3 receipts, got %v", result["receipts"])
	}
}

func TestHealth(t *testing.T) {
	srv := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	var result map[string]any
	json.NewDecoder(w.Body).Decode(&result)
	if result["status"] != "ok" {
		t.Error("health should return ok")
	}
}

func TestCORS(t *testing.T) {
	// With no AllowedOrigins configured, CORS headers should NOT be set (secure default).
	srv := newTestServer(t)
	req := httptest.NewRequest(http.MethodOptions, "/api/v1/evaluate", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Error("OPTIONS should return 200 for preflight")
	}
	if w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("CORS origin should NOT be set when AllowedOrigins is nil (secure default)")
	}

	// With explicit AllowedOrigins, matching origin should be reflected.
	helmPDP := pdp.NewHelmPDP("test-v1", map[string]bool{"read_file": true})
	srvWithOrigins := NewServer(ServerConfig{
		PDP:            helmPDP,
		AllowedOrigins: []string{"https://app.example.com"},
	})
	req2 := httptest.NewRequest(http.MethodOptions, "/api/v1/evaluate", nil)
	req2.Header.Set("Origin", "https://app.example.com")
	w2 := httptest.NewRecorder()
	srvWithOrigins.ServeHTTP(w2, req2)
	if w2.Header().Get("Access-Control-Allow-Origin") != "https://app.example.com" {
		t.Errorf("expected CORS origin https://app.example.com, got %q", w2.Header().Get("Access-Control-Allow-Origin"))
	}
}

func TestLamportMonotonicity(t *testing.T) {
	srv := newTestServer(t)

	var lamports []uint64
	for i := 0; i < 5; i++ {
		body := EvaluateRequest{Tool: "read_file", AgentID: "a", SessionID: "s"}
		reqBody, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/evaluate", bytes.NewReader(reqBody))
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
		var resp EvaluateResponse
		json.NewDecoder(w.Body).Decode(&resp)
		lamports = append(lamports, resp.LamportClock)
	}

	for i := 1; i < len(lamports); i++ {
		if lamports[i] <= lamports[i-1] {
			t.Errorf("Lamport clocks not monotonic: %d <= %d", lamports[i], lamports[i-1])
		}
	}
}
