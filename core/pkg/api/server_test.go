// quantum_posture: API receipt tests exercise a classical Ed25519 signer; no post-quantum assurance is claimed.
package api

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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
		OutputHash:       "sha256:output",
		Timestamp:        time.Date(2026, time.August, 1, 12, 34, 56, 123456789, time.FixedZone("test", 2*60*60)),
		SignatureVersion: contracts.ReceiptSignatureV5,
		Verdict:          "DENY",
		ReasonCode:       "POLICY_VIOLATION",
		PolicyHash:       "sha256:policy",
		SessionID:        "session-v5",
		DecisionHash:     "sha256:decision",
	}
	dto := FromCanonical(receipt)
	if dto.SignatureVersion != contracts.ReceiptSignatureV5 || dto.Verdict != receipt.Verdict || dto.ReasonCode != receipt.ReasonCode || dto.PolicyHash != receipt.PolicyHash || dto.SessionID != receipt.SessionID || dto.DecisionHash != receipt.DecisionHash {
		t.Fatalf("V5 receipt fields not preserved by API DTO: %+v", dto)
	}
	if dto.DecisionHash == receipt.OutputHash {
		t.Fatalf("API DTO must preserve canonical decision_hash when it differs from output_hash: %+v", dto)
	}
	if want := receipt.Timestamp.UTC().Format(time.RFC3339Nano); dto.Timestamp != want {
		t.Fatalf("API DTO timestamp = %q, want RFC3339Nano %q", dto.Timestamp, want)
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
	if stored.OutputHash != evaluated.DecisionHash || stored.DecisionHash != evaluated.DecisionHash {
		t.Fatalf("PDP decision hash must be bound by the V5 receipt: output_hash=%q decision_hash=%q response=%q", stored.OutputHash, stored.DecisionHash, evaluated.DecisionHash)
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
		"signature_version", "verdict", "reason_code", "decision_hash", "output_hash", "prev_hash", "lamport_clock", "args_hash", "policy_hash", "session_id",
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
	if received.DecisionHash != evaluated.DecisionHash || received.OutputHash != evaluated.DecisionHash {
		t.Fatalf("GET receipt did not preserve signed decision hash: %+v", received)
	}
	timestamp, err := time.Parse(time.RFC3339Nano, received.Timestamp)
	if err != nil {
		t.Fatalf("GET receipt timestamp must be RFC3339Nano: %q: %v", received.Timestamp, err)
	}

	fromGET := &contracts.Receipt{
		ReceiptID:           received.ReceiptID,
		DecisionID:          received.DecisionID,
		CorrelationID:       received.CorrelationID,
		EffectID:            received.EffectID,
		ExternalReferenceID: received.ExternalReferenceID,
		Status:              received.Status,
		OutputHash:          received.OutputHash,
		BlobHash:            received.BlobHash,
		Timestamp:           timestamp,
		ExecutorID:          received.ExecutorID,
		Metadata:            received.Metadata,
		Signature:           received.Signature,
		SignatureProfile:    received.SignatureProfile,
		SignatureAlgorithm:  received.SignatureAlgorithm,
		KeyID:               received.KeyID,
		PublicKeySet:        received.PublicKeySet,
		PrevHash:            received.PrevHash,
		LamportClock:        received.LamportClock,
		ArgsHash:            received.ArgsHash,
		SignatureVersion:    received.SignatureVersion,
		DecisionHash:        received.DecisionHash,
		Verdict:             received.Verdict,
		ReasonCode:          received.ReasonCode,
		PolicyHash:          received.PolicyHash,
		SessionID:           received.SessionID,
	}
	valid, version, err = helmcrypto.VerifyReceiptSignature(received.PublicKeySet[helmcrypto.SigPrefixEd25519], fromGET)
	if err != nil || !valid || version != helmcrypto.ReceiptPreimageSignedFieldsV5 {
		t.Fatalf("GET receipt is not independently verifiable as V5: valid=%v version=%q err=%v dto=%+v", valid, version, err, received)
	}
	storedHash, err := contracts.ReceiptChainHash(stored)
	if err != nil {
		t.Fatalf("hash stored receipt: %v", err)
	}
	returnedHash, err := contracts.ReceiptChainHash(fromGET)
	if err != nil {
		t.Fatalf("hash GET receipt: %v", err)
	}
	if returnedHash != storedHash {
		t.Fatalf("GET receipt must reproduce canonical chain hash: got %q want %q", returnedHash, storedHash)
	}
}

func TestEvaluateFailsClosedWithoutProductionReceiptSigner(t *testing.T) {
	t.Setenv("HELM_PRODUCTION", "true")
	helmPDP := pdp.NewHelmPDP("test-v1", map[string]bool{"read_file": true})
	srv := NewServer(ServerConfig{PDP: helmPDP, Authenticator: testAPIAuthenticator})
	reqBody, err := json.Marshal(EvaluateRequest{Tool: "read_file", EffectLevel: "read_file", SessionID: "no-signer"})
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

func TestEvaluateRejectsBlankSessionIDBeforeReceiptIssuance(t *testing.T) {
	for _, tc := range []struct {
		name string
		body EvaluateRequest
	}{
		{name: "missing", body: EvaluateRequest{Tool: "read_file", EffectLevel: "read_file"}},
		{name: "whitespace", body: EvaluateRequest{Tool: "read_file", EffectLevel: "read_file", SessionID: " \t\n "}},
		{name: "context whitespace", body: EvaluateRequest{Tool: "read_file", EffectLevel: "read_file", Context: map[string]any{"session_id": " \t\n "}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := newTestServer(t)
			reqBody, err := json.Marshal(tc.body)
			if err != nil {
				t.Fatalf("marshal request: %v", err)
			}

			w := httptest.NewRecorder()
			srv.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/evaluate", bytes.NewReader(reqBody)))
			if w.Code != http.StatusBadRequest {
				t.Fatalf("evaluate with blank session_id = %d, want 400: %s", w.Code, w.Body.String())
			}
			var response map[string]string
			if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if response["error"] != "session_id is required" {
				t.Fatalf("error = %q, want session_id is required", response["error"])
			}
			if len(srv.receipts) != 0 {
				t.Fatalf("blank session_id issued receipts: %+v", srv.receipts)
			}
		})
	}
}

func TestEvaluateRejectsBlankEffectiveIntentBeforeReceiptIssuance(t *testing.T) {
	for _, tc := range []struct {
		name string
		body EvaluateRequest
	}{
		{
			name: "whitespace canonical tool",
			body: EvaluateRequest{Tool: " \t\n ", EffectLevel: "read_file", SessionID: "session-tool"},
		},
		{
			name: "whitespace legacy action",
			body: EvaluateRequest{Tool: " \t\n ", Action: " \t\n ", EffectLevel: "read_file", SessionID: "session-action"},
		},
		{
			name: "whitespace canonical effect",
			body: EvaluateRequest{Tool: "read_file", EffectLevel: " \t\n ", SessionID: "session-effect"},
		},
		{
			name: "whitespace legacy resource",
			body: EvaluateRequest{Tool: "read_file", EffectLevel: " \t\n ", Resource: " \t\n ", SessionID: "session-resource"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := newTestServer(t)
			reqBody, err := json.Marshal(tc.body)
			if err != nil {
				t.Fatalf("marshal request: %v", err)
			}

			w := httptest.NewRecorder()
			srv.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/evaluate", bytes.NewReader(reqBody)))
			if w.Code != http.StatusBadRequest {
				t.Fatalf("evaluate with blank effective intent = %d, want 400: %s", w.Code, w.Body.String())
			}
			var response map[string]string
			if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if response["error"] != "tool and effect_level are required" {
				t.Fatalf("error = %q, want tool and effect_level are required", response["error"])
			}
			if len(srv.receipts) != 0 {
				t.Fatalf("blank effective intent issued receipts: %+v", srv.receipts)
			}
		})
	}
}

func TestEvaluateRejectsBlankSessionIDBeforeSignerAvailability(t *testing.T) {
	t.Setenv("HELM_PRODUCTION", "true")
	srv := NewServer(ServerConfig{
		PDP:           pdp.NewHelmPDP("test-v1", map[string]bool{"read_file": true}),
		Authenticator: testAPIAuthenticator,
	})
	reqBody, err := json.Marshal(EvaluateRequest{Tool: "read_file", EffectLevel: "read_file", Context: map[string]any{"session_id": " \t\n "}})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	w := httptest.NewRecorder()
	srv.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/evaluate", bytes.NewReader(reqBody)))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("evaluate with blank session_id and no signer = %d, want 400: %s", w.Code, w.Body.String())
	}
	if len(srv.receipts) != 0 {
		t.Fatalf("blank session_id issued receipts: %+v", srv.receipts)
	}
}

func TestEvaluateAcceptsCurrentAndLegacyRequestSessions(t *testing.T) {
	srv := NewServer(ServerConfig{
		PDP: pdp.NewHelmPDP("test-v1", map[string]bool{
			"modern-resource":  true,
			"context-resource": true,
			"legacy-resource":  true,
		}),
		Authenticator: testAPIAuthenticator,
	})

	for _, tc := range []struct {
		name          string
		body          string
		wantSessionID string
		wantTool      string
	}{
		{
			name:          "current top-level session wins",
			body:          `{"tool":"modern-tool","effect_level":"modern-resource","session_id":"  modern-session  ","context":{"session_id":"context-session"}}`,
			wantSessionID: "modern-session",
			wantTool:      "modern-tool",
		},
		{
			name:          "current context session fallback",
			body:          `{"tool":"context-tool","effect_level":"context-resource","session_id":" \t ","context":{"session_id":"  context-session  "}}`,
			wantSessionID: "context-session",
			wantTool:      "context-tool",
		},
		{
			name:          "legacy decision request",
			body:          `{"principal":"untrusted","action":"legacy-tool","resource":"legacy-resource","context":{"session_id":"  legacy-session  "}}`,
			wantSessionID: "legacy-session",
			wantTool:      "legacy-tool",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			srv.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/evaluate", bytes.NewBufferString(tc.body)))
			if w.Code != http.StatusOK {
				t.Fatalf("evaluate status = %d: %s", w.Code, w.Body.String())
			}

			var response EvaluateResponse
			if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if !response.Allow {
				t.Fatalf("evaluate denied compatible request: %+v", response)
			}

			srv.mu.RLock()
			receipt := srv.receipts[response.ReceiptID]
			srv.mu.RUnlock()
			if receipt == nil {
				t.Fatal("evaluate did not retain a receipt")
			}
			if receipt.SessionID != tc.wantSessionID || receipt.EffectID != tc.wantTool {
				t.Fatalf("receipt = session %q, tool %q; want session %q, tool %q", receipt.SessionID, receipt.EffectID, tc.wantSessionID, tc.wantTool)
			}
		})
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
		SessionID:   "deny-session",
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
	reqBody, _ := json.Marshal(EvaluateRequest{Tool: "read_file", AgentID: "victim", EffectLevel: "read_file", SessionID: "s"})
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
	body := EvaluateRequest{Tool: "read_file", AgentID: "a", EffectLevel: "read_file", SessionID: "s"}
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

func TestEvaluateBuildsCanonicalReceiptChain(t *testing.T) {
	signer, err := helmcrypto.NewEd25519SignerFromSeed(bytes.Repeat([]byte{0x23}, ed25519.SeedSize), "api-chain-test")
	if err != nil {
		t.Fatalf("new receipt signer: %v", err)
	}
	srv := NewServer(ServerConfig{
		PDP:           pdp.NewHelmPDP("test-v1", map[string]bool{"read_file": true}),
		Authenticator: testAPIAuthenticator,
		ReceiptSigner: signer,
	})

	const sessionID = "canonical-chain-session"
	receiptIDs := make([]string, 0, 2)
	for i := 0; i < 2; i++ {
		reqBody, err := json.Marshal(EvaluateRequest{Tool: "read_file", AgentID: "a", EffectLevel: "read_file", SessionID: sessionID})
		if err != nil {
			t.Fatalf("marshal evaluate request %d: %v", i, err)
		}
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/evaluate", bytes.NewReader(reqBody)))
		if w.Code != http.StatusOK {
			t.Fatalf("evaluate %d status = %d: %s", i, w.Code, w.Body.String())
		}
		var response EvaluateResponse
		if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
			t.Fatalf("decode evaluate response %d: %v", i, err)
		}
		receiptIDs = append(receiptIDs, response.ReceiptID)
	}

	srv.mu.RLock()
	first := srv.receipts[receiptIDs[0]]
	second := srv.receipts[receiptIDs[1]]
	srv.mu.RUnlock()
	if first == nil || second == nil {
		t.Fatalf("stored chain receipts missing: first=%+v second=%+v", first, second)
	}
	if first.PrevHash != "" {
		t.Fatalf("genesis prev_hash = %q, want empty", first.PrevHash)
	}
	wantPrevHash, err := contracts.ReceiptChainHash(first)
	if err != nil {
		t.Fatalf("hash first receipt: %v", err)
	}
	if second.PrevHash != wantPrevHash {
		t.Fatalf("successor prev_hash = %q, want canonical receipt hash %q", second.PrevHash, wantPrevHash)
	}

	for i, wantPrevHash := range []string{"", wantPrevHash} {
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/receipts/"+receiptIDs[i], nil))
		if w.Code != http.StatusOK {
			t.Fatalf("GET receipt %d status = %d: %s", i, w.Code, w.Body.String())
		}
		var receipt ReceiptDTO
		if err := json.NewDecoder(w.Body).Decode(&receipt); err != nil {
			t.Fatalf("decode GET receipt %d: %v", i, err)
		}
		if receipt.PrevHash != wantPrevHash {
			t.Fatalf("GET receipt %d prev_hash = %q, want %q", i, receipt.PrevHash, wantPrevHash)
		}
	}

	w := httptest.NewRecorder()
	srv.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/verify/"+sessionID, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("verify chain status = %d: %s", w.Code, w.Body.String())
	}
	var result map[string]any
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("decode chain verification: %v", err)
	}
	if result["valid"] != true || result["receipts"] != float64(2) {
		t.Fatalf("canonical API chain did not verify: %+v", result)
	}

	srv.mu.Lock()
	second.PrevHash = "sha256:tampered"
	srv.mu.Unlock()
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/verify/"+sessionID, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("verify tampered chain status = %d: %s", w.Code, w.Body.String())
	}
	var tamperedResult map[string]any
	if err := json.NewDecoder(w.Body).Decode(&tamperedResult); err != nil {
		t.Fatalf("decode tampered chain verification: %v", err)
	}
	if tamperedResult["valid"] != false {
		t.Fatalf("tampered API chain verified: %+v", tamperedResult)
	}
}

func TestVerifyRejectsTamperedSignedReceipts(t *testing.T) {
	srv := newTestServer(t)
	issue := func(sessionID string) EvaluateResponse {
		t.Helper()
		body, err := json.Marshal(EvaluateRequest{Tool: "read_file", EffectLevel: "read_file", SessionID: sessionID})
		if err != nil {
			t.Fatalf("marshal evaluate request: %v", err)
		}
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/evaluate", bytes.NewReader(body)))
		if w.Code != http.StatusOK {
			t.Fatalf("evaluate %q = %d: %s", sessionID, w.Code, w.Body.String())
		}
		var response EvaluateResponse
		if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
			t.Fatalf("decode evaluate response: %v", err)
		}
		return response
	}
	verify := func(sessionID string) map[string]any {
		t.Helper()
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/verify/"+sessionID, nil))
		if w.Code != http.StatusOK {
			t.Fatalf("verify %q = %d: %s", sessionID, w.Code, w.Body.String())
		}
		var result map[string]any
		if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
			t.Fatalf("decode verify response: %v", err)
		}
		return result
	}

	// A singleton has no successor whose prev_hash could expose a mutation.
	single := issue("signed-singleton")
	srv.mu.Lock()
	srv.receipts[single.ReceiptID].OutputHash = "sha256:tampered-singleton"
	srv.mu.Unlock()
	if got := verify("signed-singleton")["valid"]; got != false {
		t.Fatalf("tampered signed singleton verified: %+v", got)
	}

	// A tampered tip also has no successor, so this relies on signature
	// verification rather than chain-link verification.
	_ = issue("signed-tip")
	tip := issue("signed-tip")
	srv.mu.Lock()
	srv.receipts[tip.ReceiptID].OutputHash = "sha256:tampered-tip"
	srv.mu.Unlock()
	if got := verify("signed-tip")["valid"]; got != false {
		t.Fatalf("tampered signed chain tip verified: %+v", got)
	}
}

func TestEvaluateScopesCausalSessionsByTenant(t *testing.T) {
	srv := NewServer(ServerConfig{
		PDP: pdp.NewHelmPDP("test-v1", map[string]bool{"read_file": true}),
		Authenticator: func(r *http.Request) (AuthenticatedPrincipal, error) {
			return AuthenticatedPrincipal{ID: "operator-" + r.Header.Get("X-Test-Tenant"), TenantID: r.Header.Get("X-Test-Tenant")}, nil
		},
	})
	const sessionID = "shared-caller-session"
	issue := func(tenantID string) EvaluateResponse {
		t.Helper()
		body, err := json.Marshal(EvaluateRequest{Tool: "read_file", EffectLevel: "read_file", SessionID: sessionID})
		if err != nil {
			t.Fatalf("marshal evaluate request: %v", err)
		}
		req := httptest.NewRequest(http.MethodPost, "/api/v1/evaluate", bytes.NewReader(body))
		req.Header.Set("X-Test-Tenant", tenantID)
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("evaluate tenant %q = %d: %s", tenantID, w.Code, w.Body.String())
		}
		var response EvaluateResponse
		if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
			t.Fatalf("decode evaluate response: %v", err)
		}
		return response
	}
	verify := func(tenantID string) map[string]any {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/verify/"+sessionID, nil)
		req.Header.Set("X-Test-Tenant", tenantID)
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("verify tenant %q = %d: %s", tenantID, w.Code, w.Body.String())
		}
		var result map[string]any
		if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
			t.Fatalf("decode verify response: %v", err)
		}
		return result
	}

	a := issue("tenant-a")
	b := issue("tenant-b")
	if a.LamportClock != 1 || b.LamportClock != 1 {
		t.Fatalf("same external session must start separate tenant chains at Lamport 1: a=%+v b=%+v", a, b)
	}
	srv.mu.RLock()
	for _, response := range []EvaluateResponse{a, b} {
		receipt := srv.receipts[response.ReceiptID]
		if receipt == nil || receipt.SessionID != sessionID || receipt.PrevHash != "" {
			srv.mu.RUnlock()
			t.Fatalf("tenant-scoped genesis receipt malformed: %+v", receipt)
		}
	}
	if len(srv.sessions) != 2 {
		srv.mu.RUnlock()
		t.Fatalf("tenant-qualified session map length = %d, want 2", len(srv.sessions))
	}
	srv.mu.RUnlock()
	for _, tenantID := range []string{"tenant-a", "tenant-b"} {
		result := verify(tenantID)
		if result["valid"] != true || result["receipts"] != float64(1) {
			t.Fatalf("tenant %q did not see its isolated valid chain: %+v", tenantID, result)
		}
	}
}

func TestEvaluateStartsCausalChainsAtOnePerSession(t *testing.T) {
	srv := newTestServer(t)

	responses := make([]EvaluateResponse, 0, 2)
	for _, sessionID := range []string{"session-a", "session-b"} {
		reqBody, err := json.Marshal(EvaluateRequest{Tool: "read_file", AgentID: "caller-supplied", EffectLevel: "read_file", SessionID: sessionID})
		if err != nil {
			t.Fatalf("marshal evaluate request for %s: %v", sessionID, err)
		}
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/evaluate", bytes.NewReader(reqBody)))
		if w.Code != http.StatusOK {
			t.Fatalf("evaluate %s status = %d: %s", sessionID, w.Code, w.Body.String())
		}
		var response EvaluateResponse
		if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
			t.Fatalf("decode evaluate response for %s: %v", sessionID, err)
		}
		responses = append(responses, response)
	}

	if responses[0].LamportClock != 1 || responses[1].LamportClock != 1 {
		t.Fatalf("new sessions should both start at Lamport 1: %+v", responses)
	}
	if responses[0].ReceiptID == responses[1].ReceiptID {
		t.Fatalf("separate session receipts must retain unique IDs: %+v", responses)
	}

	srv.mu.RLock()
	defer srv.mu.RUnlock()
	for _, response := range responses {
		receipt := srv.receipts[response.ReceiptID]
		if receipt == nil {
			t.Fatalf("receipt %q was not retained", response.ReceiptID)
		}
		if receipt.ExecutorID != "operator-1" {
			t.Fatalf("receipt executor = %q, want authenticated executor", receipt.ExecutorID)
		}
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
		body := EvaluateRequest{Tool: "read_file", AgentID: "a", EffectLevel: "read_file", SessionID: "s"}
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
