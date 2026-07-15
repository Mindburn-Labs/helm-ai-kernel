package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	helmauth "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/auth"
	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/guardian"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/prg"
)

func TestReadGovernedOpenAIRequestResetsBody(t *testing.T) {
	body := []byte(`{"model":"gpt-test","messages":[]}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	gotBody, gotMap, ok := readGovernedOpenAIRequest(rec, req)
	if !ok {
		t.Fatalf("readGovernedOpenAIRequest failed with status %d", rec.Code)
	}
	if !bytes.Equal(gotBody, body) {
		t.Fatalf("body bytes changed: %q", gotBody)
	}
	if gotMap["model"] != "gpt-test" {
		t.Fatalf("model = %v, want gpt-test", gotMap["model"])
	}
	resetBody, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(resetBody, body) {
		t.Fatalf("reset body = %q, want %q", resetBody, body)
	}
}

func TestReadGovernedOpenAIRequestRejectsOversize(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(make([]byte, governedOpenAIRequestMaxBytes+1)))
	rec := httptest.NewRecorder()

	if _, _, ok := readGovernedOpenAIRequest(rec, req); ok {
		t.Fatal("expected oversized request to fail")
	}
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusRequestEntityTooLarge)
	}
}

func TestGovernedOpenAIProxyRejectsMissingAuthenticatedTenantScope(t *testing.T) {
	signer, err := helmcrypto.NewEd25519Signer("openai-scope-test")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(`{"model":"gpt-test","messages":[]}`))
	rec := httptest.NewRecorder()

	// The JSON body must never be able to supply the tenant or principal that
	// the proxy uses for its governed decision.
	handleGovernedOpenAIProxy(rec, req, &Services{Guardian: guardian.NewGuardian(signer, prg.NewGraph(), nil)})

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
}

func TestGovernedOpenAIProxyDoesNotForwardWhenDecisionReceiptPersistenceFails(t *testing.T) {
	signer, err := helmcrypto.NewEd25519Signer("openai-receipt-test")
	if err != nil {
		t.Fatal(err)
	}
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"should-not-forward"}`))
	}))
	defer upstream.Close()
	t.Setenv("HELM_UPSTREAM_URL", upstream.URL)

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(`{"model":"gpt-test","messages":[]}`))
	req.Header.Set(sessionHeader, "session-openai-test")
	req = req.WithContext(helmauth.WithPrincipal(req.Context(), &helmauth.BasePrincipal{ID: "principal-test", TenantID: "tenant-test"}))
	rec := httptest.NewRecorder()

	// The empty policy graph yields a signed DENY decision. The important
	// boundary is that receipt persistence fails before either an allow or deny
	// decision can be exposed to an upstream provider.
	handleGovernedOpenAIProxy(rec, req, &Services{
		Guardian:      guardian.NewGuardian(signer, prg.NewGraph(), nil),
		ReceiptSigner: signer,
		ReceiptStore:  &captureReceiptStore{storeErr: errReceiptPersistenceTest},
	})

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusInternalServerError, rec.Body.String())
	}
	if got := upstreamCalls.Load(); got != 0 {
		t.Fatalf("upstream calls = %d, want 0 after receipt persistence failure", got)
	}
	if got := rec.Header().Get("X-Helm-Receipt-ID"); got != "" {
		t.Fatalf("receipt header = %q, want empty after receipt persistence failure", got)
	}
}

func TestGovernedOpenAIProxyEmitsPersistedReceiptID(t *testing.T) {
	signer, err := helmcrypto.NewEd25519Signer("openai-allow-test")
	if err != nil {
		t.Fatal(err)
	}
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		if got := r.Header.Get("Authorization"); got != "Bearer provider-secret" {
			t.Fatalf("upstream authorization = %q, want server-owned provider credential", got)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"chatcmpl-governed"}`))
	}))
	defer upstream.Close()
	t.Setenv("HELM_UPSTREAM_URL", upstream.URL+"/v1")
	t.Setenv("HELM_UPSTREAM_API_KEY", "provider-secret")

	receipts := &captureReceiptStore{}
	svc := &Services{
		Guardian:      guardian.NewGuardian(signer, allowGraphForExtAuthzTest("LLM_INFERENCE"), nil),
		ReceiptStore:  receipts,
		ReceiptSigner: signer,
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(`{"model":"gpt-test","messages":[]}`))
	req.Header.Set("Authorization", "Bearer helm-admin-secret")
	req.Header.Set(sessionHeader, "session-openai-test")
	req.Header.Set(workspaceHeader, "workspace-openai-test")
	req = req.WithContext(helmauth.WithPrincipal(req.Context(), &helmauth.BasePrincipal{ID: "principal-test", TenantID: "tenant-test"}))
	rec := httptest.NewRecorder()

	handleGovernedOpenAIProxy(rec, req, svc)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if got := upstreamCalls.Load(); got != 1 {
		t.Fatalf("upstream calls = %d, want 1", got)
	}
	if receipts.stored == nil {
		t.Fatal("expected persisted decision receipt")
	}
	wantReceiptID := decisionReceiptID(rec.Header().Get("X-Helm-Decision-ID"))
	if got := rec.Header().Get("X-Helm-Receipt-ID"); got != wantReceiptID {
		t.Fatalf("receipt header = %q, want %q", got, wantReceiptID)
	}
	if receipts.stored.ReceiptID != wantReceiptID {
		t.Fatalf("stored receipt ID = %q, want %q", receipts.stored.ReceiptID, wantReceiptID)
	}
}

func TestGovernedOpenAIProxyEmitsPersistedReceiptIDForDeniedDecision(t *testing.T) {
	signer, err := helmcrypto.NewEd25519Signer("openai-deny-test")
	if err != nil {
		t.Fatal(err)
	}
	receipts := &captureReceiptStore{}
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(`{"model":"gpt-test","messages":[]}`))
	req.Header.Set(sessionHeader, "session-openai-deny-test")
	req = req.WithContext(helmauth.WithPrincipal(req.Context(), &helmauth.BasePrincipal{ID: "principal-test", TenantID: "tenant-test"}))
	rec := httptest.NewRecorder()

	// An empty graph produces a signed DENY. The receipt header must still refer
	// to the persisted decision so a client can audit a blocked chat request.
	handleGovernedOpenAIProxy(rec, req, &Services{
		Guardian:      guardian.NewGuardian(signer, prg.NewGraph(), nil),
		ReceiptStore:  receipts,
		ReceiptSigner: signer,
	})

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}
	if receipts.stored == nil {
		t.Fatal("expected persisted decision receipt for denied request")
	}
	wantReceiptID := decisionReceiptID(rec.Header().Get("X-Helm-Decision-ID"))
	if got := rec.Header().Get("X-Helm-Receipt-ID"); got != wantReceiptID {
		t.Fatalf("receipt header = %q, want %q", got, wantReceiptID)
	}
	if receipts.stored.ReceiptID != wantReceiptID {
		t.Fatalf("stored receipt ID = %q, want %q", receipts.stored.ReceiptID, wantReceiptID)
	}
}

var errReceiptPersistenceTest = &openAIReceiptPersistenceError{}

type openAIReceiptPersistenceError struct{}

func (*openAIReceiptPersistenceError) Error() string { return "receipt persistence unavailable" }
