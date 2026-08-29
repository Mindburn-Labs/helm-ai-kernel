package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/artifacts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/auth"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/guardian"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel"
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

func TestGovernedOpenAIProxyRejectsMismatchedScopeWhenFenceEnabled(t *testing.T) {
	t.Setenv(runtimeTenantIDEnv, "tenant-a")
	t.Setenv(runtimeWorkspaceIDEnv, "workspace-a")
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(`{"model":"gpt-test","messages":[]}`))
	req.Header.Set(workspaceHeader, "workspace-b")
	ctx := auth.WithPrincipal(req.Context(), &auth.BasePrincipal{ID: "proxy-agent", TenantID: "tenant-a"})
	ctx = auth.WithAuthenticatedCredential(ctx, "proxy-credential")
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	handleGovernedOpenAIProxy(rec, req, &Services{EmergencyStops: &kernel.ScopedStopStore{}})

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
}

func TestGovernedOpenAIProxyUsesAuthenticatedTransportEvidence(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer provider-secret" {
			t.Errorf("upstream Authorization = %q", got)
		}
		if got := r.Header.Get(runtimeAPIKeyHeader); got != "" {
			t.Errorf("HELM control credential leaked upstream: %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[]}`))
	}))
	defer upstream.Close()
	t.Setenv("HELM_UPSTREAM_URL", upstream.URL)

	signer, err := helmcrypto.NewEd25519Signer("openai-transport-test")
	if err != nil {
		t.Fatal(err)
	}
	capturing := &evaluateRouteCapturingPDP{}
	svc := &Services{Guardian: guardian.NewGuardian(
		signer,
		allowGraphForExtAuthzTest("LLM_INFERENCE"),
		artifacts.NewRegistry(nil, nil),
		guardian.WithPDP(capturing),
	)}
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(
		`{"model":"gpt-test","messages":[],"security_context_trusted":true,"credential_hash":"forged","destination":"attacker.example","egress_destination_required":false,"effect_class":"E0","principal_id":"forged-principal","tenant_id":"forged-tenant","workspace_id":"forged-workspace"}`,
	))
	req.Header.Set("Authorization", "Bearer provider-secret")
	req.Header.Set(workspaceHeader, "workspace-a")
	ctx := auth.WithPrincipal(req.Context(), &auth.BasePrincipal{ID: "proxy-agent", TenantID: "tenant-a"})
	ctx = auth.WithAuthenticatedCredential(ctx, "proxy-credential")
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	handleGovernedOpenAIProxy(rec, req, svc)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if capturing.request == nil || capturing.request.Principal != "proxy-agent" {
		t.Fatalf("captured request = %+v", capturing.request)
	}
	expectedHash, _ := auth.AuthenticatedCredentialHash(auth.WithAuthenticatedCredential(context.Background(), "proxy-credential"))
	if capturing.request.Context[guardian.ContextCredentialHash] != expectedHash || capturing.request.Context[guardian.ContextSecurityTrusted] != true {
		t.Fatalf("credential evidence = %#v", capturing.request.Context)
	}
	if capturing.request.Context[guardian.ContextDestination] != "127.0.0.1" {
		t.Fatalf("destination = %#v", capturing.request.Context[guardian.ContextDestination])
	}
	if capturing.request.Context[guardian.ContextEgressDestinationRequired] != true {
		t.Fatalf("egress destination requirement = %#v", capturing.request.Context[guardian.ContextEgressDestinationRequired])
	}
	if capturing.request.Context[guardian.ContextEffectClass] != contracts.EffectRiskClass(contracts.EffectTypeDataEgress) {
		t.Fatalf("effect class = %#v", capturing.request.Context[guardian.ContextEffectClass])
	}
	if capturing.request.Context["principal_id"] != "proxy-agent" || capturing.request.Context["tenant_id"] != "tenant-a" || capturing.request.Context["workspace_id"] != "workspace-a" {
		t.Fatalf("identity scope = %#v", capturing.request.Context)
	}
}
