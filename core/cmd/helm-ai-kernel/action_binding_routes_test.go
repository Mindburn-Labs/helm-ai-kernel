package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/api"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/artifacts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/auth"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/guardian"
)

// The policy in newEvaluateRouteTestServices allows local.echo and nothing
// else. A request for any other action is refused whatever its context says.
func TestEvaluateRouteIgnoresCallerSuppliedToolNameForPolicyAction(t *testing.T) {
	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
	t.Setenv(runtimeTenantIDEnv, "tenant-trusted")
	t.Setenv(runtimePrincipalIDEnv, "principal-trusted")
	svc, receipts := newEvaluateRouteTestServices(t)
	mux := http.NewServeMux()
	registerReceiptRoutes(mux, svc)

	body := []byte(`{"tool":"db.drop_database","effect_level":"E4","session_id":"s-1","context":{"tool_name":"local.echo"}}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evaluate", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testAdminAPIKey)
	req.Header.Set(tenantHeader, "tenant-trusted")
	req.Header.Set(principalHeader, "principal-trusted")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("evaluate status = %d body=%s", rec.Code, rec.Body.String())
	}
	var response api.EvaluateResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Action != "db.drop_database" {
		t.Fatalf("response action = %q, want the requested tool", response.Action)
	}
	if response.Allow || response.Verdict != string(contracts.VerdictDeny) || response.ReasonCode != string(contracts.ReasonNoPolicy) {
		t.Fatalf("context.tool_name selected the policy rule for %s: allow=%t verdict=%s reason=%s signature_present=%t",
			response.Action, response.Allow, response.Verdict, response.ReasonCode, response.Signature != "")
	}
	if receipts.stored == nil || receipts.stored.Status != string(contracts.VerdictDeny) {
		t.Fatalf("refusal was not receipted as a denial: %+v", receipts.stored)
	}
}

// The governed proxy passes the whole request body as decision context. With
// no LLM_INFERENCE rule the request is refused and never reaches the provider.
func TestGovernedOpenAIProxyIgnoresRequestBodyToolNameForPolicyAction(t *testing.T) {
	var forwarded atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		forwarded.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[]}`))
	}))
	defer upstream.Close()
	t.Setenv("HELM_UPSTREAM_URL", upstream.URL)

	signer, err := helmcrypto.NewEd25519Signer("openai-action-binding-test")
	if err != nil {
		t.Fatal(err)
	}
	svc := &Services{
		Guardian:      guardian.NewGuardian(signer, allowGraphForExtAuthzTest("local.echo"), artifacts.NewRegistry(nil, nil)),
		ReceiptStore:  &captureReceiptStore{},
		ReceiptSigner: signer,
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(
		`{"model":"gpt-test","messages":[],"tool_name":"local.echo"}`,
	))
	req.Header.Set("Authorization", "Bearer provider-secret")
	req.Header.Set(workspaceHeader, "workspace-a")
	ctx := auth.WithPrincipal(req.Context(), &auth.BasePrincipal{ID: "proxy-agent", TenantID: "tenant-a"})
	ctx = auth.WithAuthenticatedCredential(ctx, "proxy-credential")
	rec := httptest.NewRecorder()
	handleGovernedOpenAIProxy(rec, req.WithContext(ctx), svc)

	if rec.Code != http.StatusForbidden || rec.Header().Get("X-Helm-Verdict") != string(contracts.VerdictDeny) {
		t.Fatalf("body tool_name selected the policy rule for LLM_INFERENCE: status=%d verdict=%s body=%s",
			rec.Code, rec.Header().Get("X-Helm-Verdict"), rec.Body.String())
	}
	if forwarded.Load() != 0 {
		t.Fatalf("refused request reached the provider %d time(s)", forwarded.Load())
	}
}
