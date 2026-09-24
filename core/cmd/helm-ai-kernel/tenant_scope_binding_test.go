package main

// S-08 regressions: the tenant/workspace scope binding runs with the
// emergency-stop fence off. Every Services here has EmergencyStops == nil,
// which is the default configuration; before HELM-755 each of these requests
// was accepted.

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/artifacts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/auth"
	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/guardian"
)

func evaluateScopeRequest(tenantID, principalID, workspaceID string) *http.Request {
	body := []byte(`{"action":"EXECUTE_TOOL","resource":"local.echo","context":{"session_id":"session-scope"}}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evaluate", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testAdminAPIKey)
	req.Header.Set(tenantHeader, tenantID)
	req.Header.Set(principalHeader, principalID)
	if workspaceID != "" {
		req.Header.Set(workspaceHeader, workspaceID)
	}
	return req
}

func TestEvaluateBindsTheConfiguredScopeWithTheFenceOff(t *testing.T) {
	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
	t.Setenv(runtimeTenantIDEnv, "tenant-a")
	t.Setenv(runtimePrincipalIDEnv, "principal-a")
	t.Setenv(runtimeWorkspaceIDEnv, "workspace-a")
	// tenant-b/principal-b is a registered binding, so it passes the route gate
	// and reaches the scope check.
	SetPrincipalBindingStore(&recordingPrincipalBindingStore{existsOK: true})
	t.Cleanup(func() { SetPrincipalBindingStore(nil) })
	svc, _ := newEvaluateRouteTestServices(t)
	mux := http.NewServeMux()
	registerReceiptRoutes(mux, svc)

	for _, test := range []struct {
		name string
		req  *http.Request
		want int
	}{
		{name: "configured scope", req: evaluateScopeRequest("tenant-a", "principal-a", "workspace-a"), want: http.StatusOK},
		{name: "foreign workspace", req: evaluateScopeRequest("tenant-a", "principal-a", "workspace-b"), want: http.StatusForbidden},
		{name: "workspace omitted", req: evaluateScopeRequest("tenant-a", "principal-a", ""), want: http.StatusForbidden},
		{name: "registered tenant outside the configured scope", req: evaluateScopeRequest("tenant-b", "principal-b", "workspace-a"), want: http.StatusForbidden},
	} {
		t.Run(test.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, test.req)
			if rec.Code != test.want {
				t.Fatalf("status=%d want %d body=%s", rec.Code, test.want, rec.Body.String())
			}
		})
	}
}

func TestReceiptReadsBindTheConfiguredScopeWithTheFenceOff(t *testing.T) {
	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
	t.Setenv(runtimeTenantIDEnv, "tenant-a")
	t.Setenv(runtimePrincipalIDEnv, "principal-a")
	t.Setenv(runtimeWorkspaceIDEnv, "workspace-a")
	svc, _ := newEvaluateRouteTestServices(t)
	mux := http.NewServeMux()
	registerReceiptRoutes(mux, svc)

	for workspace, want := range map[string]int{"": http.StatusForbidden, "workspace-b": http.StatusForbidden} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/receipts", nil)
		req.Header.Set("Authorization", "Bearer "+testAdminAPIKey)
		req.Header.Set(tenantHeader, "tenant-a")
		req.Header.Set(principalHeader, "principal-a")
		if workspace != "" {
			req.Header.Set(workspaceHeader, workspace)
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Fatalf("workspace %q: status=%d want %d body=%s", workspace, rec.Code, want, rec.Body.String())
		}
	}
}

func TestExtAuthzTakesTheScopeFromConfigurationNotTheBody(t *testing.T) {
	t.Setenv(serviceAPIKeyEnv, "route-secret")
	signer, err := helmcrypto.NewEd25519Signer("extauthz-scope-test")
	if err != nil {
		t.Fatal(err)
	}
	svc := &Services{
		Guardian:      guardian.NewGuardian(signer, allowGraphForExtAuthzTest("local.echo"), artifacts.NewRegistry(nil, nil)),
		ReceiptSigner: signer,
	}
	mux := http.NewServeMux()
	registerExtAuthzRoutes(mux, svc)
	authorize := func(tenantID string) int {
		body := mustJSONExtAuthzRoute(t, extAuthzRouteFixture("req-scope-"+tenantID, tenantID, "epoch-1"))
		req := httptest.NewRequest(http.MethodPost, extauthzAuthorizePath, bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer route-secret")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec.Code
	}

	t.Setenv(runtimeTenantIDEnv, "")
	t.Setenv(runtimeWorkspaceIDEnv, "")
	if got := authorize("tenant-victim"); got != http.StatusForbidden {
		t.Fatalf("unconfigured scope: a body-named tenant got status %d, want 403", got)
	}

	t.Setenv(runtimeTenantIDEnv, "tenant-a")
	t.Setenv(runtimeWorkspaceIDEnv, "workspace-a")
	if got := authorize("tenant-victim"); got != http.StatusForbidden {
		t.Fatalf("configured scope: a body-named foreign tenant got status %d, want 403", got)
	}
	if got := authorize("tenant-a"); got != http.StatusOK {
		t.Fatalf("configured scope: the configured tenant got status %d, want 200", got)
	}
}

func TestGovernedProxyBindsTheConfiguredScopeWithTheFenceOff(t *testing.T) {
	t.Setenv(runtimeTenantIDEnv, "tenant-a")
	t.Setenv(runtimeWorkspaceIDEnv, "workspace-a")
	proxy := func(tenantID, workspaceID string) int {
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(`{"model":"gpt-test","messages":[]}`))
		if workspaceID != "" {
			req.Header.Set(workspaceHeader, workspaceID)
		}
		ctx := auth.WithPrincipal(req.Context(), &auth.BasePrincipal{ID: "proxy-agent", TenantID: tenantID})
		req = req.WithContext(auth.WithAuthenticatedCredential(ctx, "proxy-credential"))
		rec := httptest.NewRecorder()
		handleGovernedOpenAIProxy(rec, req, &Services{})
		return rec.Code
	}
	if got := proxy("tenant-a", "workspace-b"); got != http.StatusForbidden {
		t.Fatalf("foreign workspace: status=%d want 403", got)
	}
	if got := proxy("tenant-b", ""); got != http.StatusForbidden {
		t.Fatalf("foreign tenant: status=%d want 403", got)
	}
	// OpenAI clients do not send X-Helm-Workspace-ID; the configured scope binds.
	if got := proxy("tenant-a", ""); got == http.StatusForbidden {
		t.Fatal("configured tenant without a workspace header was refused; the proxy binds the configured workspace")
	}
}
