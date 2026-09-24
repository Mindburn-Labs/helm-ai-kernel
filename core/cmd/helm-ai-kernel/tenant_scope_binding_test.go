package main

// S-08 scope binding. With the emergency-stop fence on, the Kernel binds the
// configured tenant and workspace. With it off, nothing is bound yet (known gap,
// waiting on tenant-from-token): deployed Control Planes call fence-off Kernels
// with each session's real tenant, and those calls must keep answering.
// Ext-authz is bound to the configured scope in both modes.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/api"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/artifacts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/auth"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/guardian"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel"
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

// The deployed QA and staging shape: fence off, chart-default scope
// "default"/"default", and a Control Plane asserting a session's real tenant.
// Every Control Plane route must answer as it did before HELM-755.
func TestFenceOffControlPlaneCallersKeepTheirPreviousBehavior(t *testing.T) {
	const (
		cpTenant    = "7c9e6679-7425-40de-944b-e07fc1f90ae7"
		cpPrincipal = "b3f1c2de-2f4a-4c55-9a0e-1f2d3c4b5a69"
		cpWorkspace = "3fa85f64-5717-4562-b3fc-2c963f66afa6"
	)
	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
	t.Setenv(organizationRuntimeAPIKeyEnv, testOrganizationRuntimeAPIKey)
	t.Setenv(runtimeTenantIDEnv, "default")
	t.Setenv(runtimePrincipalIDEnv, "default")
	t.Setenv(runtimeWorkspaceIDEnv, "default")
	SetPrincipalBindingStore(&recordingPrincipalBindingStore{existsOK: true})
	t.Cleanup(func() { SetPrincipalBindingStore(nil) })
	identify := func(req *http.Request, token string) *http.Request {
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set(tenantHeader, cpTenant)
		req.Header.Set(principalHeader, cpPrincipal)
		req.Header.Set(workspaceHeader, cpWorkspace)
		return req
	}

	evaluateSvc, _ := newEvaluateRouteTestServices(t)
	// No activation key: organization-runtime evaluation ends in a signed
	// activation denial, which still proves the scope binding let it through.
	evaluateSvc.CompanyActivationEnvironmentID = "managed"
	evaluateMux := http.NewServeMux()
	registerReceiptRoutes(evaluateMux, evaluateSvc)
	receiptSvc, cleanup := newContractRouteTestServices(t)
	t.Cleanup(cleanup)
	receiptMux := http.NewServeMux()
	registerReceiptRoutes(receiptMux, receiptSvc)

	orgBody, err := json.Marshal(api.EvaluateRequest{
		Tool: "EXECUTE_TOOL", Resource: "connector://crm/contact-123", EffectLevel: "E1", SessionID: "cp-session",
		Originator: &contracts.OrganizationRuntimeOriginatorAssertion{
			PrincipalID: "human-originator-1", AssertionSource: contracts.OrganizationRuntimeOriginatorAssertionSourceControlPlane,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	orgRequest := identify(httptest.NewRequest(http.MethodPost, companyActivationOrganizationRuntimePath, bytes.NewReader(orgBody)), testOrganizationRuntimeAPIKey)
	orgRequest.Header.Set(companyActivationExecutionProfileHeader, companyActivationOrganizationRuntimeProfile)

	for _, test := range []struct {
		name string
		mux  http.Handler
		req  *http.Request
		want int
	}{
		{name: "evaluate", mux: evaluateMux, req: evaluateScopeRequest(cpTenant, cpPrincipal, cpWorkspace), want: http.StatusOK},
		{name: "organization runtime evaluate", mux: evaluateMux, req: orgRequest, want: http.StatusOK},
		{name: "receipt list", mux: receiptMux, req: identify(httptest.NewRequest(http.MethodGet, "/api/v1/receipts", nil), testAdminAPIKey), want: http.StatusOK},
		{name: "receipt by id", mux: receiptMux, req: identify(httptest.NewRequest(http.MethodGet, "/api/v1/receipts/rcpt-test", nil), testAdminAPIKey), want: http.StatusNotFound},
	} {
		t.Run(test.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			test.mux.ServeHTTP(rec, test.req)
			if rec.Code != test.want {
				t.Fatalf("status=%d want %d body=%s", rec.Code, test.want, rec.Body.String())
			}
		})
	}

	// The proxy has no upstream here, so an unbound request ends at 503.
	proxyRequest := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(`{"model":"gpt-test","messages":[]}`))
	proxyRequest.Header.Set(workspaceHeader, cpWorkspace)
	ctx := auth.WithPrincipal(proxyRequest.Context(), &auth.BasePrincipal{ID: cpPrincipal, TenantID: cpTenant})
	proxyRequest = proxyRequest.WithContext(auth.WithAuthenticatedCredential(ctx, "proxy-credential"))
	rec := httptest.NewRecorder()
	handleGovernedOpenAIProxy(rec, proxyRequest, &Services{})
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("proxy status=%d want 503 body=%s", rec.Code, rec.Body.String())
	}
}

// Fence on, receipt reads now bind the configured tenant as evaluate already
// did: a registered binding for another tenant cannot read with the fenced
// workspace header.
func TestFencedReceiptReadsBindTheConfiguredTenant(t *testing.T) {
	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
	t.Setenv(runtimeTenantIDEnv, "tenant-a")
	t.Setenv(runtimePrincipalIDEnv, "principal-a")
	t.Setenv(runtimeWorkspaceIDEnv, "workspace-a")
	SetPrincipalBindingStore(&recordingPrincipalBindingStore{existsOK: true})
	t.Cleanup(func() { SetPrincipalBindingStore(nil) })
	svc, cleanup := newContractRouteTestServices(t)
	t.Cleanup(cleanup)
	svc.EmergencyStops = &kernel.ScopedStopStore{}
	mux := http.NewServeMux()
	registerReceiptRoutes(mux, svc)

	read := func(tenantID, principalID string) int {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/receipts", nil)
		req.Header.Set("Authorization", "Bearer "+testAdminAPIKey)
		req.Header.Set(tenantHeader, tenantID)
		req.Header.Set(principalHeader, principalID)
		req.Header.Set(workspaceHeader, "workspace-a")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec.Code
	}
	if got := read("tenant-b", "principal-b"); got != http.StatusForbidden {
		t.Fatalf("fenced receipt read by another registered tenant: status=%d want 403", got)
	}
	if got := read("tenant-a", "principal-a"); got != http.StatusOK {
		t.Fatalf("fenced receipt read by the configured tenant: status=%d want 200", got)
	}
}
