package main

// HELM-755 S-05 / §10.2: a data-level cross-tenant negative for every
// tenant_scoped route, generated from the route registry. Tenant A owns the
// seeded receipts; tenant B is a registered binding, so it passes the route
// gate. Every tenant_scoped route is called as B, and B must never see A's
// data. The route-level gate negatives live in route_audit_test.go.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// tenantDataScope says how each tenant_scoped route keeps tenants apart. A
// tenant_scoped route without an entry fails TestEveryTenantRouteDeclaresItsDataScope.
const (
	// tenantKeyedStore: reads and writes go through a store keyed by the
	// authenticated tenant (the receipt store and what is derived from it).
	tenantKeyedStore = "tenant-keyed store"
	// configuredTenantStore: the store has no tenant dimension, so the route
	// serves only the configured tenant (protectConfiguredTenantStore).
	configuredTenantStore = "configured-tenant store"
	// noTenantData: static or caller-supplied content, no stored tenant data.
	noTenantData = "no stored tenant data"
)

var tenantDataScope = map[string]string{
	"/api/v1/evaluate":                      tenantKeyedStore,
	"/api/v1/receipts":                      tenantKeyedStore,
	"/api/v1/receipts/":                     tenantKeyedStore,
	"/api/v1/receipts/tail":                 tenantKeyedStore,
	"/api/v1/proofgraph/sessions":           tenantKeyedStore,
	"/api/v1/proofgraph/sessions/":          tenantKeyedStore,
	"/api/v1/proofgraph/receipts/":          tenantKeyedStore,
	"/api/v1/evidence/export":               tenantKeyedStore,
	"/api/v1/console/bootstrap":             tenantKeyedStore,
	"/api/v1/console/surfaces":              tenantKeyedStore,
	"/api/v1/console/surfaces/":             tenantKeyedStore,
	"/api/v1/onboarding/state":              tenantKeyedStore,
	"/api/v1/onboarding/run-step":           tenantKeyedStore,
	"/api/v1/onboarding/export":             tenantKeyedStore,
	"/api/v1/agent-ui/info":                 tenantKeyedStore,
	"/api/v1/agent-ui/run":                  tenantKeyedStore,
	"/api/ag-ui/info":                       tenantKeyedStore,
	"/api/ag-ui/run":                        tenantKeyedStore,
	"/api/v1/boundary/status":               configuredTenantStore,
	"/api/v1/boundary/capabilities":         configuredTenantStore,
	"/api/v1/boundary/records":              configuredTenantStore,
	"/api/v1/boundary/records/":             configuredTenantStore,
	"/api/v1/evidence/verification-scopes":  configuredTenantStore,
	"/api/v1/evidence/verification-scopes/": configuredTenantStore,
	"/api/v1/telemetry/harness-traces":      configuredTenantStore,
	"/api/v1/telemetry/harness-traces/":     configuredTenantStore,
	"/api/v1/plans/transactions":            configuredTenantStore,
	"/api/v1/plans/transactions/":           configuredTenantStore,
	"/api/v1/harness/change-contracts":      configuredTenantStore,
	"/api/v1/harness/change-contracts/":     configuredTenantStore,
	"/api/v1/launchpad/":                    configuredTenantStore,
	"/api/v1/coexistence/capabilities":      noTenantData,
	"/api/v1/telemetry/otel/config":         noTenantData,
}

// tenantAMarkers are values only tenant A's seeded receipt carries
// (newContractRouteTestServices).
var tenantAMarkers = []string{"rcpt-test", "dec-test", "sha256:test-decision", "session-test"}

func leaksTenantAData(status int, body string) bool {
	if status == http.StatusForbidden || status == http.StatusNotFound {
		return false
	}
	for _, marker := range tenantAMarkers {
		if strings.Contains(body, marker) {
			return true
		}
	}
	return false
}

func tenantRequest(t *testing.T, method, path, tenantID, principalID string) *http.Request {
	t.Helper()
	var body *strings.Reader
	if method == http.MethodPost || method == http.MethodPut {
		body = strings.NewReader(`{}`)
	} else {
		body = strings.NewReader("")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	t.Cleanup(cancel) // streaming routes (receipt tail, agent UI run) end here
	req := httptest.NewRequest(method, path, body).WithContext(ctx)
	req.Header.Set("Authorization", "Bearer "+testAdminAPIKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(tenantHeader, tenantID)
	req.Header.Set(principalHeader, principalID)
	return req
}

// tenantIsolationMuxes mounts the production composition with tenant A as the
// configured tenant and tenant B as a registered binding.
func tenantIsolationMuxes(t *testing.T) map[string]*runtimeRouteMux {
	t.Helper()
	muxes := runtimeRouteConfigs(t)
	t.Setenv(runtimeTenantIDEnv, defaultRuntimeTenantID)
	t.Setenv(runtimePrincipalIDEnv, "principal-a")
	t.Setenv(runtimeWorkspaceIDEnv, "")
	SetPrincipalBindingStore(&recordingPrincipalBindingStore{existsOK: true})
	t.Cleanup(func() { SetPrincipalBindingStore(nil) })
	return muxes
}

func TestEveryTenantRouteDeclaresItsDataScope(t *testing.T) {
	declared := map[string]bool{}
	for _, spec := range RuntimeRouteSpecs() {
		if spec.Auth != RouteAuthTenant {
			continue
		}
		declared[spec.MuxPattern] = true
		if tenantDataScope[spec.MuxPattern] == "" {
			t.Errorf("%s %s is tenant_scoped but tenantDataScope does not say how its data is kept per tenant", spec.Method, spec.Path)
		}
	}
	for pattern := range tenantDataScope {
		if !declared[pattern] {
			t.Errorf("tenantDataScope lists %s, which is not a tenant_scoped route", pattern)
		}
	}
}

func TestTenantRoutesNeverShowAnotherTenantsData(t *testing.T) {
	muxes := tenantIsolationMuxes(t)

	// Positive control: the markers are live, so their absence below means
	// something.
	own := httptest.NewRecorder()
	muxes["serve"].ServeHTTP(own, tenantRequest(t, http.MethodGet, "/api/v1/receipts", defaultRuntimeTenantID, "principal-a"))
	if own.Code != http.StatusOK || !leaksTenantAData(own.Code, own.Body.String()) {
		t.Fatalf("tenant A cannot see its own seeded receipt (status %d): the isolation probe would pass vacuously. body=%s", own.Code, own.Body.String())
	}

	for _, spec := range RuntimeRouteSpecs() {
		if spec.Auth != RouteAuthTenant {
			continue
		}
		probed := false
		for name, mux := range muxes {
			req := tenantRequest(t, spec.Method, representativeRuntimePath(spec.Path), "tenant-b", "principal-b")
			if _, pattern := mux.Handler(req); pattern != spec.MuxPattern {
				continue
			}
			probed = true
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			if leaksTenantAData(rec.Code, rec.Body.String()) {
				t.Errorf("[%s] %s %s: tenant B saw tenant A's data (status %d): %.300s", name, spec.Method, spec.Path, rec.Code, rec.Body.String())
			}
			if tenantDataScope[spec.MuxPattern] == configuredTenantStore && rec.Code != http.StatusForbidden {
				t.Errorf("[%s] %s %s serves a store without a tenant dimension to another tenant: status %d, want 403", name, spec.Method, spec.Path, rec.Code)
			}
		}
		if !probed {
			t.Errorf("%s %s: no configuration mounts it, so no cross-tenant negative ran", spec.Method, spec.Path)
		}
	}
}

// Negative control: a handler that serves the shared store to any caller is
// caught by the same check.
func TestTenantIsolationProbeDetectsASharedStore(t *testing.T) {
	leaky := `{"receipts":[{"receipt_id":"rcpt-test","decision_id":"dec-test"}]}`
	if !leaksTenantAData(http.StatusOK, leaky) {
		t.Fatal("a response carrying tenant A's receipt was not flagged")
	}
	if leaksTenantAData(http.StatusForbidden, leaky) || leaksTenantAData(http.StatusOK, `{"receipts":[]}`) {
		t.Fatal("a refusal or an empty result was flagged as a leak")
	}
}

// Launchpad is off unless HELM_LAUNCHPAD_ROUTES_ENABLED is set (§14.7).
func TestLaunchpadRoutesAreOffByDefault(t *testing.T) {
	t.Setenv(launchpadRoutesEnabledEnv, "")
	mux := newRuntimeRouteMux()
	RegisterLaunchpadRoutes(mux, &Services{})
	if got := mux.Mounted(); len(got) != 0 {
		t.Fatalf("Launchpad mounted %v without opt-in", got)
	}
	t.Setenv(launchpadRoutesEnabledEnv, "1")
	RegisterLaunchpadRoutes(mux, &Services{})
	if got := mux.Mounted(); len(got) != 1 || got[0] != "/api/v1/launchpad/" {
		t.Fatalf("Launchpad opt-in mounted %v", got)
	}
}

// The Console's local and desktop kernel modes probe and read
// /api/v1/boundary/status, a configured-tenant store route. Both launchers send
// the tenant the Kernel is configured with, so they keep answering:
//   - helm-desktop starts the Kernel without HELM_RUNTIME_TENANT_ID ("default")
//     and the Console with HELM_KERNEL_TENANT=default, principal system-admin;
//   - `helm-ai-kernel local console` sets HELM_RUNTIME_TENANT_ID to the
//     quickstart tenant and passes the same tenant to the Console.
func TestLocalConsoleCallersKeepBoundaryStatus(t *testing.T) {
	for _, test := range []struct {
		name, configuredTenant, configuredPrincipal, tenant, principal string
	}{
		{name: "desktop", tenant: defaultRuntimeTenantID, principal: "system-admin"},
		{name: "local console", configuredTenant: "tenant-local", configuredPrincipal: "principal-local", tenant: "tenant-local", principal: "principal-local"},
	} {
		t.Run(test.name, func(t *testing.T) {
			svc, cleanup := newContractRouteTestServices(t)
			defer cleanup()
			t.Setenv(runtimeTenantIDEnv, test.configuredTenant)
			t.Setenv(runtimePrincipalIDEnv, test.configuredPrincipal)
			SetPrincipalBindingStore(nil)
			mux := http.NewServeMux()
			registerContractRoutes(mux, svc)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, tenantRequest(t, http.MethodGet, "/api/v1/boundary/status", test.tenant, test.principal))
			if rec.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
		})
	}
}
