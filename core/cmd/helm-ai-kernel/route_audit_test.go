package main

// H22 / F-11: the API listener serves exactly the routes RuntimeRouteSpecs()
// declares, and every declared route refuses callers that lack its declared
// credential. The previous guard read one of nineteen route files with a regex
// that saw 21 of 135 registrations (S-04). These tests instead mount the
// production composition (registerRuntimeAPIRoutes on the registry-checked
// runtimeRouteMux) and probe every registry entry over HTTP, so a route cannot
// escape by living in another file, using mux.Handle, or taking its path from a
// constant.
//
// The tenant probes are gate-level: an unbound tenant or principal is refused
// before the handler runs. Whether a handler then scopes its data to the
// authenticated tenant is a separate, data-level property (S-05, HELM-755 S3).

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/credentials"
	mcppkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/mcp"
)

// publicRoutes are the paths the registry declares RouteAuthPublic. Each needs
// a stated reason; adding one is the deliberate, reviewable act of publishing
// an endpoint on a listener that HELM_BIND_ADDR=0.0.0.0 makes internet-facing.
var publicRoutes = map[string]string{
	"/healthz":                                  "liveness probe",
	"/version":                                  "build identity, no tenant data",
	"/api/v1/version":                           "build identity, no tenant data",
	"/v1/meta/capabilities":                     "static capability list",
	"/api/v1/meta/capabilities":                 "static capability list",
	"/api/health":                               "public demo liveness",
	"/api/demo/run":                             "public demo sandbox; ephemeral demo data, no tenant data",
	"/api/demo/verify":                          "public demo sandbox; verifies a caller-supplied demo receipt",
	"/api/demo/tamper":                          "public demo sandbox; mutates a caller-supplied demo receipt",
	"/api/v1/evidence/verify":                   "offline verification of a caller-supplied bundle; reads no stored data",
	"/api/v1/replay/verify":                     "offline replay of a caller-supplied bundle; reads no stored data",
	"/api/v1/conformance/vectors":               "static conformance vectors",
	"/api/v1/conformance/negative":              "static negative conformance vectors",
	"/.well-known/agent-card.json":              "A2A agent card",
	"/.well-known/oauth-protected-resource":     "RFC 9728 protected-resource metadata",
	"/.well-known/oauth-protected-resource/mcp": "RFC 9728 protected-resource metadata for /mcp",
	"/__helm/config.json":                       "local quickstart bootstrap; identity fields only to loopback peers (F-13)",
	"/api/v1/local-session/exchange":            "local quickstart token exchange; loopback peers only",
	desktopReadyPath:                            "Desktop launch proof: HMAC of the caller's nonce; mounted only when Desktop launched the Kernel",
}

const (
	probeServiceKey             = "probe-service-key"
	probeOrganizationRuntimeKey = "probe-organization-runtime-key"
	probeTenant                 = "tenant-probe"
	probePrincipal              = "principal-probe"
	probeWorkspace              = "workspace-probe"
	foreignTenant               = "tenant-foreign"
	foreignPrincipal            = "principal-foreign"
)

// routeProbe is one request against a route and the statuses that count as
// the route refusing it.
type routeProbe struct {
	name   string
	set    func(*http.Request)
	refuse []int
}

func probeBearer(token string) func(*http.Request) {
	return func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+token) }
}

func probeIdentity(token, tenantID, principalID string) func(*http.Request) {
	return func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set(tenantHeader, tenantID)
		r.Header.Set(principalHeader, principalID)
		r.Header.Set(workspaceHeader, probeWorkspace)
	}
}

// refusalProbes are the negatives generated for a declared auth tier. Each tier
// must refuse no credential and the credentials of the other tiers; the tenant
// tiers must also refuse an identity that is not bound to the credential.
func refusalProbes(auth RouteAuth) ([]routeProbe, error) {
	unauthenticated := routeProbe{name: "no credential", set: func(*http.Request) {}, refuse: []int{http.StatusUnauthorized}}
	unauthorized := []int{http.StatusUnauthorized}
	forbidden := []int{http.StatusForbidden}
	switch auth {
	case RouteAuthPublic:
		return nil, nil
	case RouteAuthAdmin, RouteAuthAuthenticated:
		return []routeProbe{
			unauthenticated,
			{name: "service credential", set: probeBearer(probeServiceKey), refuse: unauthorized},
			{name: "organization runtime credential", set: probeBearer(probeOrganizationRuntimeKey), refuse: unauthorized},
		}, nil
	case RouteAuthTenant:
		return []routeProbe{
			unauthenticated,
			{name: "admin credential without tenant binding", set: probeBearer(testAdminAPIKey), refuse: forbidden},
			{name: "admin credential asserting a foreign tenant", set: probeIdentity(testAdminAPIKey, foreignTenant, probePrincipal), refuse: forbidden},
			{name: "admin credential asserting a foreign principal", set: probeIdentity(testAdminAPIKey, probeTenant, foreignPrincipal), refuse: forbidden},
			{name: "service credential with a bound identity", set: probeIdentity(probeServiceKey, probeTenant, probePrincipal), refuse: unauthorized},
			{name: "organization runtime credential with a bound identity", set: probeIdentity(probeOrganizationRuntimeKey, probeTenant, probePrincipal), refuse: unauthorized},
		}, nil
	case RouteAuthConfiguredTenant:
		return []routeProbe{
			unauthenticated,
			{name: "admin credential asserting a foreign tenant", set: probeIdentity(testAdminAPIKey, foreignTenant, probePrincipal), refuse: forbidden},
			{name: "admin credential asserting a foreign principal", set: probeIdentity(testAdminAPIKey, probeTenant, foreignPrincipal), refuse: forbidden},
			{name: "service credential", set: probeBearer(probeServiceKey), refuse: unauthorized},
		}, nil
	case RouteAuthOrganizationRuntime:
		return []routeProbe{
			unauthenticated,
			{name: "admin credential with a bound identity", set: probeIdentity(testAdminAPIKey, probeTenant, probePrincipal), refuse: unauthorized},
			{name: "service credential with a bound identity", set: probeIdentity(probeServiceKey, probeTenant, probePrincipal), refuse: unauthorized},
			{name: "organization runtime credential without bindings", set: probeBearer(probeOrganizationRuntimeKey), refuse: forbidden},
			{name: "organization runtime credential asserting a foreign tenant", set: probeIdentity(probeOrganizationRuntimeKey, foreignTenant, probePrincipal), refuse: forbidden},
		}, nil
	case RouteAuthService:
		return []routeProbe{
			unauthenticated,
			{name: "admin credential", set: probeBearer(testAdminAPIKey), refuse: unauthorized},
			{name: "organization runtime credential", set: probeBearer(probeOrganizationRuntimeKey), refuse: unauthorized},
		}, nil
	case RouteAuthWorkload:
		// The probe runtimes' token validators reject every token, so these show
		// the route consults its workload validator and nothing else. Accepting
		// a real workload token is covered by the approval route tests.
		return []routeProbe{
			unauthenticated,
			{name: "admin credential", set: probeBearer(testAdminAPIKey), refuse: unauthorized},
			{name: "service credential", set: probeBearer(probeServiceKey), refuse: unauthorized},
		}, nil
	case RouteAuthLoopback:
		// httptest requests come from 192.0.2.1, which is not loopback. These
		// routes answer 404 so they do not advertise themselves off-host.
		return []routeProbe{{name: "non-loopback peer", set: func(*http.Request) {}, refuse: []int{http.StatusNotFound}}}, nil
	default:
		return nil, fmt.Errorf("no refusal probes for auth tier %q: add them before declaring a route with it", auth)
	}
}

// probeRoute sends every refusal probe for spec to handler and returns the
// probes the route did not refuse.
func probeRoute(handler http.Handler, spec RuntimeRouteSpec) []string {
	probes, err := refusalProbes(spec.Auth)
	if err != nil {
		return []string{err.Error()}
	}
	var failures []string
	for _, probe := range probes {
		req := httptest.NewRequest(spec.Method, representativeRuntimePath(spec.Path), nil)
		probe.set(req)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		refused := false
		for _, status := range probe.refuse {
			refused = refused || rec.Code == status
		}
		if !refused {
			failures = append(failures, fmt.Sprintf("%s %s (%s): %s answered %d, want %v", spec.Method, spec.Path, spec.Auth, probe.name, rec.Code, probe.refuse))
		}
	}
	return failures
}

type rejectingWorkloadValidator struct{}

func (rejectingWorkloadValidator) ValidateAuthorization(string) (*mcppkg.OAuthTokenClaims, error) {
	return nil, &mcppkg.JWKSValidationError{Kind: mcppkg.JWKSErrInvalidSignature, Message: "route probe"}
}

type emptyReconciliationCandidates struct{}

func (emptyReconciliationCandidates) ListReconciliationCandidates(context.Context) (contracts.EffectReconciliationCandidates, error) {
	return contracts.EffectReconciliationCandidates{}, nil
}

// runtimeRouteConfigs mounts the production route composition under every
// server configuration that changes what is mounted, with every optional
// runtime present. The union of their catalogs must equal the registry.
func runtimeRouteConfigs(t *testing.T) map[string]*runtimeRouteMux {
	t.Helper()
	chdirTempDir(t)
	svc, cleanup := newContractRouteTestServices(t)
	t.Cleanup(cleanup)
	t.Setenv(serviceAPIKeyEnv, probeServiceKey)
	t.Setenv(organizationRuntimeAPIKeyEnv, probeOrganizationRuntimeKey)
	t.Setenv(runtimeTenantIDEnv, probeTenant)
	t.Setenv(runtimePrincipalIDEnv, probePrincipal)
	t.Setenv(runtimeWorkspaceIDEnv, probeWorkspace)
	SetPrincipalBindingStore(nil)

	reject := rejectingWorkloadValidator{}
	svc.Creds = credentials.NewHandler(nil)
	svc.ApprovalConsumption = &approvalConsumptionRuntime{
		consumer: &fakeApprovalGrantConsumer{}, admitter: &fakeApprovalDispatchAdmitter{},
		controller: &fakeApprovalCeremonyController{}, disposition: &fakeEffectDispositionRecorder{},
		reconciliationCandidates: emptyReconciliationCandidates{}, stops: &fakeApprovalScopedStopReader{},
		validator: reject, dispatchValidator: reject, controlValidator: reject,
		dispositionValidator: reject, reconciliationValidator: reject,
		audience: "helm-data-plane", maxTokenTTL: 5 * time.Minute,
	}
	svc.GeneratedSpecApproval = generatedSpecApprovalRouteTestRuntime(reject, reject)

	configs := map[string]serverOptions{
		"serve":                {Mode: "serve", PolicyPath: "policy.toml"},
		"quickstart":           {Mode: "quickstart", BindAddr: "127.0.0.1", Port: 7714, Quickstart: quickstartRouteRuntime()},
		"quickstart console":   {Mode: "quickstart", BindAddr: "127.0.0.1", Port: 7714, Quickstart: quickstartRouteRuntime(), ConsoleMode: true, ConsolePeerProof: &localConsolePeerProof{}},
		"serve with Launchpad": {Mode: "serve", PolicyPath: "policy.toml"},
	}
	t.Setenv(launchpadRoutesEnabledEnv, "")
	muxes := make(map[string]*runtimeRouteMux, len(configs))
	for name, opts := range configs {
		// Launchpad is mounted only on explicit opt-in (HELM-755 S-05).
		if name == "serve with Launchpad" {
			t.Setenv(launchpadRoutesEnabledEnv, "1")
		} else {
			t.Setenv(launchpadRoutesEnabledEnv, "")
		}
		mux := newRuntimeRouteMux()
		// main mounts the Desktop routes before the service routes.
		registerDesktopReadyRoute(mux, "probe-desktop-token")
		registerDesktopTransportV1ProofRoute(mux, &desktopTransportV1{}, "http://127.0.0.1:7714")
		registerRuntimeAPIRoutes(mux, svc, opts)
		muxes[name] = mux
	}
	return muxes
}

func TestRuntimeRouteCatalogEqualsRegistry(t *testing.T) {
	muxes := runtimeRouteConfigs(t)
	mounted := map[string]bool{}
	for _, mux := range muxes {
		for _, pattern := range mux.Mounted() {
			mounted[pattern] = true
		}
	}
	if len(mounted) < 100 {
		t.Fatalf("only %d patterns mounted: the route composition is no longer being exercised", len(mounted))
	}

	seen := map[string]bool{}
	for _, spec := range RuntimeRouteSpecs() {
		key := spec.Method + " " + spec.Path
		if seen[key] {
			t.Errorf("duplicate registry entry %s", key)
		}
		seen[key] = true
		if !mounted[spec.MuxPattern] && !mounted[spec.Method+" "+spec.MuxPattern] {
			t.Errorf("%s (%s) is declared but no server configuration mounts %q", key, spec.OperationID, spec.MuxPattern)
		}
	}
	// The mux already panics on an undeclared pattern; checking again here means
	// a weakened mux fails this test instead of passing silently.
	for pattern := range mounted {
		if len(declaredRouteSpecs(pattern)) == 0 {
			t.Errorf("mounted pattern %q has no registry entry", pattern)
		}
	}
}

// TestRuntimeRoutesRefuseCallersWithoutTheirDeclaredCredential generates the
// negatives for every registry entry from its declared auth tier.
func TestRuntimeRoutesRefuseCallersWithoutTheirDeclaredCredential(t *testing.T) {
	muxes := runtimeRouteConfigs(t)
	for _, spec := range RuntimeRouteSpecs() {
		probed := false
		for name, mux := range muxes {
			req := httptest.NewRequest(spec.Method, representativeRuntimePath(spec.Path), nil)
			if _, pattern := mux.Handler(req); pattern != spec.MuxPattern && pattern != spec.Method+" "+spec.MuxPattern {
				continue
			}
			probed = true
			for _, failure := range probeRoute(mux, spec) {
				t.Errorf("[%s] %s", name, failure)
			}
		}
		if !probed {
			t.Errorf("%s %s: no configuration routes its path to %q, so no negative ran", spec.Method, spec.Path, spec.MuxPattern)
		}
	}
}

// TestRouteProbesDetectAnUnguardedHandler is the negative control for the
// generated probes: without it, a passing probe run would also be what a
// broken probe returns.
func TestRouteProbesDetectAnUnguardedHandler(t *testing.T) {
	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
	t.Setenv(serviceAPIKeyEnv, probeServiceKey)
	t.Setenv(runtimeTenantIDEnv, probeTenant)
	t.Setenv(runtimePrincipalIDEnv, probePrincipal)
	SetPrincipalBindingStore(nil)
	ok := func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }
	for _, test := range []struct {
		spec    RuntimeRouteSpec
		handler http.HandlerFunc
		leaks   int
	}{
		{spec: RuntimeRouteSpec{Method: http.MethodPost, Path: "/api/v1/evaluate", Auth: RouteAuthTenant}, handler: ok, leaks: 6},
		// Guarded, but as admin: the tenant binding probes must still fail.
		{spec: RuntimeRouteSpec{Method: http.MethodPost, Path: "/api/v1/evaluate", Auth: RouteAuthTenant}, handler: protectRuntimeHandler(RouteAuthAdmin, ok), leaks: 3},
		{spec: RuntimeRouteSpec{Method: http.MethodPost, Path: "/internal/policy/reconcile", Auth: RouteAuthService}, handler: protectRuntimeHandler(RouteAuthAdmin, ok), leaks: 1},
		{spec: RuntimeRouteSpec{Method: http.MethodPost, Path: "/api/v1/evaluate", Auth: RouteAuthTenant}, handler: protectRuntimeHandler(RouteAuthTenant, ok), leaks: 0},
	} {
		failures := probeRoute(test.handler, test.spec)
		if len(failures) != test.leaks {
			t.Fatalf("%s guarded by %T: %d probe failures %v, want %d", test.spec.Path, test.handler, len(failures), failures, test.leaks)
		}
	}
	if failures := probeRoute(http.HandlerFunc(ok), RuntimeRouteSpec{Method: http.MethodGet, Path: "/x", Auth: "made_up"}); len(failures) != 1 || !strings.Contains(failures[0], "no refusal probes") {
		t.Fatalf("unknown auth tier produced %v; it must fail rather than probe nothing", failures)
	}
}

// S-04's three shapes that the regex could not see are all refused by the mux.
func TestRuntimeRouteMuxRefusesUndeclaredPatterns(t *testing.T) {
	const backdoorPath = "/api/v1/backdoor"
	leak := func(http.ResponseWriter, *http.Request) {}
	for name, register := range map[string]func(*runtimeRouteMux){
		"HandleFunc with a constant path":  func(m *runtimeRouteMux) { m.HandleFunc(backdoorPath, leak) },
		"Handle":                           func(m *runtimeRouteMux) { m.Handle("/api/v1/backdoor2", http.HandlerFunc(leak)) },
		"method-qualified pattern":         func(m *runtimeRouteMux) { m.HandleFunc("POST /api/v1/backdoor3", leak) },
		"declared path, undeclared method": func(m *runtimeRouteMux) { m.HandleFunc("PUT /api/v1/credentials/status", leak) },
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("an undeclared route was mounted")
				}
			}()
			register(newRuntimeRouteMux())
		})
	}
	mux := newRuntimeRouteMux()
	mux.HandleFunc("GET /api/v1/credentials/status", leak)
	if got := mux.Mounted(); len(got) != 1 || got[0] != "GET /api/v1/credentials/status" {
		t.Fatalf("declared route not recorded: %v", got)
	}
}

func TestPublicRoutesAreDeclaredWithAReason(t *testing.T) {
	declared := map[string]bool{}
	for _, spec := range RuntimeRouteSpecs() {
		if spec.Auth != RouteAuthPublic {
			continue
		}
		declared[spec.Path] = true
		if strings.TrimSpace(publicRoutes[spec.Path]) == "" {
			t.Errorf("%s %s is declared public without a reason in publicRoutes", spec.Method, spec.Path)
		}
	}
	for path := range publicRoutes {
		if !declared[path] {
			t.Errorf("publicRoutes lists %s, which the registry does not declare public", path)
		}
	}
	// Growth needs a reviewed edit to this number, not a quiet append.
	const maxPublic = 19
	if len(declared) > maxPublic {
		t.Fatalf("%d public paths (limit %d): every unauthenticated endpoint is attack surface on a 0.0.0.0 deployment", len(declared), maxPublic)
	}
}
