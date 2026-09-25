package main

// quantum_posture: tests mint classical RS256 (and deliberately invalid HS256
// and "none") JWTs against a local JWKS issuer; no post-quantum claim.

// ADR-0005 §7 for phase 1: generated per-route token negatives (1), the
// data-level cross-tenant negative (2), compatibility pins (4), key rotation
// (5) and negative controls for the validator (6), plus the §3 binding
// cross-check and the two phase-3 counters. §7 test 3 (row security) is in
// pkg/postgresmigration.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/api"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/artifacts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/guardian"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel"
	mcppkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/mcp"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/store"
)

const (
	testCPIssuer   = "https://control-plane.test/workload-identity"
	testCPAudience = "helm-kernel:test-environment"
	testCPActor    = "spiffe://helm/control-plane"
)

// testCPIssuerKeys is a JWKS issuer whose published key set can change.
type testCPIssuerKeys struct {
	mu        sync.Mutex
	keys      map[string]*rsa.PrivateKey
	published map[string]bool
	server    *httptest.Server
}

func newTestCPIssuer(t *testing.T, kids ...string) *testCPIssuerKeys {
	t.Helper()
	issuer := &testCPIssuerKeys{keys: map[string]*rsa.PrivateKey{}, published: map[string]bool{}}
	for _, kid := range kids {
		issuer.addKey(t, kid)
	}
	issuer.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		issuer.mu.Lock()
		defer issuer.mu.Unlock()
		var set jose.JSONWebKeySet
		for kid, published := range issuer.published {
			if published {
				set.Keys = append(set.Keys, jose.JSONWebKey{Key: &issuer.keys[kid].PublicKey, KeyID: kid, Algorithm: "RS256", Use: "sig"})
			}
		}
		_ = json.NewEncoder(w).Encode(set)
	}))
	t.Cleanup(issuer.server.Close)
	return issuer
}

func (i *testCPIssuerKeys) addKey(t *testing.T, kid string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	i.keys[kid] = key
	i.published[kid] = true
}

func (i *testCPIssuerKeys) publish(kid string, published bool) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.published[kid] = published
}

// identity builds the token path through the production constructor, from
// HELM_CP_IDENTITY_* with a pinned CA bundle for the httptest issuer.
func (i *testCPIssuerKeys) identity(t *testing.T) *controlPlaneIdentity {
	t.Helper()
	caFile := filepath.Join(t.TempDir(), "control-plane-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: i.server.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(cpIdentityJWKSURLEnv, i.server.URL)
	t.Setenv(cpIdentityIssuerEnv, testCPIssuer)
	t.Setenv(cpIdentityAudienceEnv, testCPAudience)
	t.Setenv(cpIdentityActorEnv, testCPActor)
	t.Setenv(cpIdentityCAFileEnv, caFile)
	t.Setenv(cpIdentityMaxTTLEnv, "")
	t.Setenv(cpIdentityRequireCNFEnv, "")
	identity, err := newControlPlaneIdentityFromEnv()
	if err != nil || identity == nil {
		t.Fatalf("control plane identity from env: identity=%v err=%v", identity, err)
	}
	return identity
}

// rotationIdentity refreshes on every unknown kid, so a rotation test does not
// wait out the production 30s refresh interval (pkg/mcp tests that limit).
func (i *testCPIssuerKeys) rotationIdentity() *controlPlaneIdentity {
	return &controlPlaneIdentity{
		issuer: testCPIssuer,
		validator: mcppkg.NewJWKSValidator(mcppkg.JWKSConfig{
			JWKSURL: i.server.URL, Issuer: testCPIssuer, Audience: testCPAudience, RequiredActor: testCPActor,
			Algorithms: []string{"RS256"}, MaxTokenTTL: cpIdentityMaxTTLCeiling, Leeway: cpIdentityClockSkew,
			HTTPClient: i.server.Client(), MinRefreshInterval: time.Nanosecond,
		}),
	}
}

type tokenClaims map[string]any

func baseTokenClaims(tenantID, principalID, workspaceID, scope string) tokenClaims {
	now := time.Now()
	return tokenClaims{
		"iss": testCPIssuer, "aud": []string{testCPAudience}, "sub": principalID,
		"act": map[string]string{"sub": testCPActor}, "tenant_id": tenantID, "workspace_id": workspaceID,
		"scope": scope, "txn": "txn-" + principalID, "jti": fmt.Sprintf("jti-%d", now.UnixNano()),
		"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(4 * time.Minute).Unix(),
	}
}

func (c tokenClaims) with(key string, value any) tokenClaims {
	out := tokenClaims{}
	for k, v := range c {
		out[k] = v
	}
	if value == nil {
		delete(out, key)
	} else {
		out[key] = value
	}
	return out
}

func (i *testCPIssuerKeys) mint(t *testing.T, kid string, claims tokenClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims(claims))
	token.Header["kid"] = kid
	i.mu.Lock()
	key := i.keys[kid]
	i.mu.Unlock()
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

// cpRouteBody is a request body that a route accepts once authenticated.
func cpRouteBody(t *testing.T, spec RuntimeRouteSpec) []byte {
	t.Helper()
	switch spec.OperationID {
	case "evaluateDecision":
		return []byte(`{"action":"EXECUTE_TOOL","resource":"local.echo","context":{"session_id":"session-token"}}`)
	case "evaluateOrganizationRuntimeDecision":
		body, err := json.Marshal(api.EvaluateRequest{
			Tool: "EXECUTE_TOOL", Resource: "connector://crm/contact-123", EffectLevel: "E1", SessionID: "cp-session",
			Originator: &contracts.OrganizationRuntimeOriginatorAssertion{
				PrincipalID: "human-originator-1", AssertionSource: contracts.OrganizationRuntimeOriginatorAssertionSourceControlPlane,
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		return body
	case "chatCompletions":
		return []byte(`{"model":"gpt-test","messages":[]}`)
	default:
		return nil
	}
}

var cpRouteScopes = map[string]string{
	"evaluateDecision":                    cpScopeEvaluate,
	"evaluateOrganizationRuntimeDecision": cpScopeOrganizationRuntime,
	"listReceipts":                        cpScopeReceiptsRead,
	"tailReceipts":                        cpScopeReceiptsRead,
	"getConsoleReceipt":                   cpScopeReceiptsRead,
	"chatCompletions":                     cpScopeProxyChat,
}

func cpTokenRequest(t *testing.T, spec RuntimeRouteSpec, token string, headers map[string]string) *http.Request {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	t.Cleanup(cancel) // the receipt tail streams until the context ends
	req := httptest.NewRequest(spec.Method, representativeRuntimePath(spec.Path), bytes.NewReader(cpRouteBody(t, spec))).WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if spec.OperationID == "evaluateOrganizationRuntimeDecision" {
		req.Header.Set(companyActivationExecutionProfileHeader, companyActivationOrganizationRuntimeProfile)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req
}

// cpTokenServices mounts the production route composition with the token path
// on. Tenant "default" owns the seeded receipt rcpt-test.
func cpTokenServices(t *testing.T, identity *controlPlaneIdentity) (*runtimeRouteMux, *Services) {
	t.Helper()
	chdirTempDir(t)
	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
	t.Setenv(organizationRuntimeAPIKeyEnv, testOrganizationRuntimeAPIKey)
	t.Setenv(runtimeTenantIDEnv, "default")
	t.Setenv(runtimePrincipalIDEnv, "default")
	t.Setenv(runtimeWorkspaceIDEnv, "default")
	SetPrincipalBindingStore(nil)
	t.Cleanup(func() { SetPrincipalBindingStore(nil) })
	svc, cleanup := newContractRouteTestServices(t)
	t.Cleanup(cleanup)
	evaluateSvc, _ := newEvaluateRouteTestServices(t)
	svc.Guardian, svc.ReceiptSigner = evaluateSvc.Guardian, evaluateSvc.ReceiptSigner
	svc.CompanyActivationEnvironmentID = "managed"
	svc.ControlPlaneIdentity = identity
	mux := newRuntimeRouteMux()
	registerRuntimeAPIRoutes(mux, svc, serverOptions{Mode: "serve", PolicyPath: "policy.toml"})
	return mux, svc
}

type cpTokenProbe struct {
	name   string
	token  func(spec RuntimeRouteSpec) string
	header map[string]string
	want   []int
}

// cpTokenProbes are the §7.1 negatives for one route, plus the positive case.
func cpTokenProbes(t *testing.T, issuer *testCPIssuerKeys) []cpTokenProbe {
	good := func(spec RuntimeRouteSpec) tokenClaims {
		return baseTokenClaims("7c9e6679-7425-40de-944b-e07fc1f90ae7", "b3f1c2de-2f4a-4c55-9a0e-1f2d3c4b5a69", "3fa85f64-5717-4562-b3fc-2c963f66afa6", cpRouteScopes[spec.OperationID])
	}
	signed := func(mutate func(tokenClaims) tokenClaims) func(RuntimeRouteSpec) string {
		return func(spec RuntimeRouteSpec) string { return issuer.mint(t, "k1", mutate(good(spec))) }
	}
	withMethod := func(method jwt.SigningMethod) func(RuntimeRouteSpec) string {
		return func(spec RuntimeRouteSpec) string {
			token := jwt.NewWithClaims(method, jwt.MapClaims(good(spec)))
			token.Header["kid"] = "k1"
			issuer.mu.Lock()
			key := issuer.keys["k1"]
			issuer.mu.Unlock()
			signed, err := token.SignedString(key)
			if err != nil {
				t.Fatal(err)
			}
			return signed
		}
	}
	unauthorized, forbidden := []int{http.StatusUnauthorized}, []int{http.StatusForbidden}
	now := time.Now()
	return []cpTokenProbe{
		{name: "no token", token: func(RuntimeRouteSpec) string { return "" }, want: unauthorized},
		{name: "wrong issuer", token: signed(func(c tokenClaims) tokenClaims { return c.with("iss", "https://other-issuer.test") }), want: unauthorized},
		{name: "wrong audience", token: signed(func(c tokenClaims) tokenClaims { return c.with("aud", []string{"helm-kernel:other-environment"}) }), want: unauthorized},
		{name: "wrong actor", token: signed(func(c tokenClaims) tokenClaims { return c.with("act", map[string]string{"sub": "spiffe://helm/other"}) }), want: unauthorized},
		{name: "no actor", token: signed(func(c tokenClaims) tokenClaims { return c.with("act", nil) }), want: unauthorized},
		{name: "expired", token: signed(func(c tokenClaims) tokenClaims {
			return c.with("iat", now.Add(-10*time.Minute).Unix()).with("nbf", now.Add(-10*time.Minute).Unix()).with("exp", now.Add(-6*time.Minute).Unix())
		}), want: unauthorized},
		{name: "not yet valid", token: signed(func(c tokenClaims) tokenClaims {
			return c.with("nbf", now.Add(2*time.Minute).Unix()).with("exp", now.Add(4*time.Minute).Unix())
		}), want: unauthorized},
		{name: "lifetime above the ceiling", token: signed(func(c tokenClaims) tokenClaims { return c.with("exp", now.Add(10*time.Minute).Unix()) }), want: unauthorized},
		{name: "no tenant", token: signed(func(c tokenClaims) tokenClaims { return c.with("tenant_id", nil) }), want: unauthorized},
		{name: "alg none", token: func(spec RuntimeRouteSpec) string {
			token, err := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims(good(spec))).SignedString(jwt.UnsafeAllowNoneSignatureType)
			if err != nil {
				t.Fatal(err)
			}
			return token
		}, want: unauthorized},
		{name: "alg HS256", token: func(spec RuntimeRouteSpec) string {
			token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(good(spec))).SignedString([]byte("shared-secret"))
			if err != nil {
				t.Fatal(err)
			}
			return token
		}, want: unauthorized},
		{name: "alg RS512", token: withMethod(jwt.SigningMethodRS512), want: unauthorized},
		{name: "alg PS256", token: withMethod(jwt.SigningMethodPS256), want: unauthorized},
		{name: "two audiences", token: signed(func(c tokenClaims) tokenClaims {
			return c.with("aud", []string{testCPAudience, "helm-kernel:other-environment"})
		}), want: unauthorized},
		{name: "wrong scope", token: signed(func(c tokenClaims) tokenClaims { return c.with("scope", "helm.unrelated") }), want: forbidden},
		{name: "a second scope", token: signed(func(c tokenClaims) tokenClaims { return c.with("scope", c["scope"].(string)+" helm.unrelated") }), want: forbidden},
		{name: "tenant header disagrees", token: signed(func(c tokenClaims) tokenClaims { return c }), header: map[string]string{tenantHeader: "tenant-other"}, want: forbidden},
		{name: "principal header disagrees", token: signed(func(c tokenClaims) tokenClaims { return c }), header: map[string]string{principalHeader: "principal-other"}, want: forbidden},
	}
}

// authRefused tells an authentication refusal from a governance decision: the
// proxy answers a policy denial with 403 "Governance Blocked".
func authRefused(rec *httptest.ResponseRecorder) bool {
	if rec.Code == http.StatusUnauthorized {
		return true
	}
	var problem struct {
		Title string `json:"title"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &problem)
	return rec.Code == http.StatusForbidden && problem.Title != "Governance Blocked"
}

func probeCPTokenRoute(t *testing.T, mux http.Handler, spec RuntimeRouteSpec, probes []cpTokenProbe) []string {
	t.Helper()
	var failures []string
	for _, probe := range probes {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, cpTokenRequest(t, spec, probe.token(spec), probe.header))
		refused := false
		for _, status := range probe.want {
			// A 403 must be the guard's refusal, not a policy decision after
			// the guard let the request through (the proxy's "Governance
			// Blocked" is also a 403).
			refused = refused || (rec.Code == status && (status != http.StatusForbidden || authRefused(rec)))
		}
		if !refused {
			failures = append(failures, fmt.Sprintf("%s %s: %s answered %d (%.80s), want a guard refusal %v", spec.Method, spec.Path, probe.name, rec.Code, rec.Body.String(), probe.want))
		}
	}
	return failures
}

// §7.1: generated from the registry. Every route that declares the token tier
// refuses each broken token and accepts a good one.
func TestControlPlaneTokenRoutesRefuseEveryBrokenToken(t *testing.T) {
	issuer := newTestCPIssuer(t, "k1")
	mux, _ := cpTokenServices(t, issuer.identity(t))
	probes := cpTokenProbes(t, issuer)
	declared := 0
	for _, spec := range RuntimeRouteSpecs() {
		if spec.AlternateAuth != RouteAuthControlPlaneToken {
			continue
		}
		declared++
		if cpRouteScopes[spec.OperationID] == "" {
			t.Errorf("%s %s declares the Control Plane token tier but has no scope here", spec.Method, spec.Path)
			continue
		}
		for _, failure := range probeCPTokenRoute(t, mux, spec, probes) {
			t.Error(failure)
		}
		rec := httptest.NewRecorder()
		good := issuer.mint(t, "k1", baseTokenClaims("7c9e6679-7425-40de-944b-e07fc1f90ae7", "b3f1c2de-2f4a-4c55-9a0e-1f2d3c4b5a69", "3fa85f64-5717-4562-b3fc-2c963f66afa6", cpRouteScopes[spec.OperationID]))
		mux.ServeHTTP(rec, cpTokenRequest(t, spec, good, nil))
		if authRefused(rec) {
			t.Errorf("%s %s refused a good token: %d %s", spec.Method, spec.Path, rec.Code, rec.Body.String())
		}
	}
	if declared != 6 {
		t.Fatalf("%d routes declare the Control Plane token tier, want the 6 Control Plane routes (ADR-0005 §1)", declared)
	}
}

// A route that does not declare the tier must not accept a token, with the
// token path on: a token for each route family is presented to every other
// non-public route.
func TestRoutesWithoutTheTokenTierRefuseAGoodToken(t *testing.T) {
	issuer := newTestCPIssuer(t, "k1")
	muxes := runtimeRouteConfigsWithIdentity(t, issuer.identity(t))
	tokens := map[string]string{}
	for _, scope := range []string{cpScopeEvaluate, cpScopeOrganizationRuntime, cpScopeReceiptsRead, cpScopeProxyChat} {
		tokens[scope] = issuer.mint(t, "k1", baseTokenClaims(probeTenant, probePrincipal, probeWorkspace, scope))
	}
	probed := 0
	for name, mux := range muxes {
		for _, spec := range RuntimeRouteSpecs() {
			if spec.Auth == RouteAuthPublic || spec.AlternateAuth == RouteAuthControlPlaneToken {
				continue
			}
			for scope, token := range tokens {
				req := httptest.NewRequest(spec.Method, representativeRuntimePath(spec.Path), nil)
				if _, pattern := mux.Handler(req); pattern != spec.MuxPattern && pattern != spec.Method+" "+spec.MuxPattern {
					continue
				}
				probed++
				req.Header.Set("Authorization", "Bearer "+token)
				rec := httptest.NewRecorder()
				mux.ServeHTTP(rec, req)
				if rec.Code != http.StatusUnauthorized && rec.Code != http.StatusForbidden && rec.Code != http.StatusNotFound {
					t.Errorf("[%s] %s %s accepted a %s token it does not declare: %d", name, spec.Method, spec.Path, scope, rec.Code)
				}
			}
		}
	}
	if probed < 400 {
		t.Fatalf("only %d probes ran: the route composition is no longer exercised", probed)
	}
}

// Wiring the token guard onto a route the registry does not declare for it
// fails at startup.
func TestTokenGuardWiringMustMatchTheRegistry(t *testing.T) {
	for _, test := range []struct{ name, route string }{
		{name: "undeclared route", route: "/api/v1/proofgraph/sessions"},
		{name: "unknown route", route: "/api/v1/not-a-route"},
	} {
		t.Run(test.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatalf("the token guard was wired onto %s", test.route)
				}
			}()
			protectControlPlaneTokenOr(&Services{}, RouteAuthTenant, test.route, cpScopeReceiptsRead, func(http.ResponseWriter, *http.Request) {})
		})
	}
}

// §7.2: a token for one tenant never reads another tenant's receipts.
func TestControlPlaneTokenReadsOnlyItsTenantsReceipts(t *testing.T) {
	issuer := newTestCPIssuer(t, "k1")
	mux, svc := cpTokenServices(t, issuer.identity(t))
	appendTenantScopedReceipt(t, svc.ReceiptStore.(*store.SQLiteReceiptStore), "tenant-b", "session-b", &contracts.Receipt{
		ReceiptID: "rcpt-tenant-b", DecisionID: "dec-tenant-b", EffectID: "EXECUTE_TOOL", Status: string(contracts.VerdictDeny),
		Timestamp: time.Date(2026, 5, 5, 0, 0, 0, 0, time.UTC), ExecutorID: "agent.b", Signature: "sig-b", DecisionHash: "sha256:tenant-b", ArgsHash: "args-b",
	})
	read := func(tenantID, path string) *httptest.ResponseRecorder {
		token := issuer.mint(t, "k1", baseTokenClaims(tenantID, "principal-"+tenantID, "workspace-"+tenantID, cpScopeReceiptsRead))
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}
	listA := read("default", "/api/v1/receipts")
	if listA.Code != http.StatusOK || !strings.Contains(listA.Body.String(), "rcpt-test") || strings.Contains(listA.Body.String(), "rcpt-tenant-b") {
		t.Fatalf("tenant default list: %d %s", listA.Code, listA.Body.String())
	}
	listB := read("tenant-b", "/api/v1/receipts")
	if listB.Code != http.StatusOK || !strings.Contains(listB.Body.String(), "rcpt-tenant-b") || strings.Contains(listB.Body.String(), "rcpt-test") {
		t.Fatalf("tenant-b list: %d %s", listB.Code, listB.Body.String())
	}
	if got := read("default", "/api/v1/receipts/rcpt-tenant-b"); got.Code != http.StatusNotFound {
		t.Fatalf("tenant default read tenant-b's receipt by id: %d %s", got.Code, got.Body.String())
	}
}

// §7.4: on a fence-off kernel configured "default"/"default", a token caller
// with the Control Plane's UUID identity gets the same statuses as the legacy
// caller pinned in TestFenceOffControlPlaneCallersKeepTheirPreviousBehavior.
func TestFenceOffControlPlaneTokenCallersMatchLegacyStatuses(t *testing.T) {
	issuer := newTestCPIssuer(t, "k1")
	mux, _ := cpTokenServices(t, issuer.identity(t))
	const (
		cpTenant    = "7c9e6679-7425-40de-944b-e07fc1f90ae7"
		cpPrincipal = "b3f1c2de-2f4a-4c55-9a0e-1f2d3c4b5a69"
		cpWorkspace = "3fa85f64-5717-4562-b3fc-2c963f66afa6"
	)
	// Chat is pinned with a real Guardian and upstream in
	// TestControlPlaneTokenChatProxyBindsTheTokenTenantAndNeverForwardsTheToken.
	want := map[string]int{
		"evaluateDecision": http.StatusOK, "evaluateOrganizationRuntimeDecision": http.StatusOK,
		"listReceipts": http.StatusOK, "getConsoleReceipt": http.StatusNotFound,
	}
	for _, spec := range RuntimeRouteSpecs() {
		status, ok := want[spec.OperationID]
		if !ok {
			continue
		}
		token := issuer.mint(t, "k1", baseTokenClaims(cpTenant, cpPrincipal, cpWorkspace, cpRouteScopes[spec.OperationID]))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, cpTokenRequest(t, spec, token, nil))
		if rec.Code != status {
			t.Errorf("%s: status=%d want %d body=%s", spec.OperationID, rec.Code, status, rec.Body.String())
		}
	}
}

// §7.5: rotate, verify old, verify new, revoke.
func TestControlPlaneTokenKeyRotation(t *testing.T) {
	issuer := newTestCPIssuer(t, "k1")
	identity := issuer.rotationIdentity()
	validate := func(kid string) error {
		_, err := identity.validator.ValidateAuthorization(issuer.mint(t, kid, baseTokenClaims("default", "p", "w", cpScopeEvaluate)))
		return err
	}
	if err := validate("k1"); err != nil {
		t.Fatalf("k1 before rotation: %v", err)
	}
	issuer.addKey(t, "k2") // rotate: publish k2 before signing with it
	if err := validate("k2"); err != nil {
		t.Fatalf("new key after rotation: %v", err)
	}
	if err := validate("k1"); err != nil {
		t.Fatalf("old key still published after rotation: %v", err)
	}
	issuer.publish("k1", false) // revoke k1
	issuer.addKey(t, "k3")      // the next unknown kid forces a refresh
	if err := validate("k3"); err != nil {
		t.Fatalf("k3: %v", err)
	}
	if err := validate("k1"); err == nil {
		t.Fatal("a token signed with the revoked key was accepted after the key set refreshed")
	}
}

// laxValidator is a validator that skips the audience or actor check. The
// §7.1 probes must catch it (§7.6, R2).
type laxValidator struct {
	inner                   tokenValidator
	skipAudience, skipActor bool
}

func (v laxValidator) ValidateAuthorization(token string) (*mcppkg.OAuthTokenClaims, error) {
	claims, err := v.inner.ValidateAuthorization(token)
	var validationErr *mcppkg.JWKSValidationError
	if err != nil && errors.As(err, &validationErr) &&
		((v.skipAudience && validationErr.Kind == mcppkg.JWKSErrInvalidAudience) || (v.skipActor && validationErr.Kind == mcppkg.JWKSErrInvalidActor)) {
		var raw struct {
			jwt.RegisteredClaims
			TenantID    string `json:"tenant_id"`
			WorkspaceID string `json:"workspace_id"`
			Scope       string `json:"scope"`
		}
		if _, _, parseErr := jwt.NewParser().ParseUnverified(token, &raw); parseErr != nil {
			return nil, parseErr
		}
		return &mcppkg.OAuthTokenClaims{RegisteredClaims: raw.RegisteredClaims, TenantID: raw.TenantID, WorkspaceID: raw.WorkspaceID, Scopes: strings.Fields(raw.Scope)}, nil
	}
	return claims, err
}

func TestControlPlaneTokenProbesCatchAValidatorThatSkipsAudienceOrActor(t *testing.T) {
	issuer := newTestCPIssuer(t, "k1")
	var evaluate RuntimeRouteSpec
	for _, spec := range RuntimeRouteSpecs() {
		if spec.OperationID == "evaluateDecision" {
			evaluate = spec
		}
	}
	for _, test := range []struct {
		name      string
		validator laxValidator
		catches   string
	}{
		{name: "skips aud", validator: laxValidator{skipAudience: true}, catches: "wrong audience"},
		{name: "skips act", validator: laxValidator{skipActor: true}, catches: "wrong actor"},
	} {
		t.Run(test.name, func(t *testing.T) {
			identity := issuer.identity(t)
			test.validator.inner = identity.validator
			identity.validator = test.validator
			mux, _ := cpTokenServices(t, identity)
			failures := probeCPTokenRoute(t, mux, evaluate, cpTokenProbes(t, issuer))
			if len(failures) == 0 || !strings.Contains(strings.Join(failures, "\n"), test.catches) {
				t.Fatalf("the probes did not catch a validator that %s: %v", test.name, failures)
			}
		})
	}
}

// ADR-0005 §3 binding cross-check and helm_token_unbound_principal_total.
func TestControlPlaneTokenBindingCrossCheck(t *testing.T) {
	issuer := newTestCPIssuer(t, "k1")
	mux, _ := cpTokenServices(t, issuer.identity(t))
	bindings, cleanupBindings := newRouteAuthTestBindingStore(t)
	t.Cleanup(cleanupBindings)
	if err := bindings.Upsert(context.Background(), store.PrincipalBinding{TenantID: "tenant-a", PrincipalID: "principal-bound"}); err != nil {
		t.Fatal(err)
	}
	SetPrincipalBindingStore(bindings)
	var evaluate RuntimeRouteSpec
	for _, spec := range RuntimeRouteSpecs() {
		if spec.OperationID == "evaluateDecision" {
			evaluate = spec
		}
	}
	unbound := func() float64 {
		return testutil.ToFloat64(controlPlaneIdentityMetrics.unbound.WithLabelValues("/api/v1/evaluate"))
	}
	call := func(tenantID, principalID string) int {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, cpTokenRequest(t, evaluate, issuer.mint(t, "k1", baseTokenClaims(tenantID, principalID, "workspace-a", cpScopeEvaluate)), nil))
		return rec.Code
	}

	before := unbound()
	if got := call("tenant-a", "principal-bound"); got != http.StatusOK {
		t.Fatalf("bound principal in its tenant: %d", got)
	}
	if unbound() != before {
		t.Fatal("a bound principal moved helm_token_unbound_principal_total")
	}
	if got := call("tenant-b", "principal-bound"); got != http.StatusForbidden {
		t.Fatalf("bound principal presented for another tenant: %d, want 403", got)
	}
	if got := call("tenant-c", "principal-unbound"); got != http.StatusOK {
		t.Fatalf("principal with no binding row: %d, want 200 on the token alone", got)
	}
	if unbound() != before+1 {
		t.Fatalf("helm_token_unbound_principal_total = %v, want %v after one unbound principal", unbound(), before+1)
	}
}

// helm_legacy_header_identity_total counts legacy requests per route, and the
// legacy line is logged at most once per principal per hour.
func TestLegacyHeaderIdentityIsCountedAndLoggedHourly(t *testing.T) {
	_, _ = cpTokenServices(t, nil)
	svc, _ := newEvaluateRouteTestServices(t)
	mux := http.NewServeMux()
	registerReceiptRoutes(mux, svc)
	legacy := func() float64 {
		return testutil.ToFloat64(controlPlaneIdentityMetrics.legacy.WithLabelValues("/api/v1/evaluate"))
	}
	before := legacy()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, evaluateScopeRequest("default", "default", "default"))
	if rec.Code != http.StatusOK || legacy() != before+1 {
		t.Fatalf("legacy evaluate: status %d, counter %v -> %v", rec.Code, before, legacy())
	}

	clock := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	metrics := newControlPlaneIdentityMetricSet(func() time.Time { return clock })
	if !metrics.shouldLog("route\x00tenant\x00principal") || metrics.shouldLog("route\x00tenant\x00principal") {
		t.Fatal("the legacy line must be logged once, then suppressed within the hour")
	}
	clock = clock.Add(legacyIdentityLogInterval)
	if !metrics.shouldLog("route\x00tenant\x00principal") {
		t.Fatal("the legacy line must be logged again after an hour")
	}
}

func TestControlPlaneIdentityConfiguration(t *testing.T) {
	for _, name := range []string{cpIdentityJWKSURLEnv, cpIdentityIssuerEnv, cpIdentityAudienceEnv, cpIdentityActorEnv, cpIdentityMaxTTLEnv} {
		t.Setenv(name, "")
	}
	if identity, err := newControlPlaneIdentityFromEnv(); identity != nil || err != nil {
		t.Fatalf("unset: identity=%v err=%v, want the token path off", identity, err)
	}
	t.Setenv(cpIdentityIssuerEnv, testCPIssuer)
	if _, err := newControlPlaneIdentityFromEnv(); err == nil {
		t.Fatal("a partial configuration was accepted")
	}
	t.Setenv(cpIdentityJWKSURLEnv, "https://control-plane.test/jwks")
	t.Setenv(cpIdentityAudienceEnv, testCPAudience)
	t.Setenv(cpIdentityActorEnv, testCPActor)
	if identity, err := newControlPlaneIdentityFromEnv(); identity == nil || err != nil {
		t.Fatalf("complete: identity=%v err=%v", identity, err)
	}
	t.Setenv(cpIdentityMaxTTLEnv, "10m")
	if _, err := newControlPlaneIdentityFromEnv(); err == nil {
		t.Fatal("a token lifetime above 300s was accepted")
	}
}

// With the fence on, a token-derived scope must still equal the configured
// scope (ADR-0005 §3, S2 behaviour).
func TestFencedKernelBindsTheTokenScopeToTheConfiguredScope(t *testing.T) {
	issuer := newTestCPIssuer(t, "k1")
	mux, svc := cpTokenServices(t, issuer.identity(t))
	svc.EmergencyStops = &kernel.ScopedStopStore{}
	read := func(tenantID, workspaceID string) int {
		token := issuer.mint(t, "k1", baseTokenClaims(tenantID, "principal-a", workspaceID, cpScopeReceiptsRead))
		req := httptest.NewRequest(http.MethodGet, "/api/v1/receipts", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec.Code
	}
	if got := read("7c9e6679-7425-40de-944b-e07fc1f90ae7", "default"); got != http.StatusForbidden {
		t.Fatalf("fenced kernel, token for another tenant: %d, want 403", got)
	}
	if got := read("default", "workspace-other"); got != http.StatusForbidden {
		t.Fatalf("fenced kernel, token for another workspace: %d, want 403", got)
	}
	if got := read("default", "default"); got != http.StatusOK {
		t.Fatalf("fenced kernel, token for the configured scope: %d, want 200", got)
	}
}

// HELM_CP_IDENTITY_REQUIRE_CNF: the token must name the client certificate
// the request arrived with (RFC 8705).
func TestControlPlaneTokenCertificateBinding(t *testing.T) {
	issuer := newTestCPIssuer(t, "k1")
	identity := issuer.identity(t)
	identity.requireCNF = true
	mux, _ := cpTokenServices(t, identity)
	clientCert := issuer.server.Certificate() // any certificate will do as the client's
	sum := sha256.Sum256(clientCert.Raw)
	thumbprint := base64.RawURLEncoding.EncodeToString(sum[:])
	read := func(cnf string, tlsState *tls.ConnectionState) int {
		claims := baseTokenClaims("default", "principal-a", "default", cpScopeReceiptsRead)
		if cnf != "" {
			claims = claims.with("cnf", map[string]string{"x5t#S256": cnf})
		}
		req := httptest.NewRequest(http.MethodGet, "/api/v1/receipts", nil)
		req.Header.Set("Authorization", "Bearer "+issuer.mint(t, "k1", claims))
		req.TLS = tlsState
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec.Code
	}
	withCert := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{clientCert}}
	if got := read(thumbprint, nil); got != http.StatusUnauthorized {
		t.Fatalf("no TLS client certificate: %d, want 401", got)
	}
	if got := read("", withCert); got != http.StatusUnauthorized {
		t.Fatalf("token without cnf: %d, want 401", got)
	}
	if got := read("wrong-thumbprint", withCert); got != http.StatusUnauthorized {
		t.Fatalf("token bound to another certificate: %d, want 401", got)
	}
	if got := read(thumbprint, withCert); got != http.StatusOK {
		t.Fatalf("token bound to this certificate: %d, want 200", got)
	}
}

// The chat proxy with a real Guardian and a stub upstream. Pins, for the
// fence-off kernel: a token caller and a legacy caller both reach the upstream
// (same status); the token caller's tenant is the token's, not the configured
// one (ADR-0005: the token scope is authoritative with the fence off, where
// legacy chat is pinned to HELM_RUNTIME_TENANT_ID); and the kernel token never
// reaches the provider.
func TestControlPlaneTokenChatProxyBindsTheTokenTenantAndNeverForwardsTheToken(t *testing.T) {
	var upstreamAuth []string
	var mu sync.Mutex
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		upstreamAuth = append(upstreamAuth, r.Header.Get("Authorization"))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[]}`))
	}))
	defer upstream.Close()
	issuer := newTestCPIssuer(t, "k1")
	identity := issuer.identity(t)
	t.Setenv("HELM_UPSTREAM_URL", upstream.URL)
	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
	t.Setenv(runtimeTenantIDEnv, "default")
	t.Setenv(runtimePrincipalIDEnv, "default")
	t.Setenv(runtimeWorkspaceIDEnv, "default")
	SetPrincipalBindingStore(nil)

	signer, err := helmcrypto.NewEd25519Signer("chat-token-test")
	if err != nil {
		t.Fatal(err)
	}
	capturing := &evaluateRouteCapturingPDP{}
	svc := &Services{
		Guardian:             guardian.NewGuardian(signer, allowGraphForExtAuthzTest("LLM_INFERENCE"), artifacts.NewRegistry(nil, nil), guardian.WithPDP(capturing)),
		ReceiptStore:         &captureReceiptStore{},
		ReceiptSigner:        signer,
		ControlPlaneIdentity: identity,
	}
	chat := protectControlPlaneTokenOr(svc, RouteAuthConfiguredTenant, "/v1/chat/completions", cpScopeProxyChat, func(w http.ResponseWriter, r *http.Request) {
		handleGovernedOpenAIProxy(w, r, svc)
	})
	call := func(headers map[string]string) (int, string) {
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(`{"model":"gpt-test","messages":[]}`))
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		chat(rec, req)
		tenant := ""
		if capturing.request != nil {
			tenant, _ = capturing.request.Context["tenant_id"].(string)
		}
		return rec.Code, tenant
	}
	const cpTenant = "7c9e6679-7425-40de-944b-e07fc1f90ae7"
	token := issuer.mint(t, "k1", baseTokenClaims(cpTenant, "b3f1c2de-2f4a-4c55-9a0e-1f2d3c4b5a69", "", cpScopeProxyChat))

	legacyStatus, legacyTenant := call(map[string]string{runtimeAPIKeyHeader: testAdminAPIKey, "Authorization": "Bearer provider-secret"})
	if legacyStatus != http.StatusOK || legacyTenant != "default" {
		t.Fatalf("legacy chat: status=%d tenant=%q, want 200 for the configured tenant", legacyStatus, legacyTenant)
	}
	tokenStatus, tokenTenant := call(map[string]string{runtimeAPIKeyHeader: token, "Authorization": "Bearer provider-secret"})
	if tokenStatus != legacyStatus || tokenTenant != cpTenant {
		t.Fatalf("token chat: status=%d tenant=%q, want %d for the token's tenant %q", tokenStatus, tokenTenant, legacyStatus, cpTenant)
	}
	bearerStatus, _ := call(map[string]string{"Authorization": "Bearer " + token})
	if bearerStatus != http.StatusOK {
		t.Fatalf("token chat with the token as bearer: status=%d", bearerStatus)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(upstreamAuth) != 3 || upstreamAuth[0] != "Bearer provider-secret" || upstreamAuth[1] != "Bearer provider-secret" || upstreamAuth[2] != "" {
		t.Fatalf("upstream Authorization headers = %q; the provider key must pass and the kernel token never", upstreamAuth)
	}
}
