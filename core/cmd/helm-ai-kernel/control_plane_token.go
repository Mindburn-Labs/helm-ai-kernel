package main

// quantum_posture: Control Plane identity tokens are classical RS256 JWTs
// verified against the Control Plane's JWKS (ADR-0005 §4); no post-quantum
// claim is made.

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/api"
	helmauth "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/auth"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/auth/jwks"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/httperr"
	mcppkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/mcp"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/store"
)

// ADR-0005 phase 1 (dual-accept). The Control Plane may present a token its
// workload identity issuer signed instead of the shared kernel key and the
// X-Helm-* identity headers. The tenant, principal and workspace then come
// from the token's claims and nothing else. With HELM_CP_IDENTITY_* unset the
// token path is off and every request takes the legacy path unchanged.
const (
	cpIdentityJWKSURLEnv    = jwks.EnvCPIdentityJWKSURL
	cpIdentityIssuerEnv     = jwks.EnvCPIdentityIssuer
	cpIdentityAudienceEnv   = jwks.EnvCPIdentityAudience
	cpIdentityActorEnv      = jwks.EnvCPIdentityActor
	cpIdentityMaxTTLEnv     = jwks.EnvCPIdentityMaxTTL
	cpIdentityRequireCNFEnv = jwks.EnvCPIdentityRequireCNF
	cpIdentityCAFileEnv     = jwks.EnvCPIdentityCAFile

	cpIdentityMaxTTLCeiling = jwks.CPIdentityMaxTTLCeiling
	cpIdentityClockSkew     = jwks.CPIdentityClockSkew

	cpScopeEvaluate            = "helm.evaluate"
	cpScopeOrganizationRuntime = "helm.organization_runtime.evaluate"
	cpScopeReceiptsRead        = "helm.receipts.read"
	cpScopeProxyChat           = "helm.proxy.chat"

	controlPlaneTokenRole = "control-plane-token"
)

// tokenValidator is the part of mcp.JWKSValidator the guard uses.
type tokenValidator interface {
	ValidateAuthorization(string) (*mcppkg.OAuthTokenClaims, error)
}

type controlPlaneIdentity struct {
	issuer     string
	validator  tokenValidator
	requireCNF bool
}

// newControlPlaneIdentityFromEnv returns nil when no HELM_CP_IDENTITY_* value
// is set. A partial configuration is a startup error, not a silently
// disabled check. The kernel requires act.sub to name the configured actor.
func newControlPlaneIdentityFromEnv() (*controlPlaneIdentity, error) {
	identity, err := jwks.ControlPlaneIdentityFromEnv(os.Getenv)
	if err != nil || identity == nil {
		return nil, err
	}
	return &controlPlaneIdentity{
		issuer:     identity.Issuer,
		validator:  identity.Validator(true),
		requireCNF: identity.RequireCNF,
	}, nil
}

// presentedToken returns the credential (X-HELM-API-Key, else the bearer)
// when it parses as a JWT whose issuer is the configured Control Plane issuer.
// Anything else, the shared admin key included, takes the legacy path. The
// claims are not trusted here; the validator checks them next, and it
// rate-limits the key fetches an unknown kid can cause.
func (cp *controlPlaneIdentity) presentedToken(r *http.Request) (string, bool) {
	if cp == nil {
		return "", false
	}
	token, _, ok := runtimeCredentialToken(r)
	if !ok || strings.Count(token, ".") != 2 {
		return "", false
	}
	var claims jwt.RegisteredClaims
	if _, _, err := jwt.NewParser().ParseUnverified(token, &claims); err != nil {
		return "", false
	}
	return token, claims.Issuer == cp.issuer
}

type tokenWorkspaceContextKey struct{}

// requestWorkspaceID is the workspace a request asserts: the token's claim on
// the token path, otherwise X-Helm-Workspace-ID.
func requestWorkspaceID(r *http.Request) string {
	if workspace, ok := r.Context().Value(tokenWorkspaceContextKey{}).(string); ok {
		return workspace
	}
	return strings.TrimSpace(r.Header.Get(workspaceHeader))
}

// protectControlPlaneTokenOr guards a route that accepts both the legacy
// credential (legacy) and a Control Plane token for scope. RuntimeRouteSpecs
// declares the pairing as AlternateAuth; route is the metric label.
func protectControlPlaneTokenOr(svc *Services, legacy RouteAuth, route, scope string, handler http.HandlerFunc) http.HandlerFunc {
	// The wiring must match the registry: every entry this pattern serves
	// declares the token tier as its alternate and legacy as its tier. A route
	// that takes tokens without declaring it, or the reverse, fails at startup.
	specs := declaredRouteSpecs(route)
	if len(specs) == 0 {
		panic(fmt.Sprintf("Control Plane token route %q is not declared in RuntimeRouteSpecs()", route))
	}
	for _, spec := range specs {
		if spec.AlternateAuth != RouteAuthControlPlaneToken || spec.Auth != legacy {
			panic(fmt.Sprintf("route %s %s is wired for %s or a Control Plane token but declared %s/%q", spec.Method, spec.Path, legacy, spec.Auth, spec.AlternateAuth))
		}
	}
	controlPlaneIdentityMetrics.declareRoute(route)
	legacyHandler := protectRuntimeHandler(legacy, func(w http.ResponseWriter, r *http.Request) {
		controlPlaneIdentityMetrics.recordLegacy(r.Context(), route)
		handler(w, r)
	})
	return func(w http.ResponseWriter, r *http.Request) {
		var cp *controlPlaneIdentity
		if svc != nil {
			cp = svc.ControlPlaneIdentity
		}
		token, ok := cp.presentedToken(r)
		if !ok {
			legacyHandler(w, r)
			return
		}
		cp.serve(w, r, token, route, scope, handler)
	}
}

func (cp *controlPlaneIdentity) serve(w http.ResponseWriter, r *http.Request, token, route, scope string, handler http.HandlerFunc) {
	claims, err := cp.validator.ValidateAuthorization(token)
	if err != nil {
		if validationErr, ok := err.(*mcppkg.JWKSValidationError); ok && validationErr.Kind == mcppkg.JWKSErrFetchFailed {
			api.WriteError(w, http.StatusServiceUnavailable, "Control Plane identity unavailable", "the Control Plane signing keys could not be loaded")
			return
		}
		httperr.WriteUnauthorized(w, "Invalid Control Plane identity token")
		return
	}
	// One audience (this environment's kernel) and one route family per token
	// (ADR-0005 §2): a token minted for several cannot be replayed across them.
	if len(claims.RegisteredClaims.Audience) != 1 {
		httperr.WriteUnauthorized(w, "Control Plane identity token must name exactly one audience")
		return
	}
	principalID := strings.TrimSpace(claims.RegisteredClaims.Subject)
	if principalID == "" || claims.TenantID == "" || (scope != cpScopeProxyChat && claims.WorkspaceID == "") {
		httperr.WriteUnauthorized(w, "Control Plane identity token lacks its principal, tenant or workspace")
		return
	}
	if cp.requireCNF && (r.TLS == nil || len(r.TLS.PeerCertificates) == 0 ||
		!mcppkg.CertificateMatchesThumbprint(r.TLS.PeerCertificates[0], claims.CertificateThumbprint)) {
		httperr.WriteUnauthorized(w, "Control Plane identity token is not bound to this client certificate")
		return
	}
	if !tokenHasScope(claims.Scopes, scope) {
		api.WriteForbidden(w, "Control Plane identity token does not carry the "+scope+" scope")
		return
	}
	// Identity headers are no longer the source; when sent they must agree.
	for header, claim := range map[string]string{tenantHeader: claims.TenantID, principalHeader: principalID, workspaceHeader: claims.WorkspaceID} {
		if asserted := strings.TrimSpace(r.Header.Get(header)); asserted != "" && asserted != claim {
			api.WriteForbidden(w, header+" does not match the Control Plane identity token")
			return
		}
	}
	if asserted := strings.TrimSpace(r.URL.Query().Get("tenant_id")); asserted != "" && asserted != claims.TenantID {
		api.WriteForbidden(w, "tenant_id does not match the Control Plane identity token")
		return
	}
	bound, err := tokenPrincipalBound(r.Context(), claims.TenantID, principalID)
	if err != nil {
		slog.ErrorContext(r.Context(), "control plane token binding check failed, denying", "route", route, "error", err)
		api.WriteForbidden(w, "Control Plane principal binding could not be verified")
		return
	}
	if bound == principalBoundElsewhere {
		api.WriteForbidden(w, "Control Plane principal is bound to other tenants, not this one")
		return
	}
	if bound == principalUnbound {
		controlPlaneIdentityMetrics.unbound.WithLabelValues(route).Inc()
	}

	roles := []string{controlPlaneTokenRole}
	if scope == cpScopeOrganizationRuntime {
		roles = append(roles, organizationRuntimeRole)
	}
	ctx := helmauth.WithPrincipal(r.Context(), &helmauth.BasePrincipal{ID: principalID, TenantID: claims.TenantID, Roles: roles})
	ctx = helmauth.WithAuthenticatedCredential(ctx, token)
	ctx = context.WithValue(ctx, tokenWorkspaceContextKey{}, claims.WorkspaceID)
	slog.DebugContext(ctx, "control plane token accepted", "route", route, "txn", claims.TransactionID, "jti", claims.RegisteredClaims.ID)
	forwarded := r.WithContext(ctx)
	// Never pass the kernel credential on: the chat proxy forwards
	// Authorization upstream as the provider credential. A token sent there
	// is dropped; send it in X-HELM-API-Key to keep a provider key in
	// Authorization.
	forwarded.Header = r.Header.Clone()
	forwarded.Header.Del(runtimeAPIKeyHeader)
	if bearer, _, ok := helmauth.BearerToken(r); ok && bearer == token {
		forwarded.Header.Del("Authorization")
	}
	handler(w, forwarded)
}

type principalBinding int

const (
	principalBoundHere principalBinding = iota
	principalUnbound
	principalBoundElsewhere
)

// tokenPrincipalBound is the ADR-0005 §3 cross-check. A principal with a
// binding row must be bound to the token's tenant; a principal with none
// passes on the token alone (and is counted). The tenant lookup runs in a
// transaction bound to the token's tenant (store.WithTenant under forced row
// security); the any-tenant lookup is bound to the principal.
func tokenPrincipalBound(ctx context.Context, tenantID, principalID string) (principalBinding, error) {
	bindings := principalBindingStore
	if bindings == nil {
		return principalUnbound, nil
	}
	here, err := bindings.Exists(ctx, tenantID, principalID)
	if err != nil {
		return 0, err
	}
	if here {
		return principalBoundHere, nil
	}
	lookup, ok := bindings.(store.PrincipalBindingLookup)
	if !ok {
		return 0, fmt.Errorf("principal binding store %T cannot look a principal up across tenants", bindings)
	}
	anywhere, err := lookup.PrincipalBound(ctx, principalID)
	if err != nil {
		return 0, err
	}
	if anywhere {
		return principalBoundElsewhere, nil
	}
	return principalUnbound, nil
}

// tokenHasScope requires the token to carry exactly the route family's scope.
func tokenHasScope(values []string, want string) bool {
	return len(values) == 1 && values[0] == want
}

// controlPlaneIdentityMetrics are the ADR-0005 phase-3 signals, per route:
// helm_legacy_header_identity_total counts requests still authenticated by the
// shared key and headers; helm_token_unbound_principal_total counts valid
// tokens whose principal has no binding row; helm_principal_rebind_refused_total
// counts binds refused because the principal is bound in another tenant.
var controlPlaneIdentityMetrics = newControlPlaneIdentityMetricSet(time.Now)

type controlPlaneIdentityMetricSet struct {
	registry *prometheus.Registry
	legacy   *prometheus.CounterVec
	unbound  *prometheus.CounterVec

	rebindRefused prometheus.Counter

	mu         sync.Mutex
	now        func() time.Time
	lastLogged map[string]time.Time
}

const legacyIdentityLogInterval = time.Hour

func newControlPlaneIdentityMetricSet(now func() time.Time) *controlPlaneIdentityMetricSet {
	m := &controlPlaneIdentityMetricSet{
		registry: prometheus.NewRegistry(),
		legacy: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "helm_legacy_header_identity_total",
			Help: "Requests on Control Plane routes authenticated by the shared kernel key and X-Helm-* identity headers (ADR-0005).",
		}, []string{"route"}),
		unbound: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "helm_token_unbound_principal_total",
			Help: "Valid Control Plane identity tokens whose principal has no principal_bindings row (ADR-0005 §3).",
		}, []string{"route"}),
		rebindRefused: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "helm_principal_rebind_refused_total",
			Help: "Principal binds refused because the principal is already bound in another tenant (ADR-0005 §11).",
		}),
		now:        now,
		lastLogged: map[string]time.Time{},
	}
	m.registry.MustRegister(m.legacy, m.unbound, m.rebindRefused)
	return m
}

// declareRoute makes both series exist at zero for route, so "zero on every
// route" is observable rather than inferred from absence.
func (m *controlPlaneIdentityMetricSet) declareRoute(route string) {
	m.legacy.WithLabelValues(route)
	m.unbound.WithLabelValues(route)
}

// recordLegacy counts one legacy-authenticated request and logs it at most
// once per route, tenant and principal per hour.
func (m *controlPlaneIdentityMetricSet) recordLegacy(ctx context.Context, route string) {
	m.legacy.WithLabelValues(route).Inc()
	tenantID, principalID := "", ""
	if principal, err := helmauth.GetPrincipal(ctx); err == nil && principal != nil {
		tenantID, principalID = principal.GetTenantID(), principal.GetID()
	}
	if m.shouldLog(route + "\x00" + tenantID + "\x00" + principalID) {
		slog.InfoContext(ctx, "legacy header identity used on a Control Plane route (ADR-0005 phase 1)",
			"route", route, "tenant_id", tenantID, "principal_id", principalID)
	}
}

func (m *controlPlaneIdentityMetricSet) shouldLog(key string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	if last, ok := m.lastLogged[key]; ok && now.Sub(last) < legacyIdentityLogInterval {
		return false
	}
	// Bounded: entries older than the interval can no longer suppress a line.
	if len(m.lastLogged) >= 4096 {
		for k, last := range m.lastLogged {
			if now.Sub(last) >= legacyIdentityLogInterval {
				delete(m.lastLogged, k)
			}
		}
	}
	m.lastLogged[key] = now
	return true
}

func (m *controlPlaneIdentityMetricSet) PrometheusGatherer() prometheus.Gatherer {
	return m.registry
}
