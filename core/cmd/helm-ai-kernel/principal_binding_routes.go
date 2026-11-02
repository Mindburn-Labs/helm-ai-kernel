package main

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/api"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/httperr"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/store"
)

var errPrincipalBindingsUnavailable = errors.New("principal binding store not configured")

// crossTenantPrincipalsEnv lists, comma-separated, the principals that may
// hold bindings in more than one tenant (ADR-0005 §11), such as the Control
// Plane's helm-workflow-runner. Empty by default: every other principal is
// bound in one tenant only. Listing a principal widens the ADR-0005 §3 token
// cross-check for exactly that principal: it passes in every tenant it is
// bound to.
const crossTenantPrincipalsEnv = "HELM_CROSS_TENANT_PRINCIPALS"

func crossTenantPrincipalsFromEnv() map[string]bool {
	allowed := map[string]bool{}
	for _, id := range strings.Split(os.Getenv(crossTenantPrincipalsEnv), ",") {
		if id = strings.TrimSpace(id); id != "" {
			allowed[id] = true
		}
	}
	return allowed
}

type principalBindingRequest struct {
	TenantID    string `json:"tenant_id"`
	PrincipalID string `json:"principal_id"`
}

type principalBindingReadResponse struct {
	TenantID    string `json:"tenant_id"`
	PrincipalID string `json:"principal_id"`
	Bound       bool   `json:"bound"`
}

// RegisterPrincipalBindingRoutes exposes the admin-only endpoint used to
// observe or register (tenant_id, principal_id) bindings so the kernel can authorize
// many tenants instead of a single env-configured pair (see
// pkg/store.PrincipalBindingStore).
//
// GET observes only the exact pair selected by tenant_id and principal_id;
// it never enrolls a principal. Each selector is a single nonempty UTF-8 value
// of at most 256 bytes without whitespace or control characters. Extra or
// duplicate selectors and queries over 2048 bytes are refused. A missing pair
// answers bound=false, while an unavailable store answers 503. GET responses
// are never cacheable.
//
// A new binding answers 201 and an existing one 200. A principal already
// bound in another tenant is refused with 409 TENANT_ISOLATION and counted in
// helm_principal_rebind_refused_total, unless HELM_CROSS_TENANT_PRINCIPALS
// lists it; each cross-tenant bind of a listed principal is logged.
func RegisterPrincipalBindingRoutes(mux routeMux, svc *Services, opts serverOptions) {
	crossTenant := crossTenantPrincipalsFromEnv()
	handler := protectRuntimeHandler(RouteAuthAdmin, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			readPrincipalBinding(w, r, svc)
			return
		}
		if r.Method != http.MethodPost {
			api.WriteMethodNotAllowed(w)
			return
		}
		var req principalBindingRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			api.WriteBadRequest(w, "Invalid JSON body")
			return
		}
		tenantID := strings.TrimSpace(req.TenantID)
		principalID := strings.TrimSpace(req.PrincipalID)
		if tenantID == "" || principalID == "" {
			api.WriteBadRequest(w, "tenant_id and principal_id are required")
			return
		}
		if svc == nil || svc.PrincipalBindings == nil {
			api.WriteInternalR(w, r, errPrincipalBindingsUnavailable)
			return
		}
		result, err := svc.PrincipalBindings.Bind(r.Context(), store.PrincipalBinding{
			TenantID:    tenantID,
			PrincipalID: principalID,
		}, crossTenant[principalID])
		if err != nil {
			api.WriteInternalR(w, r, err)
			return
		}
		status := http.StatusOK
		switch result.Outcome {
		case store.BindRefusedCrossTenant:
			controlPlaneIdentityMetrics.rebindRefused.Inc()
			slog.WarnContext(r.Context(), "refused to bind a principal already bound in another tenant (ADR-0005 §11)",
				"tenant_id", tenantID, "principal_id", principalID, "bound_tenants", result.OtherTenants)
			problem := httperr.NewProblem(http.StatusConflict, "Conflict",
				"principal is already bound in another tenant", string(contracts.ReasonTenantIsolation))
			problem.Instance = r.URL.Path
			problem.TraceID = w.Header().Get("X-Request-ID")
			httperr.WriteProblem(w, problem)
			return
		case store.BindCreated:
			status = http.StatusCreated
		}
		if len(result.OtherTenants) > 0 {
			slog.InfoContext(r.Context(), "cross-tenant principal binding ("+crossTenantPrincipalsEnv+")",
				"tenant_id", tenantID, "principal_id", principalID, "created", result.Outcome == store.BindCreated,
				"other_tenants", result.OtherTenants)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(principalBindingRequest{
			TenantID:    tenantID,
			PrincipalID: principalID,
		})
	})
	mux.HandleFunc("/api/v1/admin/principal-bindings", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("Cache-Control", "no-store")
		}
		handler(w, r)
	})
}

func readPrincipalBinding(w http.ResponseWriter, r *http.Request, svc *Services) {
	req, err := principalBindingReadSelectors(r.URL.RawQuery)
	if err != nil {
		api.WriteBadRequest(w, "Exactly one canonical tenant_id and principal_id are required")
		return
	}
	if svc == nil || svc.PrincipalBindings == nil {
		api.WriteErrorR(w, r, http.StatusServiceUnavailable, "Service Unavailable", "Principal binding lookup is unavailable")
		return
	}
	bound, err := svc.PrincipalBindings.Exists(r.Context(), req.TenantID, req.PrincipalID)
	if err != nil {
		slog.ErrorContext(r.Context(), "principal binding lookup unavailable", "error", err)
		api.WriteErrorR(w, r, http.StatusServiceUnavailable, "Service Unavailable", "Principal binding lookup is unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(principalBindingReadResponse{
		TenantID: req.TenantID, PrincipalID: req.PrincipalID, Bound: bound,
	})
}

func principalBindingReadSelectors(rawQuery string) (principalBindingRequest, error) {
	invalid := errors.New("invalid principal binding selectors")
	if len(rawQuery) > 2048 {
		return principalBindingRequest{}, invalid
	}
	values, err := url.ParseQuery(rawQuery)
	if err != nil || len(values) != 2 || len(values["tenant_id"]) != 1 || len(values["principal_id"]) != 1 {
		return principalBindingRequest{}, invalid
	}
	req := principalBindingRequest{TenantID: values["tenant_id"][0], PrincipalID: values["principal_id"][0]}
	for _, id := range []string{req.TenantID, req.PrincipalID} {
		if len(id) == 0 || len(id) > 256 || !utf8.ValidString(id) {
			return principalBindingRequest{}, invalid
		}
		for _, char := range id {
			if unicode.IsSpace(char) || unicode.IsControl(char) {
				return principalBindingRequest{}, invalid
			}
		}
	}
	return req, nil
}
