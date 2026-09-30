package main

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"strings"

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

// RegisterPrincipalBindingRoutes exposes the admin-only endpoint used to
// register (tenant_id, principal_id) bindings so the kernel can authorize
// many tenants instead of a single env-configured pair (see
// pkg/store.PrincipalBindingStore).
//
// A new binding answers 201 and an existing one 200. A principal already
// bound in another tenant is refused with 409 TENANT_ISOLATION and counted in
// helm_principal_rebind_refused_total, unless HELM_CROSS_TENANT_PRINCIPALS
// lists it; each cross-tenant bind of a listed principal is logged.
func RegisterPrincipalBindingRoutes(mux routeMux, svc *Services, opts serverOptions) {
	crossTenant := crossTenantPrincipalsFromEnv()
	mux.HandleFunc("/api/v1/admin/principal-bindings", protectRuntimeHandler(RouteAuthAdmin, func(w http.ResponseWriter, r *http.Request) {
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
	}))
}
