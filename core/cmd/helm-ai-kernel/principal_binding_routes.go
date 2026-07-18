package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/api"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/store"
)

var errPrincipalBindingsUnavailable = errors.New("principal binding store not configured")

type principalBindingRequest struct {
	TenantID    string `json:"tenant_id"`
	PrincipalID string `json:"principal_id"`
}

// RegisterPrincipalBindingRoutes exposes the admin-only endpoint used to
// register (tenant_id, principal_id) bindings so the kernel can authorize
// many tenants instead of a single env-configured pair (see
// pkg/store.PrincipalBindingStore).
func RegisterPrincipalBindingRoutes(mux *http.ServeMux, svc *Services, opts serverOptions) {
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
			api.WriteInternal(w, errPrincipalBindingsUnavailable)
			return
		}
		if err := svc.PrincipalBindings.Upsert(r.Context(), store.PrincipalBinding{
			TenantID:    tenantID,
			PrincipalID: principalID,
		}); err != nil {
			api.WriteInternal(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(principalBindingRequest{
			TenantID:    tenantID,
			PrincipalID: principalID,
		})
	}))
}
