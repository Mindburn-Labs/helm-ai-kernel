package main

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/api"
	policyreconcile "github.com/Mindburn-Labs/helm-oss/core/pkg/policy/reconcile"
)

func registerPolicyReconcileRoutes(mux *http.ServeMux, svc *Services) {
	mux.HandleFunc("/internal/policy/reconcile", protectRuntimeHandler(RouteAuthService, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			api.WriteMethodNotAllowed(w)
			return
		}
		if requestHasBody(r) {
			api.WriteBadRequest(w, "policy reconcile does not accept request body")
			return
		}
		if svc == nil || svc.PolicyReconciler == nil {
			api.WriteError(w, http.StatusServiceUnavailable, "Policy reconciler unavailable", "runtime policy reconciler is not initialized")
			return
		}

		scope := svc.PolicyScope.Normalize()
		if scope.Key() == policyreconcile.DefaultScope.Key() {
			scope = policyreconcile.DefaultScope
		}
		status, _ := svc.PolicyReconciler.Reconcile(r.Context(), scope)
		if status.ReconcileStatus == "" {
			status = policyreconcile.ReconcileStatus{
				TenantID:        scope.TenantID,
				WorkspaceID:     scope.WorkspaceID,
				ReconcileStatus: policyreconcile.StatusNoPolicy,
				SnapshotStatus:  policyreconcile.StatusNoPolicy,
			}
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(status)
	}))
}

func requestHasBody(r *http.Request) bool {
	if r.Body == nil {
		return false
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, 1))
	if err != nil {
		return true
	}
	return len(data) > 0
}
