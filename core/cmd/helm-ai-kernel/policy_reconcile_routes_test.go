package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	policyreconcile "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/policy/reconcile"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/prg"
)

func newPolicyReconcileRouteServices(t *testing.T) *Services {
	t.Helper()
	scope := policyreconcile.DefaultScope
	bundle := []byte("policy-route")
	head := policyreconcile.PolicyHead{
		Scope:       scope,
		PolicyEpoch: 42,
		PolicyHash:  policyreconcile.HashBytes(bundle),
		BundleRef:   "policy.toml",
	}
	source := policyreconcile.NewStaticSource(head, bundle)
	store := policyreconcile.NewAtomicSnapshotStore()
	reconciler, err := policyreconcile.NewReconciler(policyreconcile.ReconcilerConfig{
		Source: source,
		Store:  store,
		Compiler: func(_ context.Context, head policyreconcile.PolicyHead, _ []byte) (*policyreconcile.EffectivePolicySnapshot, error) {
			scope := head.Scope.Normalize()
			return &policyreconcile.EffectivePolicySnapshot{
				TenantID:    scope.TenantID,
				WorkspaceID: scope.WorkspaceID,
				PolicyEpoch: head.PolicyEpoch,
				PolicyHash:  head.PolicyHash,
				Validation:  policyreconcile.ValidationStatus{Status: policyreconcile.StatusActive},
				Graph:       prg.NewGraph(),
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("new reconciler: %v", err)
	}
	return &Services{PolicyReconciler: reconciler, PolicySnapshotStore: store, PolicyScope: scope}
}

func TestPolicyReconcileRouteRequiresServiceAuth(t *testing.T) {
	t.Setenv(serviceAPIKeyEnv, "route-secret")
	mux := http.NewServeMux()
	registerPolicyReconcileRoutes(mux, newPolicyReconcileRouteServices(t))

	req := httptest.NewRequest(http.MethodPost, "/internal/policy/reconcile", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected unauthorized, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestPolicyReconcileRouteIsPostOnlyAndWakeOnly(t *testing.T) {
	t.Setenv(serviceAPIKeyEnv, "route-secret")
	mux := http.NewServeMux()
	registerPolicyReconcileRoutes(mux, newPolicyReconcileRouteServices(t))

	getReq := httptest.NewRequest(http.MethodGet, "/internal/policy/reconcile", nil)
	getReq.Header.Set("Authorization", "Bearer route-secret")
	getRec := httptest.NewRecorder()
	mux.ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected method not allowed, got %d", getRec.Code)
	}

	bodyReq := httptest.NewRequest(http.MethodPost, "/internal/policy/reconcile", strings.NewReader(`{"install":"no"}`))
	bodyReq.Header.Set("Authorization", "Bearer route-secret")
	bodyRec := httptest.NewRecorder()
	mux.ServeHTTP(bodyRec, bodyReq)
	if bodyRec.Code != http.StatusBadRequest {
		t.Fatalf("expected bad request for body, got %d", bodyRec.Code)
	}
}

func TestPolicyReconcileRouteReturnsInstalledStatus(t *testing.T) {
	t.Setenv(serviceAPIKeyEnv, "route-secret")
	mux := http.NewServeMux()
	registerPolicyReconcileRoutes(mux, newPolicyReconcileRouteServices(t))

	req := httptest.NewRequest(http.MethodPost, "/internal/policy/reconcile", nil)
	req.Header.Set("Authorization", "Bearer route-secret")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected ok, got %d body=%s", rec.Code, rec.Body.String())
	}
	var status policyreconcile.ReconcileStatus
	if err := json.NewDecoder(rec.Body).Decode(&status); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if status.InstalledPolicyEpoch != 42 || status.InstalledPolicyHash == "" || status.ReconcileStatus != "ok" {
		t.Fatalf("unexpected reconcile status: %+v", status)
	}
	if status.PolicyEpoch != status.InstalledPolicyEpoch || status.PolicyHash != status.InstalledPolicyHash {
		t.Fatalf("short policy fields did not mirror installed snapshot: %+v", status)
	}
}

func TestPolicyReconcileRouteIsIdempotent(t *testing.T) {
	t.Setenv(serviceAPIKeyEnv, "route-secret")
	mux := http.NewServeMux()
	registerPolicyReconcileRoutes(mux, newPolicyReconcileRouteServices(t))

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/internal/policy/reconcile", nil)
		req.Header.Set("Authorization", "Bearer route-secret")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: expected ok, got %d body=%s", i+1, rec.Code, rec.Body.String())
		}
		if i == 1 {
			var status policyreconcile.ReconcileStatus
			if err := json.NewDecoder(rec.Body).Decode(&status); err != nil {
				t.Fatalf("decode second status: %v", err)
			}
			if status.ReconcileStatus != policyreconcile.StatusNoChange || status.Updated {
				t.Fatalf("second reconcile was not idempotent: %+v", status)
			}
			if status.PolicyEpoch != 42 || status.PolicyHash == "" {
				t.Fatalf("idempotent status lost installed authority fields: %+v", status)
			}
		}
	}
}
