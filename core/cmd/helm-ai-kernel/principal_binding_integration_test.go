package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/store"

	_ "modernc.org/sqlite"
)

// TestPrincipalBindingEndpointToGateSharedStoreInvariant proves the
// endpoint-write is visible to the gate-read through the SAME store
// instance — the exact end-to-end property the feature exists for. Task 2's
// admin endpoint (RegisterPrincipalBindingRoutes) and Task 3's tenant gate
// (requireRuntimeTenant, via SetPrincipalBindingStore) each hold their own
// handle to a store.PrincipalBindingStore: *Services.PrincipalBindings for
// the endpoint, the package-level principalBindingStore for the gate. In
// production both are wired to the same instance in main.go (lines
// ~369-370); this test is the only place that wiring is verified rather than
// merely inspected — a future refactor that splits the two sinks apart
// would be caught here.
func TestPrincipalBindingEndpointToGateSharedStoreInvariant(t *testing.T) {
	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
	t.Setenv(runtimeTenantIDEnv, "tenant-a")
	t.Setenv(runtimePrincipalIDEnv, "principal-a")

	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	sharedStore, err := store.NewSQLitePrincipalBindingStore(db)
	if err != nil {
		t.Fatal(err)
	}

	// Wire the ONE store instance both ways, exactly as main.go does at
	// registration: onto *Services for the admin endpoint, and into the
	// gate via SetPrincipalBindingStore.
	svc := &Services{PrincipalBindings: sharedStore}
	SetPrincipalBindingStore(sharedStore)
	t.Cleanup(func() { SetPrincipalBindingStore(nil) })

	mux := http.NewServeMux()
	RegisterPrincipalBindingRoutes(mux, svc, serverOptions{Mode: "serve"})

	// 1. Register a NON-env (tenant, principal) pair through the admin
	// endpoint — the same path an operator would use.
	body, _ := json.Marshal(map[string]string{"tenant_id": "tenant-x", "principal_id": "principal-x"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/principal-bindings", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testAdminAPIKey)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code < 200 || rec.Code >= 300 {
		t.Fatalf("principal binding registration status = %d body=%s", rec.Code, rec.Body.String())
	}

	// 2. Drive the tenant gate with the pair just registered — it must be
	// accepted through the SAME store instance the endpoint just wrote to.
	gate := protectRuntimeHandler(RouteAuthTenant, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	gateReq := httptest.NewRequest(http.MethodGet, "/api/v1/receipts", nil)
	gateReq.Header.Set("Authorization", "Bearer "+testAdminAPIKey)
	gateReq.Header.Set(tenantHeader, "tenant-x")
	gateReq.Header.Set(principalHeader, "principal-x")
	gateRec := httptest.NewRecorder()
	gate(gateRec, gateReq)

	if gateRec.Code != http.StatusNoContent {
		t.Fatalf("tenant gate for endpoint-registered pair status = %d, want %d body=%s", gateRec.Code, http.StatusNoContent, gateRec.Body.String())
	}

	// 3. Negative control: an unregistered non-env pair must still 403 —
	// proving acceptance above came from the shared store, not from a gate
	// that accepts anything once the store is non-nil.
	negReq := httptest.NewRequest(http.MethodGet, "/api/v1/receipts", nil)
	negReq.Header.Set("Authorization", "Bearer "+testAdminAPIKey)
	negReq.Header.Set(tenantHeader, "tenant-y")
	negReq.Header.Set(principalHeader, "principal-y")
	negRec := httptest.NewRecorder()
	gate(negRec, negReq)

	if negRec.Code != http.StatusForbidden {
		t.Fatalf("tenant gate for unregistered non-env pair status = %d, want %d body=%s", negRec.Code, http.StatusForbidden, negRec.Body.String())
	}
}

func TestPrincipalBindingReadUsesExactRealStoreWithoutWrites(t *testing.T) {
	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	// Keep PRAGMA query_only and total_changes on the same physical connection.
	db.SetMaxOpenConns(1)
	s, err := store.NewSQLitePrincipalBindingStore(db)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := s.Bind(context.Background(), store.PrincipalBinding{TenantID: "tenant-a", PrincipalID: "principal-a"}, false); err != nil || result.Outcome != store.BindCreated {
		t.Fatalf("fixture owner seed: %+v %v", result, err)
	}
	var before int
	if err := db.QueryRow("SELECT total_changes()").Scan(&before); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("PRAGMA query_only = ON"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("DELETE FROM principal_bindings"); err == nil {
		t.Fatal("read-only connection unexpectedly permits a binding write")
	}
	mux := http.NewServeMux()
	RegisterPrincipalBindingRoutes(mux, &Services{PrincipalBindings: s}, serverOptions{Mode: "serve"})
	for _, tc := range []struct {
		query string
		bound bool
	}{
		{"tenant_id=tenant-a&principal_id=principal-a", true},
		{"tenant_id=tenant-b&principal_id=principal-a", false},
		{"tenant_id=tenant-a&principal_id=principal-b", false},
	} {
		rec := getPrincipalBindingForTest(mux, testAdminAPIKey, tc.query)
		if rec.Code != http.StatusOK {
			t.Fatalf("query-only read = %d %s", rec.Code, rec.Body.String())
		}
		var got principalBindingReadResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || got.Bound != tc.bound {
			t.Fatalf("exact-pair read = %+v err=%v, want bound=%v", got, err, tc.bound)
		}
	}
	var after, rows int
	if err := db.QueryRow("SELECT total_changes()").Scan(&after); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow("SELECT count(*) FROM principal_bindings").Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if after != before || rows != 1 {
		t.Fatalf("read mutated real registry: changes %d -> %d, rows=%d", before, after, rows)
	}
}
