package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/httperr"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/store"

	_ "modernc.org/sqlite"
)

func newPrincipalBindingTestServices(t *testing.T) (*Services, store.PrincipalBindingStore, func()) {
	t.Helper()
	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	bindingStore, err := store.NewSQLitePrincipalBindingStore(db)
	if err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	return &Services{PrincipalBindings: bindingStore}, bindingStore, func() { _ = db.Close() }
}

func postPrincipalBindingForTest(mux *http.ServeMux, bearer, tenantID, principalID string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]string{"tenant_id": tenantID, "principal_id": principalID})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/principal-bindings", bytes.NewReader(body))
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestPrincipalBindingRoutesUpsertsAndIsIdempotent(t *testing.T) {
	svc, bindingStore, cleanup := newPrincipalBindingTestServices(t)
	defer cleanup()
	mux := http.NewServeMux()
	RegisterPrincipalBindingRoutes(mux, svc, serverOptions{Mode: "serve"})

	rec := postPrincipalBindingForTest(mux, testAdminAPIKey, "acme", "acme-admin")
	if rec.Code != http.StatusCreated {
		t.Fatalf("principal binding register status = %d body=%s", rec.Code, rec.Body.String())
	}

	ok, err := bindingStore.Exists(context.Background(), "acme", "acme-admin")
	if err != nil {
		t.Fatalf("Exists returned error: %v", err)
	}
	if !ok {
		t.Fatal("expected binding to exist after registration")
	}

	// Re-POST the same pair must remain idempotent: 200, nothing new.
	rec2 := postPrincipalBindingForTest(mux, testAdminAPIKey, "acme", "acme-admin")
	if rec2.Code != http.StatusOK {
		t.Fatalf("repeat principal binding register status = %d body=%s", rec2.Code, rec2.Body.String())
	}
}

func TestPrincipalBindingRoutesRejectMissingBearer(t *testing.T) {
	svc, _, cleanup := newPrincipalBindingTestServices(t)
	defer cleanup()
	mux := http.NewServeMux()
	RegisterPrincipalBindingRoutes(mux, svc, serverOptions{Mode: "serve"})

	rec := postPrincipalBindingForTest(mux, "", "acme", "acme-admin")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("principal binding register without bearer status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestPrincipalBindingRoutesRejectInvalidBearer(t *testing.T) {
	svc, _, cleanup := newPrincipalBindingTestServices(t)
	defer cleanup()
	mux := http.NewServeMux()
	RegisterPrincipalBindingRoutes(mux, svc, serverOptions{Mode: "serve"})

	rec := postPrincipalBindingForTest(mux, "not-the-admin-key", "acme", "acme-admin")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("principal binding register with invalid bearer status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestPrincipalBindingRoutesRejectMissingFields(t *testing.T) {
	svc, _, cleanup := newPrincipalBindingTestServices(t)
	defer cleanup()
	mux := http.NewServeMux()
	RegisterPrincipalBindingRoutes(mux, svc, serverOptions{Mode: "serve"})

	rec := postPrincipalBindingForTest(mux, testAdminAPIKey, "", "x")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("principal binding register with missing tenant_id status = %d body=%s", rec.Code, rec.Body.String())
	}

	rec2 := postPrincipalBindingForTest(mux, testAdminAPIKey, "acme", "")
	if rec2.Code != http.StatusBadRequest {
		t.Fatalf("principal binding register with missing principal_id status = %d body=%s", rec2.Code, rec2.Body.String())
	}
}

// ADR-0005 §11: binding a principal that is already bound in another tenant is
// refused with 409 TENANT_ISOLATION and counted; nothing is written, and the
// original binding stays idempotent.
func TestPrincipalBindingRouteRefusesCrossTenantRebind(t *testing.T) {
	t.Setenv(crossTenantPrincipalsEnv, "")
	svc, bindingStore, cleanup := newPrincipalBindingTestServices(t)
	defer cleanup()
	mux := http.NewServeMux()
	RegisterPrincipalBindingRoutes(mux, svc, serverOptions{Mode: "serve"})
	refused := func() float64 { return testutil.ToFloat64(controlPlaneIdentityMetrics.rebindRefused) }

	if rec := postPrincipalBindingForTest(mux, testAdminAPIKey, "tenant-a", "member-a"); rec.Code != http.StatusCreated {
		t.Fatalf("first bind: %d %s", rec.Code, rec.Body.String())
	}
	before := refused()
	rec := postPrincipalBindingForTest(mux, testAdminAPIKey, "tenant-b", "member-a")
	if rec.Code != http.StatusConflict {
		t.Fatalf("bind into a second tenant: %d %s, want 409", rec.Code, rec.Body.String())
	}
	var problem httperr.ProblemDetail
	if err := json.Unmarshal(rec.Body.Bytes(), &problem); err != nil {
		t.Fatal(err)
	}
	if len(problem.Details) != 1 || problem.Details[0].Debug.ReasonCode != "TENANT_ISOLATION" {
		t.Fatalf("409 reason code = %+v, want TENANT_ISOLATION", problem.Details)
	}
	if bytes.Contains(rec.Body.Bytes(), []byte("tenant-a")) {
		t.Fatalf("the refusal names the other tenant: %s", rec.Body.String())
	}
	if refused() != before+1 {
		t.Fatalf("helm_principal_rebind_refused_total = %v, want %v", refused(), before+1)
	}
	if ok, err := bindingStore.Exists(context.Background(), "tenant-b", "member-a"); err != nil || ok {
		t.Fatalf("a refused bind was written: ok=%v err=%v", ok, err)
	}
	if rec := postPrincipalBindingForTest(mux, testAdminAPIKey, "tenant-a", "member-a"); rec.Code != http.StatusOK {
		t.Fatalf("re-bind in the principal's own tenant: %d, want 200", rec.Code)
	}
}

// Only principals listed in HELM_CROSS_TENANT_PRINCIPALS may hold bindings in
// several tenants.
func TestPrincipalBindingRouteAllowsListedCrossTenantPrincipals(t *testing.T) {
	t.Setenv(crossTenantPrincipalsEnv, " helm-workflow-runner , ,other-runner")
	svc, bindingStore, cleanup := newPrincipalBindingTestServices(t)
	defer cleanup()
	mux := http.NewServeMux()
	RegisterPrincipalBindingRoutes(mux, svc, serverOptions{Mode: "serve"})
	before := testutil.ToFloat64(controlPlaneIdentityMetrics.rebindRefused)

	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		if rec := postPrincipalBindingForTest(mux, testAdminAPIKey, tenant, "helm-workflow-runner"); rec.Code != http.StatusCreated {
			t.Fatalf("listed principal into %s: %d %s", tenant, rec.Code, rec.Body.String())
		}
		if ok, err := bindingStore.Exists(context.Background(), tenant, "helm-workflow-runner"); err != nil || !ok {
			t.Fatalf("listed principal not bound in %s: ok=%v err=%v", tenant, ok, err)
		}
	}
	if got := testutil.ToFloat64(controlPlaneIdentityMetrics.rebindRefused); got != before {
		t.Fatalf("a listed principal's bind was counted as refused: %v -> %v", before, got)
	}
	postPrincipalBindingForTest(mux, testAdminAPIKey, "tenant-a", "member-a")
	if rec := postPrincipalBindingForTest(mux, testAdminAPIKey, "tenant-b", "member-a"); rec.Code != http.StatusConflict {
		t.Fatalf("an unlisted principal into a second tenant: %d, want 409", rec.Code)
	}
}

type principalBindingReadTestStore struct {
	bound       bool
	err         error
	existsCalls int
	bindCalls   int
	tenantID    string
	principalID string
}

func (s *principalBindingReadTestStore) Bind(context.Context, store.PrincipalBinding, bool) (store.BindResult, error) {
	s.bindCalls++
	return store.BindResult{}, errors.New("read path attempted a binding write")
}

func (s *principalBindingReadTestStore) Exists(_ context.Context, tenantID, principalID string) (bool, error) {
	s.existsCalls++
	s.tenantID, s.principalID = tenantID, principalID
	return s.bound, s.err
}

func getPrincipalBindingForTest(mux *http.ServeMux, bearer, query string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/principal-bindings?"+query, nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestPrincipalBindingReadFreshExactPairAndClosedResponse(t *testing.T) {
	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
	for _, ids := range [][2]string{{"tenant-a", "principal-a"}, {strings.Repeat("t", 256), strings.Repeat("é", 128)}} {
		s := &principalBindingReadTestStore{}
		mux := http.NewServeMux()
		RegisterPrincipalBindingRoutes(mux, &Services{PrincipalBindings: s}, serverOptions{Mode: "serve"})
		query := url.Values{"tenant_id": {ids[0]}, "principal_id": {ids[1]}}.Encode()
		for i, bound := range []bool{false, true, false} {
			s.bound = bound
			rec := getPrincipalBindingForTest(mux, testAdminAPIKey, query)
			if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Content-Type") != "application/json" {
				t.Fatalf("read status/headers = %d %v body=%s", rec.Code, rec.Header(), rec.Body.String())
			}
			var got map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if len(got) != 3 || got["tenant_id"] != ids[0] || got["principal_id"] != ids[1] || got["bound"] != bound {
				t.Fatalf("read response is not the exact closed current tuple: %+v", got)
			}
			if s.existsCalls != i+1 || s.tenantID != ids[0] || s.principalID != ids[1] || s.bindCalls != 0 {
				t.Fatalf("unexpected store calls: %+v", s)
			}
		}
	}
}

func TestPrincipalBindingReadRejectsInvalidSelectorsBeforeLookup(t *testing.T) {
	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
	for _, query := range []string{
		"", "tenant_id=t", "principal_id=p", "tenant_id=&principal_id=p", "tenant_id=t&principal_id=",
		"tenant_id=t&tenant_id=t&principal_id=p", "tenant_id=t&principal_id=p&principal_id=p",
		"tenant_id=t&tenant%5Fid=t&principal_id=p", "tenant_id=t&principal_id=p&extra=x",
		"tenant_id=t&principal_id=p&=x", "tenant_id=t&principal_id=p;extra=x",
		"tenant_id=%zz&principal_id=p", "tenant_id=t&principal_id=%ff", "tenant_id=t&principal_id=p%00",
		"tenant_id=+t&principal_id=p", "tenant_id=t&principal_id=p+", "tenant_id=t&principal_id=p%0A",
		"tenant_id=t&principal_id=" + url.QueryEscape("p\u00a0x"),
		"tenant_id=" + strings.Repeat("t", 257) + "&principal_id=p",
		"tenant_id=t&principal_id=" + url.QueryEscape(strings.Repeat("é", 129)),
		"tenant_id=" + strings.Repeat("%74", 700) + "&principal_id=p",
	} {
		t.Run(query, func(t *testing.T) {
			s := &principalBindingReadTestStore{bound: true}
			mux := http.NewServeMux()
			RegisterPrincipalBindingRoutes(mux, &Services{PrincipalBindings: s}, serverOptions{Mode: "serve"})
			rec := getPrincipalBindingForTest(mux, testAdminAPIKey, query)
			if rec.Code != http.StatusBadRequest || rec.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("invalid selector status = %d headers=%v body=%s", rec.Code, rec.Header(), rec.Body.String())
			}
			if s.existsCalls != 0 || s.bindCalls != 0 {
				t.Fatalf("invalid selectors reached store: %+v", s)
			}
		})
	}
}

func TestPrincipalBindingReadRequiresExistingAdminAuthentication(t *testing.T) {
	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
	for _, bearer := range []string{"", "invalid-admin"} {
		s := &principalBindingReadTestStore{bound: true}
		mux := http.NewServeMux()
		RegisterPrincipalBindingRoutes(mux, &Services{PrincipalBindings: s}, serverOptions{Mode: "serve"})
		rec := getPrincipalBindingForTest(mux, bearer, "tenant_id=t&principal_id=p")
		if rec.Code != http.StatusUnauthorized || rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("unauthorized read = %d %v %s", rec.Code, rec.Header(), rec.Body.String())
		}
		if s.existsCalls != 0 || s.bindCalls != 0 {
			t.Fatalf("unauthorized request reached store: %+v", s)
		}
	}
}

func TestPrincipalBindingReadUnavailableNeverReturnsBindingProof(t *testing.T) {
	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
	failed := &principalBindingReadTestStore{bound: true, err: errors.New("private-lookup-error")}
	for name, svc := range map[string]*Services{
		"nil-service": nil, "nil-store": {}, "lookup-error": {PrincipalBindings: failed},
	} {
		t.Run(name, func(t *testing.T) {
			mux := http.NewServeMux()
			RegisterPrincipalBindingRoutes(mux, svc, serverOptions{Mode: "serve"})
			rec := getPrincipalBindingForTest(mux, testAdminAPIKey, "tenant_id=t&principal_id=p")
			if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("unavailable read = %d %v %s", rec.Code, rec.Header(), rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), "private-lookup-error") || strings.Contains(rec.Body.String(), `"bound"`) {
				t.Fatalf("unavailable response leaked lookup details or binding proof: %s", rec.Body.String())
			}
		})
	}
	if failed.existsCalls != 1 || failed.bindCalls != 0 {
		t.Fatalf("unexpected unavailable store calls: %+v", failed)
	}
}

func TestPrincipalBindingReadKeepsOtherMethodsRefused(t *testing.T) {
	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
	s := &principalBindingReadTestStore{bound: true}
	mux := http.NewServeMux()
	RegisterPrincipalBindingRoutes(mux, &Services{PrincipalBindings: s}, serverOptions{Mode: "serve"})
	for _, method := range []string{http.MethodHead, http.MethodPut, http.MethodDelete, http.MethodOptions} {
		req := httptest.NewRequest(method, "/api/v1/admin/principal-bindings?tenant_id=t&principal_id=p", nil)
		req.Header.Set("Authorization", "Bearer "+testAdminAPIKey)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s status = %d body=%s", method, rec.Code, rec.Body.String())
		}
	}
	if s.existsCalls != 0 || s.bindCalls != 0 {
		t.Fatalf("unsupported method reached store: %+v", s)
	}
}
