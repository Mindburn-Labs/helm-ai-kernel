package auth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/auth"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/identity"
)

// createTestToken generates a signed JWT for testing using the provided KeySet.
func createTestToken(t *testing.T, ks identity.KeySet, sub, tenantID string, roles []string, expiry time.Time) string {
	t.Helper()
	claims := auth.HelmClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   sub,
			ExpiresAt: jwt.NewNumericDate(expiry),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "helm-test",
		},
		TenantID: tenantID,
		Roles:    roles,
	}
	token, err := ks.Sign(context.Background(), claims)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}
	return token
}

func setupValidator(t *testing.T) (identity.KeySet, *auth.JWTValidator) {
	ks, err := identity.NewInMemoryKeySet()
	if err != nil {
		t.Fatalf("failed to create keyset: %v", err)
	}
	return ks, auth.NewJWTValidator(ks)
}

func TestMiddleware_ValidJWT(t *testing.T) {
	ks, validator := setupValidator(t)
	middleware := auth.NewMiddleware(validator)

	var capturedPrincipal auth.Principal
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, err := auth.GetPrincipal(r.Context())
		if err != nil {
			t.Errorf("expected principal in context: %v", err)
		}
		capturedPrincipal = p
		w.WriteHeader(http.StatusOK)
	}))

	token := createTestToken(t, ks, "user-123", "tenant-abc", []string{"admin"}, time.Now().Add(1*time.Hour))

	req := httptest.NewRequest("GET", "/api/v1/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if capturedPrincipal == nil {
		t.Fatal("principal was not set in context")
	}
	if capturedPrincipal.GetID() != "user-123" {
		t.Errorf("expected subject 'user-123', got %q", capturedPrincipal.GetID())
	}
	if capturedPrincipal.GetTenantID() != "tenant-abc" {
		t.Errorf("expected tenant 'tenant-abc', got %q", capturedPrincipal.GetTenantID())
	}
}

func TestMiddleware_ExpiredJWT(t *testing.T) {
	ks, validator := setupValidator(t)
	middleware := auth.NewMiddleware(validator)

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called for expired token")
	}))

	token := createTestToken(t, ks, "user-123", "tenant-abc", []string{"admin"}, time.Now().Add(-1*time.Hour))

	req := httptest.NewRequest("GET", "/api/v1/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestMiddleware_MissingHeader(t *testing.T) {
	_, validator := setupValidator(t)
	middleware := auth.NewMiddleware(validator)

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called without auth header")
	}))

	req := httptest.NewRequest("GET", "/api/v1/test", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestMiddleware_InvalidSignature(t *testing.T) {
	// Create token with one KeySet, validate with another
	ks1, _ := setupValidator(t)
	_, validator2 := setupValidator(t) // Different keys

	middleware := auth.NewMiddleware(validator2)

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called for invalid signature")
	}))

	token := createTestToken(t, ks1, "user-123", "tenant-abc", []string{"admin"}, time.Now().Add(1*time.Hour))

	req := httptest.NewRequest("GET", "/api/v1/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestMiddleware_PublicPathsBypass(t *testing.T) {
	_, validator := setupValidator(t)
	middleware := auth.NewMiddleware(validator)

	called := false
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if !called {
		t.Error("handler should be called for public paths without auth")
	}
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestMiddleware_NilValidator_FailClosed(t *testing.T) {
	middleware := auth.NewMiddleware(nil)

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called when validator is nil")
	}))

	req := httptest.NewRequest("GET", "/api/v1/test", nil)
	req.Header.Set("Authorization", "Bearer some-token")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestMiddleware_MissingTenantClaim(t *testing.T) {
	ks, validator := setupValidator(t)
	middleware := auth.NewMiddleware(validator)

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called for missing tenant claim")
	}))

	token := createTestToken(t, ks, "user-123", "", []string{"admin"}, time.Now().Add(1*time.Hour))
	req := httptest.NewRequest("GET", "/api/v1/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestMiddleware_MissingSubjectClaim(t *testing.T) {
	ks, validator := setupValidator(t)
	middleware := auth.NewMiddleware(validator)

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called for missing subject claim")
	}))

	token := createTestToken(t, ks, "", "tenant-abc", []string{"admin"}, time.Now().Add(1*time.Hour))
	req := httptest.NewRequest("GET", "/api/v1/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestLegacyMiddleware_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic from legacy auth.Middleware")
		}
	}()

	_ = auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
}

func TestGetRequestID_ExtractsFromContext(t *testing.T) {
	var got string
	handler := auth.RequestIDMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = auth.GetRequestID(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/v1/test", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if got == "" {
		t.Fatal("expected non-empty request id from context")
	}
	if w.Header().Get("X-Request-ID") == "" {
		t.Fatal("expected X-Request-ID header to be set")
	}
}
