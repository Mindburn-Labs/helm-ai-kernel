package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBasePrincipalGetID(t *testing.T) {
	p := &BasePrincipal{ID: "u-1", TenantID: "t-1", Roles: []string{"admin"}}
	assert.Equal(t, "u-1", p.GetID())
}

func TestBasePrincipalGetTenantID(t *testing.T) {
	p := &BasePrincipal{TenantID: "t-42"}
	assert.Equal(t, "t-42", p.GetTenantID())
}

func TestBasePrincipalAdminHasPermission(t *testing.T) {
	p := &BasePrincipal{Roles: []string{"admin"}}
	assert.True(t, p.HasPermission("anything"))
}

func TestBasePrincipalNonAdminNoPermission(t *testing.T) {
	p := &BasePrincipal{Roles: []string{"viewer"}}
	assert.False(t, p.HasPermission("write"))
}

func TestWithPrincipalAndGetPrincipal(t *testing.T) {
	ctx := WithPrincipal(context.Background(), &BasePrincipal{ID: "p-1"})
	p, err := GetPrincipal(ctx)
	require.NoError(t, err)
	assert.Equal(t, "p-1", p.GetID())
}

func TestGetPrincipalFromEmptyContext(t *testing.T) {
	_, err := GetPrincipal(context.Background())
	assert.Error(t, err)
}

func TestGetTenantIDFromContext(t *testing.T) {
	ctx := WithPrincipal(context.Background(), &BasePrincipal{TenantID: "t-5"})
	tid, err := GetTenantID(ctx)
	require.NoError(t, err)
	assert.Equal(t, "t-5", tid)
}

func TestGetTenantIDMissingPrincipal(t *testing.T) {
	_, err := GetTenantID(context.Background())
	assert.Error(t, err)
}

func TestMustGetTenantIDPanicsOnMissing(t *testing.T) {
	assert.Panics(t, func() { MustGetTenantID(context.Background()) })
}

func TestIsPublicPathHealth(t *testing.T) {
	assert.True(t, isPublicPath("/health"))
	assert.True(t, isPublicPath("/healthz"))
	assert.True(t, isPublicPath("/version"))
}

func TestIsPublicPathStaticPrefix(t *testing.T) {
	assert.True(t, isPublicPath("/static/app.js"))
}

func TestIsPublicPathProtectedEndpoint(t *testing.T) {
	assert.False(t, isPublicPath("/api/v1/admin"))
}

func TestSecurityHeadersSet(t *testing.T) {
	handler := SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	assert.Equal(t, "nosniff", rr.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "DENY", rr.Header().Get("X-Frame-Options"))
}

func TestRequestIDMiddlewareGeneratesID(t *testing.T) {
	handler := RequestIDMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rid := GetRequestID(r.Context())
		assert.NotEmpty(t, rid)
	}))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	assert.NotEmpty(t, rr.Header().Get("X-Request-ID"))
}

func TestRequestIDMiddlewareReusesClientID(t *testing.T) {
	handler := RequestIDMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Request-ID", "client-123")
	handler.ServeHTTP(rr, req)
	assert.Equal(t, "client-123", rr.Header().Get("X-Request-ID"))
}

func TestGetRequestIDEmptyContext(t *testing.T) {
	assert.Equal(t, "", GetRequestID(context.Background()))
}

func TestCORSMiddlewareAllowedOrigin(t *testing.T) {
	handler := CORSMiddleware([]string{"https://app.example.com"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Origin", "https://app.example.com")
	handler.ServeHTTP(rr, req)
	assert.Equal(t, "https://app.example.com", rr.Header().Get("Access-Control-Allow-Origin"))
}

func TestCORSMiddlewareDisallowedOrigin(t *testing.T) {
	handler := CORSMiddleware([]string{"https://allowed.com"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Origin", "https://evil.com")
	handler.ServeHTTP(rr, req)
	assert.Empty(t, rr.Header().Get("Access-Control-Allow-Origin"))
}

func TestCORSMiddlewareDefaultDeniesOrigin(t *testing.T) {
	t.Setenv("CORS_ORIGINS", "")
	handler := CORSMiddleware(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Origin", "https://any.com")
	handler.ServeHTTP(rr, req)
	assert.Empty(t, rr.Header().Get("Access-Control-Allow-Origin"))
	assert.Contains(t, rr.Header().Get("Access-Control-Allow-Headers"), "X-Helm-Tenant-ID")
}

func TestCORSMiddlewarePreflightReturns204(t *testing.T) {
	handler := CORSMiddleware(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("OPTIONS", "/", nil)
	req.Header.Set("Origin", "https://any.com")
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNoContent, rr.Code)
}

func TestIsOriginAllowedWildcard(t *testing.T) {
	assert.True(t, isOriginAllowed("https://any.com", []string{"*"}))
}
