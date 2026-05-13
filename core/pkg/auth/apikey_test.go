package auth_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/auth"
)

func TestAdminAPIKeyMiddleware_ValidKey(t *testing.T) {
	os.Setenv("HELM_ADMIN_API_KEY", "test-secret-key-32chars-minimum!")
	defer os.Unsetenv("HELM_ADMIN_API_KEY")

	var capturedPrincipal auth.Principal
	handler := auth.RequireAdminAuth(func(w http.ResponseWriter, r *http.Request) {
		p, err := auth.GetPrincipal(r.Context())
		if err != nil {
			t.Errorf("expected principal: %v", err)
		}
		capturedPrincipal = p
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("POST", "/api/v1/trust/keys/add", nil)
	req.Header.Set("Authorization", "Bearer test-secret-key-32chars-minimum!")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if capturedPrincipal == nil {
		t.Fatal("principal not set")
	}
	if capturedPrincipal.GetID() != "system-admin" {
		t.Errorf("expected 'system-admin', got %q", capturedPrincipal.GetID())
	}
	if !capturedPrincipal.HasPermission("anything") {
		t.Error("admin principal should have all permissions")
	}
}

func TestAdminAPIKeyMiddleware_InvalidKey(t *testing.T) {
	os.Setenv("HELM_ADMIN_API_KEY", "correct-key")
	defer os.Unsetenv("HELM_ADMIN_API_KEY")

	handler := auth.RequireAdminAuth(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called with invalid key")
	})

	req := httptest.NewRequest("POST", "/api/v1/trust/keys/add", nil)
	req.Header.Set("Authorization", "Bearer wrong-key")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestAdminAPIKeyMiddleware_MissingHeader(t *testing.T) {
	os.Setenv("HELM_ADMIN_API_KEY", "some-key")
	defer os.Unsetenv("HELM_ADMIN_API_KEY")

	handler := auth.RequireAdminAuth(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called without auth header")
	})

	req := httptest.NewRequest("POST", "/api/v1/trust/keys/add", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestAdminAPIKeyMiddleware_NoKeyConfigured_FailClosed(t *testing.T) {
	os.Unsetenv("HELM_ADMIN_API_KEY")

	handler := auth.RequireAdminAuth(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called when no key configured")
	})

	req := httptest.NewRequest("POST", "/api/v1/trust/keys/add", nil)
	req.Header.Set("Authorization", "Bearer any-value")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 (fail-closed), got %d", w.Code)
	}
}

func TestAdminAPIKeyMiddleware_MalformedAuthHeader(t *testing.T) {
	os.Setenv("HELM_ADMIN_API_KEY", "some-key")
	defer os.Unsetenv("HELM_ADMIN_API_KEY")

	handler := auth.RequireAdminAuth(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called with malformed header")
	})

	req := httptest.NewRequest("POST", "/api/v1/trust/keys/add", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestAdminAPIKeyMiddleware_TimingSafe(t *testing.T) {
	// Verify that keys of different lengths still return 401 (constant time compare)
	os.Setenv("HELM_ADMIN_API_KEY", "correct-key-with-specific-length")
	defer os.Unsetenv("HELM_ADMIN_API_KEY")

	handler := auth.RequireAdminAuth(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	})

	// Short key
	req := httptest.NewRequest("POST", "/test", nil)
	req.Header.Set("Authorization", "Bearer x")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("short key: expected 401, got %d", w.Code)
	}

	// Long key
	req = httptest.NewRequest("POST", "/test", nil)
	req.Header.Set("Authorization", "Bearer xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("long key: expected 401, got %d", w.Code)
	}
}
