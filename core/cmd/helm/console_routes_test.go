package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestConsoleReservedPathsDoNotFallThroughToSPA(t *testing.T) {
	reserved := []string{
		"/api/v1/unknown",
		"/v1/chat/completions",
		"/mcp",
		"/mcp/v1/capabilities",
		"/.well-known/oauth-protected-resource/mcp",
		"/healthz",
		"/version",
	}
	for _, path := range reserved {
		if !isReservedConsolePath(path) {
			t.Fatalf("%s should be reserved", path)
		}
	}
}

func TestConsoleApplicationRoutesFallThroughToSPA(t *testing.T) {
	appRoutes := []string{"/", "/command", "/receipts/rcpt_123", "/settings"}
	for _, path := range appRoutes {
		if isReservedConsolePath(path) {
			t.Fatalf("%s should be handled by console SPA", path)
		}
	}
}

func TestConsoleBootstrapRequiresCredentials(t *testing.T) {
	t.Setenv("HELM_ADMIN_API_KEY", "")
	mux := http.NewServeMux()
	RegisterConsoleRoutes(mux, &Services{}, serverOptions{Mode: "serve"})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/console/bootstrap", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("console bootstrap without credentials status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestConsoleBootstrapAllowsAdminCredentials(t *testing.T) {
	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
	mux := http.NewServeMux()
	RegisterConsoleRoutes(mux, &Services{}, serverOptions{Mode: "serve"})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/console/bootstrap", nil)
	authorizeTestRequest(req)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("console bootstrap with credentials status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestConsoleReplaySurfaceUsesVerifierContract(t *testing.T) {
	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
	mux := http.NewServeMux()
	RegisterConsoleRoutes(mux, &Services{}, serverOptions{Mode: "serve"})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/console/surfaces/replay", nil)
	authorizeTestRequest(req)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("console replay surface status = %d body=%s", rec.Code, rec.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode replay surface: %v", err)
	}
	if payload["source"] != "/api/v1/replay/verify" {
		t.Fatalf("replay surface source = %v", payload["source"])
	}
}
