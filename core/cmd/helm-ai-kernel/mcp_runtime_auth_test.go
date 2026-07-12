package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	mcppkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWrapMCPAuth_OAuthBypassesProtectedResourceMetadata(t *testing.T) {
	t.Setenv("HELM_OAUTH_BEARER_TOKEN", "testtoken")

	called := false
	handler, err := wrapMCPAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}), "oauth", "http://localhost:9194")
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource/mcp", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.True(t, called)
	assert.Equal(t, http.StatusNoContent, rec.Code)
}

func TestWrapMCPAuth_OAuthChallengesWithoutBearer(t *testing.T) {
	t.Setenv("HELM_OAUTH_BEARER_TOKEN", "testtoken")

	handler, err := wrapMCPAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), "oauth", "http://localhost:9194")
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), "resource_metadata=\"http://localhost:9194/.well-known/oauth-protected-resource/mcp\"")
}

func TestWrapMCPAuth_OAuthAllowsValidBearer(t *testing.T) {
	t.Setenv("HELM_OAUTH_BEARER_TOKEN", "testtoken")
	t.Setenv("HELM_OAUTH_SCOPES", "mcp:tool:read,mcp:tool:write")

	called := false
	handler, err := wrapMCPAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		auth, ok := mcppkg.OAuthAuthorizationFromContext(r.Context())
		require.True(t, ok)
		assert.Equal(t, []string{"mcp:tool:read", "mcp:tool:write"}, auth.Scopes)
		assert.Equal(t, []string{"http://localhost:9194/mcp"}, auth.Resources)
		w.WriteHeader(http.StatusNoContent)
	}), "oauth", "http://localhost:9194")
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer testtoken")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.True(t, called)
	assert.Equal(t, http.StatusNoContent, rec.Code)
}

func TestHostedMeteredMCPRefusesUnauthenticatedHTTPTransport(t *testing.T) {
	t.Setenv("HELM_METERING_URL", "http://metering.example")
	t.Setenv("HELM_METERING_SERVICE_TOKEN", "service-token")
	t.Setenv("HELM_METERING_ACTIVATE", "1")

	_, err := newLocalMCPHTTPServer(0, "none")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires an authenticated HTTP transport")
}

func TestHostedMeteredMCPRefusesLocalRuntimeWithoutDecisionReceiptProvider(t *testing.T) {
	t.Setenv("HELM_METERING_URL", "http://metering.example")
	t.Setenv("HELM_METERING_SERVICE_TOKEN", "service-token")
	t.Setenv("HELM_METERING_ACTIVATE", "1")
	t.Setenv("HELM_API_KEY", "test-key")

	_, err := newLocalMCPHTTPServer(0, "static-header")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "trusted pre-dispatch decision receipt provider")
}
