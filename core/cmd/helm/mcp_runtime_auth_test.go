package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

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

	called := false
	handler, err := wrapMCPAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
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
