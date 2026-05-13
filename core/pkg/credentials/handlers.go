// Package credentials - HTTP handlers for credential management API
package credentials

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/api"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/auth"
	"github.com/google/uuid"
)

// Handler provides HTTP handlers for credential management.
type Handler struct {
	store       *Store
	googleOAuth *GoogleOAuth
}

// NewHandler creates a new credential handler.
func NewHandler(store *Store) *Handler {
	return &Handler{
		store:       store,
		googleOAuth: NewGoogleOAuth("", ""),
	}
}

// RegisterRoutes registers credential API routes on the given mux.
// All credential routes require authentication (H-1: no more spoofable X-Operator-ID).
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	adminAuth := auth.AdminAPIKeyMiddleware()
	wrap := func(handler http.HandlerFunc) http.Handler {
		return adminAuth(handler)
	}

	mux.Handle("GET /api/v1/credentials/status", wrap(h.handleStatus))
	mux.Handle("GET /api/v1/credentials/config", wrap(h.handleConfig))
	mux.Handle("POST /api/v1/credentials/google/token", wrap(h.handleGoogleToken))
	mux.Handle("POST /api/v1/credentials/google/refresh", wrap(h.handleGoogleRefresh))
	mux.Handle("DELETE /api/v1/credentials/google", wrap(h.handleDeleteGoogle))
	mux.Handle("POST /api/v1/credentials/openai", wrap(h.handleStoreOpenAI))
	mux.Handle("DELETE /api/v1/credentials/openai", wrap(h.handleDeleteOpenAI))
	mux.Handle("POST /api/v1/credentials/anthropic", wrap(h.handleStoreAnthropic))
	mux.Handle("DELETE /api/v1/credentials/anthropic", wrap(h.handleDeleteAnthropic))
}

// getOperatorID extracts operator ID from the authenticated principal in context.
// Falls back to "default-operator" only if no principal is set (should not happen
// when auth middleware is wired correctly — this fallback exists for graceful
// degradation during development only).
func getOperatorID(r *http.Request) string {
	// Primary: extract from authenticated principal (set by JWT or API key middleware)
	if principal, err := auth.GetPrincipal(r.Context()); err == nil {
		return principal.GetID()
	}
	// Fallback for development/testing only — never reachable when middleware is active
	return "default-operator"
}

// handleStatus returns credential connection status for all providers.
func (h *Handler) handleStatus(w http.ResponseWriter, r *http.Request) {
	operatorID := getOperatorID(r)

	statuses, err := h.store.GetStatus(r.Context(), operatorID)
	if err != nil {
		api.WriteInternal(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(statuses)
}

// handleConfig returns OAuth configuration (client IDs, not secrets).
func (h *Handler) handleConfig(w http.ResponseWriter, r *http.Request) {
	config := map[string]string{
		"googleClientId": h.googleOAuth.ClientID,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(config)
}

// TokenExchangeRequest represents the OAuth code exchange request.
type TokenExchangeRequest struct {
	Code         string `json:"code"`
	CodeVerifier string `json:"codeVerifier"`
	RedirectURI  string `json:"redirectUri"`
}

// handleGoogleToken exchanges OAuth code for tokens.
func (h *Handler) handleGoogleToken(w http.ResponseWriter, r *http.Request) {
	var req TokenExchangeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.WriteBadRequest(w, "Invalid request body")
		return
	}

	// Exchange code for tokens
	tokenResp, err := h.googleOAuth.ExchangeCode(r.Context(), req.Code, req.CodeVerifier, req.RedirectURI)
	if err != nil {
		slog.Warn("credentials: google token exchange failed", "error", err)
		api.WriteBadRequest(w, "Token exchange failed")
		return
	}

	// Get user info
	userInfo, err := h.googleOAuth.GetUserInfo(r.Context(), tokenResp.AccessToken)
	if err != nil {
		slog.Warn("credentials: failed to get user info", "error", err)
		// Continue without email
	}

	// Store credential
	operatorID := getOperatorID(r)
	expiresAt := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)

	cred := &Credential{
		ID:           uuid.New().String(),
		OperatorID:   operatorID,
		Provider:     ProviderGoogle,
		TokenType:    TokenTypeBearer,
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		ExpiresAt:    &expiresAt,
	}

	if userInfo != nil {
		cred.Email = userInfo.Email
	}

	if err := h.store.SaveCredential(r.Context(), cred); err != nil {
		slog.Error("credentials: failed to save credential", "error", err)
		api.WriteInternal(w, err)
		return
	}

	// Return token info (frontend needs this for immediate use)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"access_token": tokenResp.AccessToken,
		"expires_in":   tokenResp.ExpiresIn,
		"scope":        tokenResp.Scope,
	})
}

// RefreshRequest represents a token refresh request.
type RefreshRequest struct {
	RefreshToken string `json:"refreshToken"`
}

// handleGoogleRefresh refreshes a Google access token.
func (h *Handler) handleGoogleRefresh(w http.ResponseWriter, r *http.Request) {
	operatorID := getOperatorID(r)

	// Get existing credential
	cred, err := h.store.GetCredential(r.Context(), operatorID, ProviderGoogle)
	if err != nil || cred == nil {
		api.WriteNotFound(w, "No credential found")
		return
	}

	// Refresh token
	tokenResp, err := h.googleOAuth.RefreshToken(r.Context(), cred.RefreshToken)
	if err != nil {
		slog.Warn("credentials: token refresh failed", "error", err)
		api.WriteBadRequest(w, "Token refresh failed")
		return
	}

	// Update credential
	expiresAt := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	cred.AccessToken = tokenResp.AccessToken
	cred.ExpiresAt = &expiresAt
	if tokenResp.RefreshToken != "" {
		cred.RefreshToken = tokenResp.RefreshToken
	}

	if err := h.store.SaveCredential(r.Context(), cred); err != nil {
		slog.Error("credentials: failed to update credential", "error", err)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"access_token": tokenResp.AccessToken,
		"expires_in":   tokenResp.ExpiresIn,
	})
}

// handleDeleteGoogle removes Google credentials.
func (h *Handler) handleDeleteGoogle(w http.ResponseWriter, r *http.Request) {
	operatorID := getOperatorID(r)

	// Revoke with Google first
	cred, _ := h.store.GetCredential(r.Context(), operatorID, ProviderGoogle)
	if cred != nil && cred.AccessToken != "" {
		_ = h.googleOAuth.RevokeToken(r.Context(), cred.AccessToken)
	}

	if err := h.store.DeleteCredential(r.Context(), operatorID, ProviderGoogle); err != nil {
		api.WriteInternal(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// APIKeyRequest represents an API key storage request.
type APIKeyRequest struct {
	APIKey string `json:"apiKey"`
}

// handleStoreOpenAI stores an OpenAI API key.
func (h *Handler) handleStoreOpenAI(w http.ResponseWriter, r *http.Request) {
	var req APIKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.WriteBadRequest(w, "Invalid request body")
		return
	}

	operatorID := getOperatorID(r)
	cred := &Credential{
		ID:          uuid.New().String(),
		OperatorID:  operatorID,
		Provider:    ProviderOpenAI,
		TokenType:   TokenTypeApiKey,
		AccessToken: req.APIKey,
	}

	if err := h.store.SaveCredential(r.Context(), cred); err != nil {
		api.WriteInternal(w, err)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

// handleDeleteOpenAI removes OpenAI credentials.
func (h *Handler) handleDeleteOpenAI(w http.ResponseWriter, r *http.Request) {
	operatorID := getOperatorID(r)

	if err := h.store.DeleteCredential(r.Context(), operatorID, ProviderOpenAI); err != nil {
		api.WriteInternal(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleStoreAnthropic stores an Anthropic API key.
func (h *Handler) handleStoreAnthropic(w http.ResponseWriter, r *http.Request) {
	var req APIKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.WriteBadRequest(w, "Invalid request body")
		return
	}

	operatorID := getOperatorID(r)
	cred := &Credential{
		ID:          uuid.New().String(),
		OperatorID:  operatorID,
		Provider:    ProviderAnthropic,
		TokenType:   TokenTypeApiKey,
		AccessToken: req.APIKey,
	}

	if err := h.store.SaveCredential(r.Context(), cred); err != nil {
		api.WriteInternal(w, err)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

// handleDeleteAnthropic removes Anthropic credentials.
func (h *Handler) handleDeleteAnthropic(w http.ResponseWriter, r *http.Request) {
	operatorID := getOperatorID(r)

	if err := h.store.DeleteCredential(r.Context(), operatorID, ProviderAnthropic); err != nil {
		api.WriteInternal(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
