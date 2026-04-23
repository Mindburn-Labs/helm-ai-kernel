package oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// TokenRefresher manages token lifecycle including refresh when nearing expiry.
type TokenRefresher struct {
	ClientID      string
	ClientSecret  string
	TokenEndpoint string
	Store         TokenStore
	HTTPClient    *http.Client
}

// EnsureValid retrieves the token for the given connector and ensures it is usable.
// If the token is expired or about to expire, it attempts a refresh.
func (r *TokenRefresher) EnsureValid(ctx context.Context, connectorID string) (*Token, error) {
	token, err := r.Store.GetToken(ctx, connectorID)
	if err != nil {
		return nil, fmt.Errorf("oauth2: get token: %w", err)
	}
	if token == nil {
		return nil, fmt.Errorf("oauth2: no token stored for connector %q", connectorID)
	}

	// Token is still valid and not near expiry.
	if !token.NeedsRefresh() {
		return token, nil
	}

	// Token needs refresh.
	if token.RefreshToken == "" {
		return nil, fmt.Errorf("oauth2: token for connector %q is expired and no refresh token available", connectorID)
	}

	refreshed, err := r.refresh(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("oauth2: refresh token for connector %q: %w", connectorID, err)
	}
	if err := r.Store.SaveToken(ctx, connectorID, refreshed); err != nil {
		return nil, fmt.Errorf("oauth2: save refreshed token: %w", err)
	}
	return refreshed, nil
}

func (r *TokenRefresher) refresh(ctx context.Context, old *Token) (*Token, error) {
	if r.TokenEndpoint == "" {
		return nil, fmt.Errorf("token endpoint is required")
	}

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", old.RefreshToken)
	if r.ClientID != "" {
		form.Set("client_id", r.ClientID)
	}
	if r.ClientSecret != "" {
		form.Set("client_secret", r.ClientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	client := r.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var raw struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int64  `json:"expires_in"`
		Scope        string `json:"scope"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	if raw.AccessToken == "" {
		return nil, fmt.Errorf("response missing access_token")
	}

	tokenType := raw.TokenType
	if tokenType == "" {
		tokenType = old.TokenType
	}
	if tokenType == "" {
		tokenType = "Bearer"
	}
	refreshToken := raw.RefreshToken
	if refreshToken == "" {
		refreshToken = old.RefreshToken
	}
	expiresIn := raw.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = int64(time.Hour / time.Second)
	}

	return &Token{
		AccessToken:  raw.AccessToken,
		RefreshToken: refreshToken,
		TokenType:    tokenType,
		ExpiresAt:    time.Now().Add(time.Duration(expiresIn) * time.Second),
		Scopes:       parseScope(raw.Scope, old.Scopes),
	}, nil
}

func parseScope(scope string, fallback []string) []string {
	if strings.TrimSpace(scope) == "" {
		out := make([]string, len(fallback))
		copy(out, fallback)
		return out
	}
	fields := strings.Fields(scope)
	out := make([]string, len(fields))
	copy(out, fields)
	return out
}
