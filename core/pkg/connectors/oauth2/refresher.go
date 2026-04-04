package oauth2

import (
	"context"
	"fmt"
)

// TokenRefresher manages token lifecycle including refresh when nearing expiry.
type TokenRefresher struct {
	ClientID      string
	ClientSecret  string
	TokenEndpoint string
	Store         TokenStore
}

// EnsureValid retrieves the token for the given connector and ensures it is usable.
// If the token is expired or about to expire, it attempts a refresh.
// Currently, actual HTTP refresh is stubbed: if the token needs refresh and no
// refresh token is available, an error is returned.
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

	// Stub: In production, this would POST to r.TokenEndpoint with the refresh token
	// and client credentials to obtain a new access token. For now, we return an error
	// indicating the token has expired since we cannot perform real OAuth2 refresh
	// without live credentials and endpoints.
	return nil, fmt.Errorf("oauth2: token for connector %q needs refresh (stub: real HTTP refresh not implemented)", connectorID)
}
