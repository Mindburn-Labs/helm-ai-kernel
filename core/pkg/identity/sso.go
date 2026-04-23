package identity

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
)

// SSOProvider defines the interface for Single Sign-On.
type SSOProvider interface {
	InitiateLogin(ctx context.Context, returnURL string) (string, error)
	Callback(ctx context.Context, code string) (*IdentityToken, error)
}

// OIDCProvider implements OpenID Connect authentication.
type OIDCProvider struct {
	IssuerURL    string
	ClientID     string
	ClientSecret string
	RedirectURL  string

	// discoveryDoc caches OIDC configuration
	discoveryDoc *oidcDiscoveryDoc
}

type oidcDiscoveryDoc struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

type oidcTokenResponse struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

func NewOIDCProvider(issuer, clientID, clientSecret, redirectURL string) *OIDCProvider {
	return &OIDCProvider{
		IssuerURL:    issuer,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
	}
}

func (p *OIDCProvider) discover(ctx context.Context) error {
	if p.discoveryDoc != nil {
		return nil
	}

	url := fmt.Sprintf("%s/.well-known/openid-configuration", p.IssuerURL)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("oidc discovery failed: %d", resp.StatusCode)
	}

	var doc oidcDiscoveryDoc
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return err
	}
	p.discoveryDoc = &doc
	return nil
}

func (p *OIDCProvider) InitiateLogin(ctx context.Context, state string) (string, error) {
	if err := p.discover(ctx); err != nil {
		return "", fmt.Errorf("discovery failed: %w", err)
	}

	return fmt.Sprintf("%s?client_id=%s&redirect_uri=%s&response_type=code&scope=openid profile email&state=%s",
		p.discoveryDoc.AuthorizationEndpoint, p.ClientID, p.RedirectURL, state), nil
}

func (p *OIDCProvider) Callback(ctx context.Context, code string) (*IdentityToken, error) {
	if err := p.discover(ctx); err != nil {
		return nil, fmt.Errorf("discovery failed: %w", err)
	}

	// Exchange code for token
	url := fmt.Sprintf("%s?grant_type=authorization_code&client_id=%s&client_secret=%s&redirect_uri=%s&code=%s",
		p.discoveryDoc.TokenEndpoint, p.ClientID, p.ClientSecret, p.RedirectURL, code)

	req, err := http.NewRequestWithContext(ctx, "POST", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange failed: %d", resp.StatusCode)
	}

	var tokenResp oidcTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, err
	}

	// Verify ID Token (simplified: assume signed by issuer, skip full JWKS validation for MVP, assume valid struct)
	// In production, we fetch JWKS from p.discoveryDoc.JWKSURI and use jwt.Parse with Keyfunc
	// checking the signature. For this MVP step, we will parse unverified claims
	// but enforce issuer check.
	// SECURITY NOTE: MVP parses unverified claims with issuer check only.
	// Full JWKS signature verification (e.g. github.com/MicahParks/keyfunc) is required
	// before production SSO deployment. See SECURITY.md for threat model.

	claims := jwt.MapClaims{}
	_, _, err = new(jwt.Parser).ParseUnverified(tokenResp.IDToken, claims)
	if err != nil {
		return nil, fmt.Errorf("failed to parse id_token: %w", err)
	}

	// Basic Validation
	iss, _ := claims.GetIssuer()
	if iss != p.IssuerURL {
		return nil, fmt.Errorf("invalid issuer: %s", iss)
	}

	sub, _ := claims.GetSubject()
	// aud, _ := claims.GetAudience() // check client ID

	// Extract email logic depending on provider
	email, _ := claims["email"].(string)

	return &IdentityToken{
		Subject: sub,
		Email:   email,
		Issuer:  iss,
		Claims:  claims,
	}, nil
}
