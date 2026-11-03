package identity

import (
	"context"
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

type jwksDocument struct {
	Keys []jwkKey `json:"keys"`
}

type jwkKey struct {
	Kty string `json:"kty"`
	Use string `json:"use,omitempty"`
	Kid string `json:"kid,omitempty"`
	Alg string `json:"alg,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

type jwkVerifierKey struct {
	key any
	kid string
	alg string
}
