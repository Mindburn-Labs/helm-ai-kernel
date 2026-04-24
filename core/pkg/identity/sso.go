package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"

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

	authURL, err := url.Parse(p.discoveryDoc.AuthorizationEndpoint)
	if err != nil {
		return "", fmt.Errorf("invalid authorization endpoint: %w", err)
	}

	query := authURL.Query()
	query.Set("client_id", p.ClientID)
	query.Set("redirect_uri", p.RedirectURL)
	query.Set("response_type", "code")
	query.Set("scope", "openid profile email")
	query.Set("state", state)
	authURL.RawQuery = query.Encode()

	return authURL.String(), nil
}

func (p *OIDCProvider) Callback(ctx context.Context, code string) (*IdentityToken, error) {
	if err := p.discover(ctx); err != nil {
		return nil, fmt.Errorf("discovery failed: %w", err)
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", p.ClientID)
	form.Set("client_secret", p.ClientSecret)
	form.Set("redirect_uri", p.RedirectURL)
	form.Set("code", code)

	req, err := http.NewRequestWithContext(ctx, "POST", p.discoveryDoc.TokenEndpoint, strings.NewReader(form.Encode()))
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

	claims := jwt.MapClaims{}
	keyFunc, err := p.jwksKeyFunc(ctx)
	if err != nil {
		return nil, err
	}

	token, err := jwt.ParseWithClaims(
		tokenResp.IDToken,
		claims,
		keyFunc,
		jwt.WithIssuer(p.IssuerURL),
		jwt.WithAudience(p.ClientID),
	)
	if err != nil {
		return nil, fmt.Errorf("invalid id_token: %w", err)
	}
	if !token.Valid {
		return nil, jwt.ErrTokenInvalidClaims
	}

	iss, _ := claims.GetIssuer()
	sub, _ := claims.GetSubject()
	email, _ := claims["email"].(string)

	return &IdentityToken{
		Subject: sub,
		Email:   email,
		Issuer:  iss,
		Claims:  claims,
	}, nil
}

func (p *OIDCProvider) jwksKeyFunc(ctx context.Context) (jwt.Keyfunc, error) {
	if p.discoveryDoc == nil || p.discoveryDoc.JWKSURI == "" {
		return nil, fmt.Errorf("oidc discovery did not provide jwks_uri")
	}

	req, err := http.NewRequestWithContext(ctx, "GET", p.discoveryDoc.JWKSURI, nil)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks fetch failed: %d", resp.StatusCode)
	}

	var doc jwksDocument
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, err
	}

	keys := make([]jwkVerifierKey, 0, len(doc.Keys))
	for _, jwk := range doc.Keys {
		if jwk.Use != "" && jwk.Use != "sig" {
			continue
		}

		key, err := jwkPublicKey(jwk)
		if err != nil {
			return nil, fmt.Errorf("invalid jwk %q: %w", jwk.Kid, err)
		}
		keys = append(keys, jwkVerifierKey{key: key, kid: jwk.Kid, alg: jwk.Alg})
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("jwks contains no signing keys")
	}

	return func(token *jwt.Token) (any, error) {
		kid, _ := token.Header["kid"].(string)
		if kid == "" && len(keys) > 1 {
			return nil, fmt.Errorf("id_token header missing kid")
		}

		for _, candidate := range keys {
			if kid != "" && candidate.kid != kid {
				continue
			}
			if candidate.alg != "" && candidate.alg != token.Method.Alg() {
				continue
			}
			if !signingMethodMatchesKey(token.Method, candidate.key) {
				continue
			}
			return candidate.key, nil
		}

		if kid != "" {
			return nil, fmt.Errorf("no jwk matches kid %q", kid)
		}
		return nil, fmt.Errorf("no jwk matches token signing method %s", token.Method.Alg())
	}, nil
}

func jwkPublicKey(jwk jwkKey) (any, error) {
	switch jwk.Kty {
	case "RSA":
		return rsaPublicKeyFromJWK(jwk)
	case "EC":
		return ecdsaPublicKeyFromJWK(jwk)
	case "OKP":
		return ed25519PublicKeyFromJWK(jwk)
	default:
		return nil, fmt.Errorf("unsupported key type %q", jwk.Kty)
	}
}

func rsaPublicKeyFromJWK(jwk jwkKey) (*rsa.PublicKey, error) {
	modulus, err := decodeJWKField(jwk.N, "n")
	if err != nil {
		return nil, err
	}
	exponent, err := decodeJWKField(jwk.E, "e")
	if err != nil {
		return nil, err
	}

	e := new(big.Int).SetBytes(exponent)
	if !e.IsInt64() {
		return nil, fmt.Errorf("rsa exponent is too large")
	}

	exp := int(e.Int64())
	if exp < 3 || exp%2 == 0 {
		return nil, fmt.Errorf("rsa exponent is invalid")
	}

	return &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: exp}, nil
}

func ecdsaPublicKeyFromJWK(jwk jwkKey) (*ecdsa.PublicKey, error) {
	curve, err := ellipticCurve(jwk.Crv)
	if err != nil {
		return nil, err
	}
	xBytes, err := decodeJWKField(jwk.X, "x")
	if err != nil {
		return nil, err
	}
	yBytes, err := decodeJWKField(jwk.Y, "y")
	if err != nil {
		return nil, err
	}

	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)
	if !curve.IsOnCurve(x, y) {
		return nil, fmt.Errorf("ec point is not on curve %s", jwk.Crv)
	}

	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

func ed25519PublicKeyFromJWK(jwk jwkKey) (ed25519.PublicKey, error) {
	if jwk.Crv != "Ed25519" {
		return nil, fmt.Errorf("unsupported okp curve %q", jwk.Crv)
	}
	xBytes, err := decodeJWKField(jwk.X, "x")
	if err != nil {
		return nil, err
	}
	if len(xBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("ed25519 public key has invalid length")
	}
	return ed25519.PublicKey(xBytes), nil
}

func ellipticCurve(crv string) (elliptic.Curve, error) {
	switch crv {
	case "P-256":
		return elliptic.P256(), nil
	case "P-384":
		return elliptic.P384(), nil
	case "P-521":
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("unsupported ec curve %q", crv)
	}
}

func decodeJWKField(value, name string) ([]byte, error) {
	if value == "" {
		return nil, fmt.Errorf("missing %s", name)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err == nil {
		return decoded, nil
	}
	decoded, paddedErr := base64.URLEncoding.DecodeString(value)
	if paddedErr == nil {
		return decoded, nil
	}
	return nil, err
}

func signingMethodMatchesKey(method jwt.SigningMethod, key any) bool {
	switch key.(type) {
	case *rsa.PublicKey:
		if _, ok := method.(*jwt.SigningMethodRSA); ok {
			return true
		}
		_, ok := method.(*jwt.SigningMethodRSAPSS)
		return ok
	case *ecdsa.PublicKey:
		_, ok := method.(*jwt.SigningMethodECDSA)
		return ok
	case ed25519.PublicKey:
		_, ok := method.(*jwt.SigningMethodEd25519)
		return ok
	default:
		return false
	}
}
