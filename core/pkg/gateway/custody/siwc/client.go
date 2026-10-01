// Package siwc keeps ChatGPT public-client credentials in the self-hosted
// gateway. It does not grant HELM authority or supply the product's IdP.
package siwc

// quantum_posture: OAuth PKCE uses SHA-256 and external ID tokens use RS256;
// neither mechanism claims post-quantum security.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

const (
	issuer           = "https://auth.openai.com"
	resource         = "https://api.openai.com/v1"
	dynamicClient    = "dynamic_agent_client"
	callbackPath     = "/auth/callback"
	requestedScope   = "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct"
	maxResponseBytes = 256 << 10
)

var (
	ErrAuthorization = errors.New("ChatGPT authorization failed; start a new sign-in")
	ErrIdentity      = errors.New("ChatGPT registration identity did not match")
	ErrPermission    = errors.New("ChatGPT plan permission is missing; reconnect with plan use enabled")
	ErrReauthorize   = errors.New("ChatGPT session needs a new sign-in")
	ErrUnavailable   = errors.New("ChatGPT authorization service is unavailable")
	ErrChanged       = errors.New("ChatGPT account changed during this operation; select it again")
)

// Client is the public OAuth client. Production endpoints are fixed; callers
// cannot redirect credentials to a configured provider URL or HTTP proxy.
type Client struct {
	http                                                  *http.Client
	now                                                   func() time.Time
	issuer, authorizeURL, tokenURL, jwksURL, discoveryURL string
}

func NewClient() *Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	return &Client{
		http: &http.Client{Transport: transport, Timeout: 20 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }},
		now: time.Now, issuer: issuer,
		authorizeURL: issuer + "/api/accounts/authorize", tokenURL: issuer + "/api/accounts/oauth/token",
		jwksURL: issuer + "/.well-known/jwks.json", discoveryURL: issuer + "/.well-known/openid-configuration",
	}
}

type pending struct {
	state, nonce, verifier, redirectURI, hostID string
	clientID                                    string
	previous                                    *record
}

func randomValue() (string, error) {
	var value [32]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value[:]), nil
}

func (c *Client) begin(hostID, redirect string, previous *record, registeredClient string) (*pending, string, error) {
	u, err := url.Parse(redirect)
	if err != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" || u.Port() == "" || u.Path != callbackPath || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return nil, "", ErrAuthorization
	}
	p := &pending{hostID: hostID, redirectURI: redirect, previous: previous}
	if registeredClient != "" && !validClientID(registeredClient) {
		return nil, "", ErrIdentity
	}
	p.clientID = registeredClient
	if previous != nil {
		p.clientID = previous.ClientID
	}
	if p.state, err = randomValue(); err != nil {
		return nil, "", err
	}
	if p.nonce, err = randomValue(); err != nil {
		return nil, "", err
	}
	if p.verifier, err = randomValue(); err != nil {
		return nil, "", err
	}
	challenge := sha256.Sum256([]byte(p.verifier))
	q := url.Values{"client_id": {dynamicClient}, "agent_name_hint": {"HELM AI OS"}, "ext_agent_host_id": {hostID},
		"response_type": {"code"}, "redirect_uri": {redirect}, "scope": {requestedScope}, "resource": {resource},
		"state": {p.state}, "nonce": {p.nonce}, "code_challenge_method": {"S256"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(challenge[:])}}
	if p.clientID != "" {
		q.Set("client_id", p.clientID)
		q.Del("agent_name_hint")
		// Hints are optional. Omitting id_token_hint keeps credentials out of
		// terminal/browser-launch diagnostics; identity is still checked below.
	}
	return p, c.authorizeURL + "?" + q.Encode(), nil
}

func (p *pending) matchesState(q url.Values) bool {
	return len(q["state"]) == 1 && subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(p.state)) == 1
}

func (p *pending) issuedClient(q url.Values) (string, error) {
	if !p.matchesState(q) || len(q["error"]) > 0 || len(q["code"]) != 1 || q.Get("code") == "" || len(q["client_id"]) > 1 {
		return "", ErrAuthorization
	}
	clientID := q.Get("client_id")
	if p.clientID != "" {
		if clientID != "" && clientID != p.clientID {
			return "", ErrIdentity
		}
		clientID = p.clientID
	}
	if !validClientID(clientID) {
		return "", ErrAuthorization
	}
	return clientID, nil
}

func (c *Client) complete(ctx context.Context, p *pending, q url.Values) (*record, error) {
	clientID, err := p.issuedClient(q)
	if err != nil {
		return nil, err
	}
	tokens, err := c.token(ctx, url.Values{"grant_type": {"authorization_code"}, "client_id": {clientID},
		"code": {q.Get("code")}, "code_verifier": {p.verifier}, "redirect_uri": {p.redirectURI}, "resource": {resource}})
	if err != nil {
		return nil, err
	}
	identity, err := c.identity(ctx, tokens.IDToken, clientID, p.nonce)
	if err != nil {
		return nil, err
	}
	if p.previous != nil && (identity.Subject != p.previous.Subject || identity.Issuer != p.previous.Issuer) {
		return nil, ErrIdentity
	}
	generation, err := randomValue()
	if err != nil {
		return nil, err
	}
	r := &record{Account: Account{ID: accountID(identity.Issuer, clientID, identity.Subject), Issuer: identity.Issuer,
		Subject: identity.Subject, ClientID: clientID, HostID: p.hostID, Generation: generation, Email: identity.Email}}
	r.replaceTokens(tokens, c.now())
	return r, nil
}

func validClientID(id string) bool {
	if !strings.HasPrefix(id, "oaiapp_") || len(id) < 8 || len(id) > 256 {
		return false
	}
	for _, ch := range id {
		if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '_' || ch == '-') {
			return false
		}
	}
	return true
}

func accountID(iss, clientID, subject string) string {
	digest := sha256.Sum256([]byte(iss + "\x00" + clientID + "\x00" + subject))
	return hex.EncodeToString(digest[:])
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	Scope        string `json:"scope"`
}

func (c *Client) token(ctx context.Context, form url.Values) (*tokenResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, ErrAuthorization
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var result tokenResponse
	if err := c.readJSON(req, &result); err != nil {
		var failure *oauthError
		if form.Get("grant_type") == "refresh_token" && errors.As(err, &failure) {
			switch failure.code {
			case "invalid_grant", "invalid_refresh_token", "token_expired", "refresh_token_expired", "refresh_token_invalidated", "refresh_token_reused":
				return nil, ErrReauthorize
			}
		}
		return nil, err
	}
	if !cleanToken(result.AccessToken) || result.TokenType != "Bearer" || result.ExpiresIn <= 0 || result.ExpiresIn > 3600 ||
		(result.RefreshToken != "" && !cleanToken(result.RefreshToken)) {
		return nil, ErrAuthorization
	}
	return &result, nil
}

func cleanToken(s string) bool {
	if len(s) == 0 || len(s) > 64<<10 {
		return false
	}
	for _, ch := range s {
		if ch < 0x21 || ch > 0x7e {
			return false
		}
	}
	return true
}

// Error descriptions and arbitrary provider response bodies can contain
// sensitive data. Keep only a machine code internally; never log the body.
type oauthError struct{ code string }

func (*oauthError) Error() string {
	return "ChatGPT OAuth request was rejected; check the client configuration or restart sign-in"
}

func (c *Client) readJSON(req *http.Request, target any) error {
	res, err := c.http.Do(req)
	if err != nil {
		return ErrUnavailable
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		if res.StatusCode >= 500 || res.StatusCode == http.StatusTooManyRequests {
			return ErrUnavailable
		}
		if req.Method == http.MethodPost && req.URL.String() == c.tokenURL {
			var failure struct {
				Error string `json:"error"`
			}
			body, readErr := io.ReadAll(io.LimitReader(res.Body, maxResponseBytes+1))
			if readErr == nil && len(body) <= maxResponseBytes && json.Unmarshal(body, &failure) == nil && failure.Error != "" {
				return &oauthError{code: failure.Error}
			}
		}
		// A JWKS/discovery 4xx says nothing about refresh-token validity.
		return ErrUnavailable
	}
	b, err := io.ReadAll(io.LimitReader(res.Body, maxResponseBytes+1))
	if err != nil || len(b) > maxResponseBytes {
		return ErrUnavailable
	}
	if err := json.Unmarshal(b, target); err != nil {
		return ErrAuthorization
	}
	return nil
}

type idClaims struct {
	jwt.RegisteredClaims
	Nonce           string `json:"nonce"`
	Email           string `json:"email"`
	AuthorizedParty string `json:"azp"`
}

func (c *Client) identity(ctx context.Context, raw, clientID, nonce string) (*idClaims, error) {
	if len(raw) == 0 || len(raw) > 32<<10 {
		return nil, ErrIdentity
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.jwksURL, nil)
	if err != nil {
		return nil, ErrIdentity
	}
	var keys jose.JSONWebKeySet
	if err := c.readJSON(req, &keys); err != nil {
		return nil, err
	}
	claims := &idClaims{}
	token, err := jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		kid, ok := t.Header["kid"].(string)
		if !ok || kid == "" {
			return nil, ErrIdentity
		}
		matches := keys.Key(kid)
		if len(matches) != 1 || !matches[0].Valid() || (matches[0].Use != "" && matches[0].Use != "sig") || (matches[0].Algorithm != "" && matches[0].Algorithm != "RS256") {
			return nil, ErrIdentity
		}
		key, ok := matches[0].Key.(*rsa.PublicKey)
		if !ok || key.N.BitLen() < 2048 {
			return nil, ErrIdentity
		}
		return key, nil
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(c.issuer), jwt.WithAudience(clientID),
		jwt.WithExpirationRequired(), jwt.WithIssuedAt(), jwt.WithTimeFunc(c.now), jwt.WithLeeway(30*time.Second))
	if err != nil || token == nil || !token.Valid || claims.IssuedAt == nil || claims.Subject == "" || len(claims.Subject) > 512 ||
		(len(claims.Audience) > 1 && claims.AuthorizedParty != clientID) ||
		(nonce != "" && subtle.ConstantTimeCompare([]byte(nonce), []byte(claims.Nonce)) != 1) {
		return nil, ErrIdentity
	}
	return claims, nil
}

func (c *Client) refresh(ctx context.Context, r *record, persist func() error) error {
	if r.PendingRefresh == nil {
		tokens, err := c.token(ctx, url.Values{"grant_type": {"refresh_token"}, "client_id": {r.ClientID},
			"refresh_token": {r.RefreshToken}, "resource": {resource}})
		if err != nil {
			return err
		}
		if tokens.RefreshToken == "" {
			return ErrReauthorize
		}
		pending := &refreshRotation{Tokens: *tokens, ReceivedAt: c.now().UTC(), CheckIdentity: tokens.IDToken != ""}
		if pending.Tokens.IDToken == "" {
			pending.Tokens.IDToken = r.IDToken
		}
		if pending.Tokens.Scope == "" {
			pending.Tokens.Scope = strings.Join(r.Scopes, " ")
		}
		// Persist the replacement BEFORE the next network operation. It is
		// quarantined and cannot authorize inference until identity validates.
		r.PendingRefresh, r.RenewalPending = pending, true
		r.RefreshToken, r.AccessToken, r.PlanUse = tokens.RefreshToken, "", false
		if err := persist(); err != nil {
			return err
		}
	}
	pending := r.PendingRefresh
	if pending.CheckIdentity {
		identity, err := c.identity(ctx, pending.Tokens.IDToken, r.ClientID, "")
		if err != nil {
			return err
		}
		if identity.Subject != r.Subject || identity.Issuer != r.Issuer {
			return ErrIdentity
		}
	}
	r.replaceTokens(&pending.Tokens, pending.ReceivedAt)
	r.PendingRefresh, r.RenewalPending = nil, false
	return persist()
}

func (c *Client) revoke(ctx context.Context, r *record) error {
	if r.RefreshToken == "" {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.discoveryURL, nil)
	if err != nil {
		return ErrUnavailable
	}
	var discovery struct {
		Issuer             string `json:"issuer"`
		RevocationEndpoint string `json:"revocation_endpoint"`
	}
	if err := c.readJSON(req, &discovery); err != nil {
		return err
	}
	u, err := url.Parse(discovery.RevocationEndpoint)
	base, _ := url.Parse(c.issuer)
	if err != nil || discovery.Issuer != c.issuer || u.Scheme != base.Scheme || u.Host != base.Host || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return ErrAuthorization
	}
	form := url.Values{"token": {r.RefreshToken}, "token_type_hint": {"refresh_token"}, "client_id": {r.ClientID}}
	req, err = http.NewRequestWithContext(ctx, http.MethodPost, u.String(), strings.NewReader(form.Encode()))
	if err != nil {
		return ErrAuthorization
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := c.http.Do(req)
	if err != nil {
		return ErrUnavailable
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return ErrUnavailable
	}
	return nil
}

func (r *record) replaceTokens(t *tokenResponse, now time.Time) {
	r.AccessToken, r.RefreshToken, r.IDToken = t.AccessToken, t.RefreshToken, t.IDToken
	r.ExpiresAt = now.UTC().Add(time.Duration(t.ExpiresIn) * time.Second)
	r.Scopes = strings.Fields(t.Scope)
	r.SignedIn = true
	r.PlanUse = slices.Contains(r.Scopes, "chatgpt.tokens.use.direct") && slices.Contains(r.Scopes, "resource.invoke") &&
		slices.Contains(r.Scopes, "offline_access") && r.RefreshToken != ""
}
