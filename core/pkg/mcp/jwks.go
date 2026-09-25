package mcp

// quantum_posture: classical RSA (RS256) JWT signature verification via JWKS;
// no hybrid or post-quantum path.

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

// JWKSValidationErrorKind classifies the type of JWKS validation failure.
type JWKSValidationErrorKind string

const (
	JWKSErrExpiredToken     JWKSValidationErrorKind = "expired_token"
	JWKSErrNotYetValid      JWKSValidationErrorKind = "token_not_yet_valid"
	JWKSErrInvalidIssuer    JWKSValidationErrorKind = "invalid_issuer"
	JWKSErrInvalidAudience  JWKSValidationErrorKind = "invalid_audience"
	JWKSErrInvalidSignature JWKSValidationErrorKind = "invalid_signature"
	JWKSErrMissingScope     JWKSValidationErrorKind = "insufficient_scope"
	JWKSErrInvalidResource  JWKSValidationErrorKind = "invalid_resource"
	JWKSErrKeyNotFound      JWKSValidationErrorKind = "key_not_found"
	JWKSErrMalformedToken   JWKSValidationErrorKind = "malformed_token"
	JWKSErrFetchFailed      JWKSValidationErrorKind = "jwks_fetch_failed"
	JWKSErrInvalidActor     JWKSValidationErrorKind = "invalid_actor"
	JWKSErrInvalidLifetime  JWKSValidationErrorKind = "invalid_lifetime"
)

// JWKSValidationError is returned when bearer token validation fails.
type JWKSValidationError struct {
	Kind    JWKSValidationErrorKind `json:"kind"`
	Message string                  `json:"message"`
}

func (e *JWKSValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Kind, e.Message)
}

// JWKSConfig configures the JWKS validator.
type JWKSConfig struct {
	JWKSURL               string   // HELM_OAUTH_JWKS_URL — JWKS endpoint
	Issuer                string   // HELM_OAUTH_ISSUER — expected iss claim
	Audience              string   // HELM_OAUTH_AUDIENCE — expected aud claim
	Resource              string   // HELM_OAUTH_RESOURCE — expected RFC 8707 resource indicator
	Scopes                []string // HELM_OAUTH_SCOPES — required scopes
	AllowInsecureLoopback bool     // test/dev-only allowance for httptest loopback JWKS endpoints
	HTTPClient            *http.Client

	// The fields below are optional; zero values keep the behaviour above.
	// Algorithms, when set, is the only accepted list of JWS "alg" values.
	Algorithms []string
	// RequiredActor, when set, must equal the RFC 8693 "act.sub" claim.
	RequiredActor string
	// MaxTokenTTL, when positive, requires "iat" and bounds exp - iat.
	MaxTokenTTL time.Duration
	// Leeway is the clock skew allowed on exp, nbf and iat.
	Leeway time.Duration
	// MinRefreshInterval bounds how often the key set is fetched, routine
	// and forced (unknown kid) refreshes alike. Default 30s.
	MinRefreshInterval time.Duration
	// MaxStale is how long cached keys keep verifying after the last
	// successful fetch while the endpoint is unreachable. Default 1h.
	MaxStale time.Duration
	// Now is the clock; tests may replace it. Default time.Now.
	Now func() time.Time
}

// OAuthTokenClaims contains validated token claims needed by MCP authorization.
type OAuthTokenClaims struct {
	RegisteredClaims jwt.RegisteredClaims
	Scopes           []string
	Resources        []string
	TenantID         string
	WorkspaceID      string
	// Actor is the RFC 8693 "act.sub" claim, the workload acting for Subject.
	Actor string
	// CertificateThumbprint is "cnf.x5t#S256": the base64url SHA-256 of the
	// client certificate the token is bound to (RFC 8705), when present.
	CertificateThumbprint string
	// TransactionID is the "txn" claim, when present.
	TransactionID string
}

type jwksClaims struct {
	Scope       string   `json:"scope"`
	Resource    string   `json:"resource"`
	Resources   []string `json:"resources"`
	TenantID    string   `json:"tenant_id"`
	WorkspaceID string   `json:"workspace_id"`
	Act         *struct {
		Sub string `json:"sub"`
	} `json:"act,omitempty"`
	Cnf *struct {
		X5tS256 string `json:"x5t#S256"`
	} `json:"cnf,omitempty"`
	Txn string `json:"txn"`
	jwt.RegisteredClaims
}

// JWKSValidator validates bearer tokens against a JWKS endpoint.
type JWKSValidator struct {
	config JWKSConfig
	client *http.Client

	mu          sync.RWMutex
	keys        map[string]*rsa.PublicKey
	last        time.Time // last successful fetch
	lastAttempt time.Time // last fetch attempt, successful or not
	lastErr     error     // result of the last attempt; nil after a success

	// fetchMu admits one fetch at a time. Callers that queue behind it see
	// the fresh lastAttempt and share that fetch's result (singleflight).
	fetchMu sync.Mutex
}

const (
	jwksRefreshInterval           = 5 * time.Minute
	jwksDefaultMinRefreshInterval = 30 * time.Second
	jwksDefaultMaxStale           = time.Hour
)

// NewJWKSValidator creates a validator with the given config.
func NewJWKSValidator(config JWKSConfig) *JWKSValidator {
	client := config.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	clientCopy := *client
	if clientCopy.Timeout <= 0 {
		clientCopy.Timeout = 10 * time.Second
	}
	return &JWKSValidator{
		config: config,
		client: &clientCopy,
		keys:   make(map[string]*rsa.PublicKey),
	}
}

// Validate parses and validates a bearer token string.
// Returns the parsed claims on success, or a typed JWKSValidationError on failure.
func (v *JWKSValidator) Validate(tokenString string) (*jwt.RegisteredClaims, error) {
	claims, err := v.ValidateAuthorization(tokenString)
	if err != nil {
		return nil, err
	}
	return &claims.RegisteredClaims, nil
}

// ValidateAuthorization parses and validates a bearer token string and returns
// normalized OAuth metadata used by MCP scope and resource policy.
func (v *JWKSValidator) ValidateAuthorization(tokenString string) (*OAuthTokenClaims, error) {
	v.refreshKeys(false)
	if err := v.keysUsable(); err != nil {
		return nil, err
	}

	options := []jwt.ParserOption{
		jwt.WithIssuer(v.config.Issuer),
		jwt.WithAudience(v.config.Audience),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
	}
	if len(v.config.Algorithms) > 0 {
		options = append(options, jwt.WithValidMethods(v.config.Algorithms))
	}
	if v.config.Leeway > 0 {
		options = append(options, jwt.WithLeeway(v.config.Leeway))
	}
	parser := jwt.NewParser(options...)

	claims := &jwksClaims{}
	token, err := parser.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, &JWKSValidationError{
				Kind:    JWKSErrInvalidSignature,
				Message: fmt.Sprintf("unexpected signing method: %v", token.Header["alg"]),
			}
		}

		kid, _ := token.Header["kid"].(string)
		if kid == "" {
			// No kid — try first available key.
			v.mu.RLock()
			defer v.mu.RUnlock()
			for _, key := range v.keys {
				return key, nil
			}
			return nil, &JWKSValidationError{Kind: JWKSErrKeyNotFound, Message: "no keys available"}
		}

		v.mu.RLock()
		key, ok := v.keys[kid]
		v.mu.RUnlock()
		if !ok {
			// An unknown kid may be a rotation: refresh, but at most once per
			// MinRefreshInterval across all callers. Within that window every
			// unknown kid is answered from the cache (a global negative cache
			// that needs no per-kid state an attacker could grow).
			v.refreshKeys(true)
			v.mu.RLock()
			key, ok = v.keys[kid]
			lastErr := v.lastErr
			v.mu.RUnlock()
			if !ok {
				if lastErr != nil {
					return nil, asFetchFailed(lastErr)
				}
				return nil, &JWKSValidationError{
					Kind:    JWKSErrKeyNotFound,
					Message: fmt.Sprintf("key %q not found in JWKS", kid),
				}
			}
		}
		return key, nil
	})

	if err != nil {
		// Keep the kind of an error raised inside the key lookup (a failed
		// fetch stays a fetch failure) instead of reclassifying its text.
		var validationErr *JWKSValidationError
		if errors.As(err, &validationErr) {
			return nil, validationErr
		}
		return nil, classifyJWTError(err)
	}

	if !token.Valid {
		return nil, &JWKSValidationError{Kind: JWKSErrInvalidSignature, Message: "token is not valid"}
	}

	// Validate scopes if configured.
	if len(v.config.Scopes) > 0 {
		if err := v.validateScopeString(claims.Scope); err != nil {
			return nil, err
		}
	}

	if v.config.RequiredActor != "" && (claims.Act == nil || claims.Act.Sub != v.config.RequiredActor) {
		return nil, &JWKSValidationError{Kind: JWKSErrInvalidActor, Message: "act.sub does not name the required actor"}
	}
	if v.config.MaxTokenTTL > 0 {
		if claims.IssuedAt == nil || claims.ExpiresAt == nil ||
			!claims.ExpiresAt.After(claims.IssuedAt.Time) ||
			claims.ExpiresAt.Sub(claims.IssuedAt.Time) > v.config.MaxTokenTTL {
			return nil, &JWKSValidationError{
				Kind:    JWKSErrInvalidLifetime,
				Message: fmt.Sprintf("token lifetime must be positive and at most %s", v.config.MaxTokenTTL),
			}
		}
	}

	resources := claims.resourceIndicators()
	if v.config.Resource != "" && !containsString(resources, v.config.Resource) {
		return nil, &JWKSValidationError{
			Kind:    JWKSErrInvalidResource,
			Message: fmt.Sprintf("missing required resource indicator: %s", v.config.Resource),
		}
	}

	out := &OAuthTokenClaims{
		RegisteredClaims: claims.RegisteredClaims,
		Scopes:           strings.Fields(claims.Scope),
		Resources:        resources,
		TenantID:         strings.TrimSpace(claims.TenantID),
		WorkspaceID:      strings.TrimSpace(claims.WorkspaceID),
		TransactionID:    strings.TrimSpace(claims.Txn),
	}
	if claims.Act != nil {
		out.Actor = strings.TrimSpace(claims.Act.Sub)
	}
	if claims.Cnf != nil {
		out.CertificateThumbprint = strings.TrimSpace(claims.Cnf.X5tS256)
	}
	return out, nil
}

// CertificateMatchesThumbprint reports whether cert is the certificate a
// token's "cnf.x5t#S256" names (RFC 8705 §3.1).
func CertificateMatchesThumbprint(cert *x509.Certificate, thumbprint string) bool {
	if cert == nil || thumbprint == "" {
		return false
	}
	sum := sha256.Sum256(cert.Raw)
	return subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(sum[:])), []byte(thumbprint)) == 1
}

func (c *jwksClaims) resourceIndicators() []string {
	seen := make(map[string]struct{})
	var resources []string
	add := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		if _, ok := seen[value]; ok {
			return
		}
		seen[value] = struct{}{}
		resources = append(resources, value)
	}
	for _, audience := range c.Audience {
		add(audience)
	}
	add(c.Resource)
	for _, resource := range c.Resources {
		add(resource)
	}
	return resources
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func (v *JWKSValidator) validateScopeString(scope string) error {
	presentScopes := make(map[string]bool)
	for _, s := range strings.Fields(scope) {
		presentScopes[s] = true
	}

	var missing []string
	for _, required := range v.config.Scopes {
		if !presentScopes[required] {
			missing = append(missing, required)
		}
	}

	if len(missing) > 0 {
		return &JWKSValidationError{
			Kind:    JWKSErrMissingScope,
			Message: fmt.Sprintf("missing required scopes: %s", strings.Join(missing, ", ")),
		}
	}
	return nil
}

func (v *JWKSValidator) now() time.Time {
	if v.config.Now != nil {
		return v.config.Now()
	}
	return time.Now()
}

func (v *JWKSValidator) minRefreshInterval() time.Duration {
	if v.config.MinRefreshInterval > 0 {
		return v.config.MinRefreshInterval
	}
	return jwksDefaultMinRefreshInterval
}

func (v *JWKSValidator) maxStale() time.Duration {
	if v.config.MaxStale > 0 {
		return v.config.MaxStale
	}
	return jwksDefaultMaxStale
}

// refreshKeys fetches the key set when it is due: when none is loaded or the
// cache is older than jwksRefreshInterval, or, with force, whenever. Either
// way no fetch starts within MinRefreshInterval of the previous attempt, and
// only one fetch runs at a time. A failed fetch keeps the cached keys and is
// recorded, so the next attempt waits out the interval instead of retrying on
// every request.
func (v *JWKSValidator) refreshKeys(force bool) {
	due := func() bool {
		now := v.now()
		if !v.lastAttempt.IsZero() && now.Sub(v.lastAttempt) < v.minRefreshInterval() {
			return false
		}
		return force || len(v.keys) == 0 || now.Sub(v.last) > jwksRefreshInterval
	}
	v.mu.RLock()
	needed := due()
	v.mu.RUnlock()
	if !needed {
		return
	}
	v.fetchMu.Lock()
	defer v.fetchMu.Unlock()
	v.mu.RLock()
	needed = due()
	v.mu.RUnlock()
	if !needed {
		return
	}
	keys, err := v.fetchKeys()
	v.mu.Lock()
	defer v.mu.Unlock()
	v.lastAttempt = v.now()
	v.lastErr = err
	if err == nil {
		v.keys = keys
		v.last = v.lastAttempt
	}
}

// keysUsable fails closed when no key set is loaded, or when the loaded one is
// older than MaxStale because every refresh since has failed.
func (v *JWKSValidator) keysUsable() error {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if len(v.keys) > 0 && v.now().Sub(v.last) <= v.maxStale() {
		return nil
	}
	if v.lastErr != nil {
		return asFetchFailed(v.lastErr)
	}
	return &JWKSValidationError{Kind: JWKSErrFetchFailed, Message: "no signing keys are loaded"}
}

func asFetchFailed(err error) *JWKSValidationError {
	var validationErr *JWKSValidationError
	if errors.As(err, &validationErr) && validationErr.Kind == JWKSErrFetchFailed {
		return validationErr
	}
	return &JWKSValidationError{Kind: JWKSErrFetchFailed, Message: err.Error()}
}

func (v *JWKSValidator) fetchKeys() (map[string]*rsa.PublicKey, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	jwksURL, err := v.validatedJWKSURL()
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return nil, &JWKSValidationError{Kind: JWKSErrFetchFailed, Message: err.Error()}
	}

	resp, err := v.client.Do(req)
	if err != nil {
		return nil, &JWKSValidationError{Kind: JWKSErrFetchFailed, Message: err.Error()}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, &JWKSValidationError{
			Kind:    JWKSErrFetchFailed,
			Message: fmt.Sprintf("JWKS endpoint returned %d", resp.StatusCode),
		}
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, &JWKSValidationError{Kind: JWKSErrFetchFailed, Message: err.Error()}
	}

	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, &JWKSValidationError{Kind: JWKSErrFetchFailed, Message: fmt.Sprintf("parse JWKS: %v", err)}
	}

	keys := make(map[string]*rsa.PublicKey, len(jwks.Keys))
	for _, key := range jwks.Keys {
		if key.Use != "sig" && key.Use != "" {
			continue
		}
		rsaKey, ok := key.Key.(*rsa.PublicKey)
		if !ok {
			continue
		}
		kid := key.KeyID
		if kid == "" {
			kid = "_default"
		}
		keys[kid] = rsaKey
	}

	return keys, nil
}

func (v *JWKSValidator) validatedJWKSURL() (string, error) {
	parsed, err := url.Parse(v.config.JWKSURL)
	if err != nil {
		return "", &JWKSValidationError{Kind: JWKSErrFetchFailed, Message: err.Error()}
	}
	if parsed.Scheme == "https" {
		return parsed.String(), nil
	}
	if parsed.Scheme == "http" && v.config.AllowInsecureLoopback && isLoopbackHost(parsed.Hostname()) {
		return parsed.String(), nil
	}
	return "", &JWKSValidationError{
		Kind:    JWKSErrFetchFailed,
		Message: "JWKS endpoint must use https; http is only allowed for explicitly enabled loopback tests",
	}
}

func isLoopbackHost(host string) bool {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func classifyJWTError(err error) error {
	if err == nil {
		return nil
	}

	msg := err.Error()
	switch {
	case strings.Contains(msg, "token is expired"):
		return &JWKSValidationError{Kind: JWKSErrExpiredToken, Message: msg}
	case strings.Contains(msg, "token used before issued"),
		strings.Contains(msg, "token is not valid yet"):
		return &JWKSValidationError{Kind: JWKSErrNotYetValid, Message: msg}
	case strings.Contains(msg, "issuer"):
		return &JWKSValidationError{Kind: JWKSErrInvalidIssuer, Message: msg}
	case strings.Contains(msg, "audience"):
		return &JWKSValidationError{Kind: JWKSErrInvalidAudience, Message: msg}
	case strings.Contains(msg, "signature"):
		return &JWKSValidationError{Kind: JWKSErrInvalidSignature, Message: msg}
	default:
		return &JWKSValidationError{Kind: JWKSErrMalformedToken, Message: msg}
	}
}
