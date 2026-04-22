package mcp

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
	JWKSErrKeyNotFound      JWKSValidationErrorKind = "key_not_found"
	JWKSErrMalformedToken   JWKSValidationErrorKind = "malformed_token"
	JWKSErrFetchFailed      JWKSValidationErrorKind = "jwks_fetch_failed"
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
	JWKSURL  string   // HELM_OAUTH_JWKS_URL — JWKS endpoint
	Issuer   string   // HELM_OAUTH_ISSUER — expected iss claim
	Audience string   // HELM_OAUTH_AUDIENCE — expected aud claim
	Scopes   []string // HELM_OAUTH_SCOPES — required scopes
}

// JWKSValidator validates bearer tokens against a JWKS endpoint.
type JWKSValidator struct {
	config JWKSConfig
	client *http.Client

	mu   sync.RWMutex
	keys map[string]*rsa.PublicKey
	last time.Time
}

const jwksRefreshInterval = 5 * time.Minute

// NewJWKSValidator creates a validator with the given config.
func NewJWKSValidator(config JWKSConfig) *JWKSValidator {
	return &JWKSValidator{
		config: config,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		keys: make(map[string]*rsa.PublicKey),
	}
}

// Validate parses and validates a bearer token string.
// Returns the parsed claims on success, or a typed JWKSValidationError on failure.
func (v *JWKSValidator) Validate(tokenString string) (*jwt.RegisteredClaims, error) {
	if err := v.refreshKeysIfNeeded(); err != nil {
		return nil, err
	}

	parser := jwt.NewParser(
		jwt.WithIssuer(v.config.Issuer),
		jwt.WithAudience(v.config.Audience),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
	)

	claims := &jwt.RegisteredClaims{}
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
			// Force refresh and retry.
			if err := v.forceRefreshKeys(); err != nil {
				return nil, err
			}
			v.mu.RLock()
			key, ok = v.keys[kid]
			v.mu.RUnlock()
			if !ok {
				return nil, &JWKSValidationError{
					Kind:    JWKSErrKeyNotFound,
					Message: fmt.Sprintf("key %q not found in JWKS", kid),
				}
			}
		}
		return key, nil
	})

	if err != nil {
		return nil, classifyJWTError(err)
	}

	if !token.Valid {
		return nil, &JWKSValidationError{Kind: JWKSErrInvalidSignature, Message: "token is not valid"}
	}

	// Validate scopes if configured.
	if len(v.config.Scopes) > 0 {
		if err := v.validateScopes(tokenString); err != nil {
			return nil, err
		}
	}

	return claims, nil
}

func (v *JWKSValidator) validateScopes(tokenString string) error {
	// Parse without validation to read custom claims.
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	type scopeClaims struct {
		Scope string `json:"scope"`
		jwt.RegisteredClaims
	}
	sc := &scopeClaims{}
	_, _, err := parser.ParseUnverified(tokenString, sc)
	if err != nil {
		return &JWKSValidationError{Kind: JWKSErrMalformedToken, Message: "cannot parse scope claims"}
	}

	presentScopes := make(map[string]bool)
	for _, s := range strings.Fields(sc.Scope) {
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

func (v *JWKSValidator) refreshKeysIfNeeded() error {
	v.mu.RLock()
	needsRefresh := len(v.keys) == 0 || time.Since(v.last) > jwksRefreshInterval
	v.mu.RUnlock()

	if !needsRefresh {
		return nil
	}
	return v.forceRefreshKeys()
}

func (v *JWKSValidator) forceRefreshKeys() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.config.JWKSURL, nil)
	if err != nil {
		return &JWKSValidationError{Kind: JWKSErrFetchFailed, Message: err.Error()}
	}

	resp, err := v.client.Do(req)
	if err != nil {
		return &JWKSValidationError{Kind: JWKSErrFetchFailed, Message: err.Error()}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return &JWKSValidationError{
			Kind:    JWKSErrFetchFailed,
			Message: fmt.Sprintf("JWKS endpoint returned %d", resp.StatusCode),
		}
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return &JWKSValidationError{Kind: JWKSErrFetchFailed, Message: err.Error()}
	}

	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal(body, &jwks); err != nil {
		return &JWKSValidationError{Kind: JWKSErrFetchFailed, Message: fmt.Sprintf("parse JWKS: %v", err)}
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

	v.mu.Lock()
	v.keys = keys
	v.last = time.Now()
	v.mu.Unlock()

	return nil
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
