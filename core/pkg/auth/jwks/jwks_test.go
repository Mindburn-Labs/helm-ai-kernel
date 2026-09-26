package jwks

// quantum_posture: tests classical RSA (RS256) JWKS/JWT bearer-token
// validation; no post-quantum claim.

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

func TestCoverageJWKSValidator(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	jwksBody, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: &privateKey.PublicKey, KeyID: "kid-1", Use: "sig", Algorithm: "RS256"},
		{Key: &privateKey.PublicKey, KeyID: "enc-only", Use: "enc"},
	}})
	if err != nil {
		t.Fatalf("marshal JWKS: %v", err)
	}
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksBody)
	}))
	defer jwksServer.Close()

	config := JWKSConfig{
		JWKSURL:               jwksServer.URL,
		Issuer:                "issuer",
		Audience:              "audience",
		Resource:              "https://resource.example/mcp",
		Scopes:                []string{"mcp:tools", "helm:verify"},
		AllowInsecureLoopback: true,
	}
	validator := NewJWKSValidator(config)
	token := signTestJWT(t, privateKey, "kid-1", jwksClaims{
		Scope:       "mcp:tools helm:verify extra",
		Resource:    "https://resource.example/mcp",
		Resources:   []string{"https://other.example/mcp"},
		TenantID:    "tenant-a",
		WorkspaceID: "workspace-a",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "issuer",
			Audience:  jwt.ClaimStrings{"audience"},
			Subject:   "agent-1",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-time.Minute)),
			NotBefore: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
		},
	})

	claims, err := validator.ValidateAuthorization(token)
	if err != nil {
		t.Fatalf("ValidateAuthorization: %v", err)
	}
	if claims.RegisteredClaims.Subject != "agent-1" || claims.TenantID != "tenant-a" || claims.WorkspaceID != "workspace-a" ||
		!containsString(claims.Resources, "https://resource.example/mcp") || !containsString(claims.Scopes, "helm:verify") {
		t.Fatalf("unexpected claims: %+v", claims)
	}
	registered, err := validator.Validate(token)
	if err != nil || registered.Subject != "agent-1" {
		t.Fatalf("Validate registered=%+v err=%v", registered, err)
	}
	// Second validation uses the cached key set and covers the no-refresh branch.
	if _, err := validator.ValidateAuthorization(token); err != nil {
		t.Fatalf("cached ValidateAuthorization: %v", err)
	}

	missingScope := NewJWKSValidator(JWKSConfig{JWKSURL: jwksServer.URL, Issuer: "issuer", Audience: "audience", Scopes: []string{"missing"}, AllowInsecureLoopback: true})
	if _, err := missingScope.ValidateAuthorization(token); !isJWKSKind(err, JWKSErrMissingScope) {
		t.Fatalf("expected missing scope, got %v", err)
	}
	missingResource := NewJWKSValidator(JWKSConfig{JWKSURL: jwksServer.URL, Issuer: "issuer", Audience: "audience", Resource: "https://missing.example/mcp", AllowInsecureLoopback: true})
	if _, err := missingResource.ValidateAuthorization(token); !isJWKSKind(err, JWKSErrInvalidResource) {
		t.Fatalf("expected invalid resource, got %v", err)
	}
	wrongKid := signTestJWT(t, privateKey, "kid-missing", jwksClaims{
		Scope: "mcp:tools",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "issuer",
			Audience:  jwt.ClaimStrings{"audience"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-time.Minute)),
		},
	})
	if _, err := NewJWKSValidator(JWKSConfig{JWKSURL: jwksServer.URL, Issuer: "issuer", Audience: "audience", AllowInsecureLoopback: true}).ValidateAuthorization(wrongKid); err == nil || (!isJWKSKind(err, JWKSErrKeyNotFound) && (!isJWKSKind(err, JWKSErrMalformedToken) || !strings.Contains(err.Error(), "key_not_found"))) {
		t.Fatalf("expected key not found path, got %v", err)
	}
	noKid := signTestJWT(t, privateKey, "", jwksClaims{
		Scope: "mcp:tools",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "issuer",
			Audience:  jwt.ClaimStrings{"audience"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-time.Minute)),
		},
	})
	if _, err := NewJWKSValidator(JWKSConfig{JWKSURL: jwksServer.URL, Issuer: "issuer", Audience: "audience", AllowInsecureLoopback: true}).ValidateAuthorization(noKid); err != nil {
		t.Fatalf("no-kid token should use first available key: %v", err)
	}

	badServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusInternalServerError)
	}))
	defer badServer.Close()
	if err := refreshErr(NewJWKSValidator(JWKSConfig{JWKSURL: badServer.URL, AllowInsecureLoopback: true})); !isJWKSKind(err, JWKSErrFetchFailed) {
		t.Fatalf("expected fetch failed, got %v", err)
	}
	invalidJWKS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{`))
	}))
	defer invalidJWKS.Close()
	if err := fetchErr(NewJWKSValidator(JWKSConfig{JWKSURL: invalidJWKS.URL, AllowInsecureLoopback: true})); !isJWKSKind(err, JWKSErrFetchFailed) {
		t.Fatalf("expected parse JWKS failure, got %v", err)
	}
	if err := fetchErr(NewJWKSValidator(JWKSConfig{JWKSURL: "http://[::1"})); !isJWKSKind(err, JWKSErrFetchFailed) {
		t.Fatalf("expected bad URL failure, got %v", err)
	}
	if err := fetchErr(NewJWKSValidator(JWKSConfig{JWKSURL: "http://jwks.example.test/keys"})); !isJWKSKind(err, JWKSErrFetchFailed) || !strings.Contains(err.Error(), "https") {
		t.Fatalf("expected non-TLS JWKS endpoint rejection, got %v", err)
	}
	if _, err := NewJWKSValidator(config).ValidateAuthorization("not-a-jwt"); !isJWKSKind(err, JWKSErrMalformedToken) && !isJWKSKind(err, JWKSErrFetchFailed) {
		t.Fatalf("expected malformed token or fetch failure, got %v", err)
	}

	for message, want := range map[string]JWKSValidationErrorKind{
		"token is expired":           JWKSErrExpiredToken,
		"token used before issued":   JWKSErrNotYetValid,
		"token has invalid issuer":   JWKSErrInvalidIssuer,
		"token has invalid audience": JWKSErrInvalidAudience,
		"signature is invalid":       JWKSErrInvalidSignature,
		"something else":             JWKSErrMalformedToken,
	} {
		if err := classifyJWTError(errors.New(message)); !isJWKSKind(err, want) {
			t.Fatalf("classifyJWTError(%q) = %v, want %s", message, err, want)
		}
	}
	if classifyJWTError(nil) != nil {
		t.Fatal("nil JWT error should classify to nil")
	}
	if containsString([]string{"a"}, "b") {
		t.Fatal("containsString false branch failed")
	}
}

func TestJWKSValidationError_ErrorString(t *testing.T) {
	e := &JWKSValidationError{Kind: JWKSErrExpiredToken, Message: "token expired at X"}
	s := e.Error()
	if s != "expired_token: token expired at X" {
		t.Fatalf("unexpected error string: %s", s)
	}
}

func TestJWKSClaimsResourceIndicatorsDeduplicateSources(t *testing.T) {
	claims := &jwksClaims{
		Resource:  "https://gateway.example/mcp",
		Resources: []string{"https://gateway.example/mcp", "https://gateway.example/mcp/v2"},
		RegisteredClaims: jwt.RegisteredClaims{
			Audience: jwt.ClaimStrings{"https://gateway.example/mcp", "https://other.example/api"},
		},
	}

	resources := claims.resourceIndicators()
	if len(resources) != 3 {
		t.Fatalf("expected three deduplicated resource indicators, got %v", resources)
	}
	for _, expected := range []string{
		"https://gateway.example/mcp",
		"https://other.example/api",
		"https://gateway.example/mcp/v2",
	} {
		if !containsString(resources, expected) {
			t.Fatalf("expected %s in resource indicators %v", expected, resources)
		}
	}
}

func signTestJWT(t *testing.T, privateKey *rsa.PrivateKey, kid string, claims jwksClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	if kid != "" {
		token.Header["kid"] = kid
	}
	signed, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}
	return signed
}

func isJWKSKind(err error, kind JWKSValidationErrorKind) bool {
	var typed *JWKSValidationError
	return errors.As(err, &typed) && typed.Kind == kind
}

func fetchErr(v *JWKSValidator) error {
	_, err := v.fetchKeys()
	return err
}

func refreshErr(v *JWKSValidator) error {
	v.refreshKeys(false)
	return v.keysUsable()
}
