package identity

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestOIDCProvider_DiscoveryAndLogin(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			_ = json.NewEncoder(w).Encode(map[string]string{
				"authorization_endpoint": "http://" + r.Host + "/auth",
				"token_endpoint":         "http://" + r.Host + "/token",
				"jwks_uri":               "http://" + r.Host + "/keys",
			})
			return
		}
		if r.URL.Path == "/auth" {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	p := NewOIDCProvider(ts.URL, "client-id", "client-secret", "http://localhost/callback")

	loginURL, err := p.InitiateLogin(context.Background(), "some-state")
	if err != nil {
		t.Fatalf("InitiateLogin failed: %v", err)
	}

	if !strings.Contains(loginURL, "/auth") {
		t.Errorf("expected auth endpoint in login URL, got: %s", loginURL)
	}
	if !strings.Contains(loginURL, "state=some-state") {
		t.Errorf("expected state in login URL")
	}
}

func TestOIDCProvider_CallbackVerifiesSignedIDToken(t *testing.T) {
	signingKey := newOIDCTestKey(t)
	ts := newOIDCTestServer(t, signingKey, func(issuer string) (string, error) {
		return signedOIDCTestToken(signingKey, "test-key", issuer, "client-id")
	})
	defer ts.Close()

	p := NewOIDCProvider(ts.URL, "client-id", "client-secret", "http://localhost/callback")

	got, err := p.Callback(context.Background(), "auth-code")
	if err != nil {
		t.Fatalf("Callback failed: %v", err)
	}
	if got.Subject != "user-123" {
		t.Fatalf("Subject = %q, want user-123", got.Subject)
	}
	if got.Email != "test@example.com" {
		t.Fatalf("Email = %q, want test@example.com", got.Email)
	}
	if got.Issuer != ts.URL {
		t.Fatalf("Issuer = %q, want %q", got.Issuer, ts.URL)
	}
}

func TestOIDCProvider_CallbackRejectsInvalidIDTokenSignature(t *testing.T) {
	trustedKey := newOIDCTestKey(t)
	untrustedKey := newOIDCTestKey(t)
	ts := newOIDCTestServer(t, trustedKey, func(issuer string) (string, error) {
		return signedOIDCTestToken(untrustedKey, "test-key", issuer, "client-id")
	})
	defer ts.Close()

	p := NewOIDCProvider(ts.URL, "client-id", "client-secret", "http://localhost/callback")

	_, err := p.Callback(context.Background(), "auth-code")
	if err == nil {
		t.Fatal("expected invalid id_token signature error")
	}
	if !strings.Contains(err.Error(), "invalid id_token") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func newOIDCTestServer(t *testing.T, signingKey *rsa.PrivateKey, issueToken func(issuer string) (string, error)) *httptest.Server {
	t.Helper()

	var ts *httptest.Server
	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"authorization_endpoint": ts.URL + "/auth",
				"token_endpoint":         ts.URL + "/token",
				"jwks_uri":               ts.URL + "/keys",
			})
		case "/keys":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"keys": []map[string]string{oidcTestJWK(signingKey, "test-key")},
			})
		case "/token":
			if err := r.ParseForm(); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("code") != "auth-code" {
				http.Error(w, "unexpected token request form", http.StatusBadRequest)
				return
			}
			idToken, err := issueToken(ts.URL)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "acc-123",
				"id_token":     idToken,
				"token_type":   "Bearer",
				"expires_in":   3600,
			})
		default:
			http.NotFound(w, r)
		}
	}))

	return ts
}

func newOIDCTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey failed: %v", err)
	}
	return key
}

func signedOIDCTestToken(key *rsa.PrivateKey, kid, issuer, audience string) (string, error) {
	claims := jwt.MapClaims{
		"sub":   "user-123",
		"iss":   issuer,
		"aud":   audience,
		"email": "test@example.com",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	return token.SignedString(key)
}

func oidcTestJWK(key *rsa.PrivateKey, kid string) map[string]string {
	return map[string]string{
		"kty": "RSA",
		"use": "sig",
		"kid": kid,
		"alg": "RS256",
		"n":   encodeJWKInt(key.PublicKey.N),
		"e":   encodeJWKInt(big.NewInt(int64(key.PublicKey.E))),
	}
}

func encodeJWKInt(n *big.Int) string {
	return base64.RawURLEncoding.EncodeToString(n.Bytes())
}
