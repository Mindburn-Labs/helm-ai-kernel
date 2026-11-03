package identity

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

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
