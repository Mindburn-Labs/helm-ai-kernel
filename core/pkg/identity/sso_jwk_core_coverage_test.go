package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestJWKPublicKeyParsersAndSigningMethodMatching(t *testing.T) {
	rsaPrivate, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	rsaJWK := jwkKey{
		Kty: "RSA",
		Kid: "rsa",
		Alg: "RS256",
		N:   jwkBytes(rsaPrivate.PublicKey.N.Bytes()),
		E:   jwkBytes(big.NewInt(int64(rsaPrivate.PublicKey.E)).Bytes()),
	}
	rsaKey, err := jwkPublicKey(rsaJWK)
	if err != nil {
		t.Fatalf("jwkPublicKey RSA: %v", err)
	}
	if !signingMethodMatchesKey(jwt.SigningMethodRS256, rsaKey) {
		t.Fatal("RSA key did not match RS256")
	}
	if !signingMethodMatchesKey(jwt.SigningMethodPS256, rsaKey) {
		t.Fatal("RSA key did not match PS256")
	}
	if signingMethodMatchesKey(jwt.SigningMethodEdDSA, rsaKey) {
		t.Fatal("RSA key matched EdDSA")
	}
	if _, err := rsaPublicKeyFromJWK(jwkKey{Kty: "RSA", E: rsaJWK.E}); err == nil {
		t.Fatal("RSA missing modulus error = nil")
	}
	if _, err := rsaPublicKeyFromJWK(jwkKey{Kty: "RSA", N: rsaJWK.N, E: jwkBytes([]byte{2})}); err == nil {
		t.Fatal("RSA invalid exponent error = nil")
	}
	if _, err := rsaPublicKeyFromJWK(jwkKey{Kty: "RSA", N: rsaJWK.N, E: jwkBytes([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})}); err == nil {
		t.Fatal("RSA huge exponent error = nil")
	}

	ecdsaPrivate, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}
	ecJWK := jwkKey{
		Kty: "EC",
		Kid: "ec",
		Alg: "ES256",
		Crv: "P-256",
		X:   jwkBytes(ecdsaPrivate.PublicKey.X.Bytes()),
		Y:   jwkBytes(ecdsaPrivate.PublicKey.Y.Bytes()),
	}
	ecKey, err := jwkPublicKey(ecJWK)
	if err != nil {
		t.Fatalf("jwkPublicKey EC: %v", err)
	}
	if !signingMethodMatchesKey(jwt.SigningMethodES256, ecKey) {
		t.Fatal("EC key did not match ES256")
	}
	if _, err := ecdsaPublicKeyFromJWK(jwkKey{Kty: "EC", Crv: "P-999", X: ecJWK.X, Y: ecJWK.Y}); err == nil {
		t.Fatal("EC unsupported curve error = nil")
	}
	if _, err := ecdsaPublicKeyFromJWK(jwkKey{Kty: "EC", Crv: "P-256", X: ecJWK.X, Y: jwkBytes([]byte{1})}); err == nil {
		t.Fatal("EC off-curve point error = nil")
	}

	edPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519 key: %v", err)
	}
	edJWK := jwkKey{Kty: "OKP", Kid: "ed", Alg: "EdDSA", Crv: "Ed25519", X: jwkBytes(edPublic)}
	edKey, err := jwkPublicKey(edJWK)
	if err != nil {
		t.Fatalf("jwkPublicKey OKP: %v", err)
	}
	if !signingMethodMatchesKey(jwt.SigningMethodEdDSA, edKey) {
		t.Fatal("Ed25519 key did not match EdDSA")
	}
	if _, err := ed25519PublicKeyFromJWK(jwkKey{Kty: "OKP", Crv: "P-256", X: edJWK.X}); err == nil {
		t.Fatal("OKP wrong curve error = nil")
	}
	if _, err := ed25519PublicKeyFromJWK(jwkKey{Kty: "OKP", Crv: "Ed25519", X: jwkBytes([]byte{1})}); err == nil {
		t.Fatal("OKP invalid length error = nil")
	}

	if _, err := jwkPublicKey(jwkKey{Kty: "oct"}); err == nil {
		t.Fatal("unsupported key type error = nil")
	}
	if _, err := ellipticCurve("P-384"); err != nil {
		t.Fatalf("P-384 curve: %v", err)
	}
	if _, err := ellipticCurve("P-521"); err != nil {
		t.Fatalf("P-521 curve: %v", err)
	}
	if _, err := decodeJWKField("", "x"); err == nil {
		t.Fatal("missing JWK field error = nil")
	}
	padded := base64.URLEncoding.EncodeToString([]byte("padded"))
	if got, err := decodeJWKField(padded, "x"); err != nil || string(got) != "padded" {
		t.Fatalf("decode padded field = %q, %v", string(got), err)
	}
	if _, err := decodeJWKField("%%%", "x"); err == nil {
		t.Fatal("invalid JWK field error = nil")
	}
	if signingMethodMatchesKey(jwt.SigningMethodEdDSA, "not-a-key") {
		t.Fatal("unknown key type matched signing method")
	}
}

func TestJWKSKeyFuncBranches(t *testing.T) {
	_, rsaJWK, edJWK := testJWKs(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jwksDocument{Keys: []jwkKey{
			{Kty: "oct", Use: "enc", Kid: "ignored"},
			rsaJWK,
			edJWK,
		}})
	}))
	defer server.Close()

	provider := &OIDCProvider{discoveryDoc: &oidcDiscoveryDoc{JWKSURI: server.URL}}
	keyFunc, err := provider.jwksKeyFunc(context.Background())
	if err != nil {
		t.Fatalf("jwksKeyFunc: %v", err)
	}
	if key, err := keyFunc(&jwt.Token{
		Method: jwt.SigningMethodRS256,
		Header: map[string]interface{}{
			"alg": "RS256",
			"kid": "rsa",
		},
	}); err != nil || key == nil {
		t.Fatalf("keyFunc RSA = %v, %v", key, err)
	}
	if key, err := keyFunc(&jwt.Token{
		Method: jwt.SigningMethodEdDSA,
		Header: map[string]interface{}{
			"alg": "EdDSA",
			"kid": "ed",
		},
	}); err != nil || key == nil {
		t.Fatalf("keyFunc Ed25519 = %v, %v", key, err)
	}
	if _, err := keyFunc(&jwt.Token{Method: jwt.SigningMethodRS256, Header: map[string]interface{}{"alg": "RS256"}}); err == nil {
		t.Fatal("keyFunc missing kid error = nil")
	}
	if _, err := keyFunc(&jwt.Token{Method: jwt.SigningMethodRS256, Header: map[string]interface{}{"alg": "RS256", "kid": "missing"}}); err == nil {
		t.Fatal("keyFunc unknown kid error = nil")
	}
	if _, err := keyFunc(&jwt.Token{Method: jwt.SigningMethodRS512, Header: map[string]interface{}{"alg": "RS512", "kid": "rsa"}}); err == nil {
		t.Fatal("keyFunc alg mismatch error = nil")
	}

	if _, err := (&OIDCProvider{}).jwksKeyFunc(context.Background()); err == nil {
		t.Fatal("missing jwks_uri error = nil")
	}
	if _, err := (&OIDCProvider{discoveryDoc: &oidcDiscoveryDoc{JWKSURI: "://bad"}}).jwksKeyFunc(context.Background()); err == nil {
		t.Fatal("bad JWKS URI error = nil")
	}
	statusServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusBadGateway)
	}))
	defer statusServer.Close()
	if _, err := (&OIDCProvider{discoveryDoc: &oidcDiscoveryDoc{JWKSURI: statusServer.URL}}).jwksKeyFunc(context.Background()); err == nil {
		t.Fatal("JWKS status error = nil")
	}
	jsonServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("{"))
	}))
	defer jsonServer.Close()
	if _, err := (&OIDCProvider{discoveryDoc: &oidcDiscoveryDoc{JWKSURI: jsonServer.URL}}).jwksKeyFunc(context.Background()); err == nil {
		t.Fatal("JWKS JSON error = nil")
	}
	noKeysServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jwksDocument{Keys: []jwkKey{{Kty: "oct", Use: "enc", Kid: "ignored"}}})
	}))
	defer noKeysServer.Close()
	if _, err := (&OIDCProvider{discoveryDoc: &oidcDiscoveryDoc{JWKSURI: noKeysServer.URL}}).jwksKeyFunc(context.Background()); err == nil {
		t.Fatal("JWKS no signing keys error = nil")
	}
	invalidKeyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jwksDocument{Keys: []jwkKey{{Kty: "RSA", Use: "sig", Kid: "bad"}}})
	}))
	defer invalidKeyServer.Close()
	if _, err := (&OIDCProvider{discoveryDoc: &oidcDiscoveryDoc{JWKSURI: invalidKeyServer.URL}}).jwksKeyFunc(context.Background()); err == nil {
		t.Fatal("JWKS invalid JWK error = nil")
	}
}

func jwkBytes(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func testJWKs(t *testing.T) (*rsa.PrivateKey, jwkKey, jwkKey) {
	t.Helper()
	rsaPrivate, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	edPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519 key: %v", err)
	}
	return rsaPrivate,
		jwkKey{
			Kty: "RSA",
			Use: "sig",
			Kid: "rsa",
			Alg: "RS256",
			N:   jwkBytes(rsaPrivate.PublicKey.N.Bytes()),
			E:   jwkBytes(big.NewInt(int64(rsaPrivate.PublicKey.E)).Bytes()),
		},
		jwkKey{
			Kty: "OKP",
			Use: "sig",
			Kid: "ed",
			Alg: "EdDSA",
			Crv: "Ed25519",
			X:   jwkBytes(edPublic),
		}
}
