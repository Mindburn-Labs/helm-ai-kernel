package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"testing"
)

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
