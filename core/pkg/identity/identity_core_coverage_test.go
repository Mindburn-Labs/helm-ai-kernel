package identity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestCertificateAuthorityCoreFlows(t *testing.T) {
	if _, err := NewCertificateAuthority(CAConfig{}); err == nil {
		t.Fatal("NewCertificateAuthority nil key error = nil")
	}

	_, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	ca, err := NewCertificateAuthority(CAConfig{CAID: "ca-1", PrivateKey: caPrivate})
	if err != nil {
		t.Fatalf("NewCertificateAuthority: %v", err)
	}
	if len(ca.CAPublicKey()) != ed25519.PublicKeySize*2 {
		t.Fatalf("CAPublicKey length = %d, want %d", len(ca.CAPublicKey()), ed25519.PublicKeySize*2)
	}

	agentPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate agent key: %v", err)
	}
	publicHex := hex.EncodeToString(agentPublic)
	req := CertificateRequest{
		AgentID:       "agent-1",
		AgentName:     "Agent One",
		PublicKey:     publicHex,
		Capabilities:  []string{"E0", "E1"},
		MaxDelegation: 2,
		ValidityDays:  1,
	}
	cert, err := ca.IssueCertificate(context.Background(), req)
	if err != nil {
		t.Fatalf("IssueCertificate: %v", err)
	}
	if cert.CertID == "" || !strings.HasPrefix(cert.CertID, "cert-") {
		t.Fatalf("CertID = %q, want generated cert id", cert.CertID)
	}
	if cert.IssuerID != "ca-1" || cert.Signature == "" {
		t.Fatalf("issued cert missing issuer/signature: %#v", cert)
	}
	if err := ca.VerifyCertificate(context.Background(), cert); err != nil {
		t.Fatalf("VerifyCertificate valid cert: %v", err)
	}

	byAgent, err := ca.GetCertificateByAgent(context.Background(), "agent-1")
	if err != nil {
		t.Fatalf("GetCertificateByAgent: %v", err)
	}
	if byAgent.CertID != cert.CertID {
		t.Fatalf("GetCertificateByAgent CertID = %s, want %s", byAgent.CertID, cert.CertID)
	}
	if _, err := ca.GetCertificateByAgent(context.Background(), "missing-agent"); err == nil {
		t.Fatal("GetCertificateByAgent missing error = nil")
	}

	if _, err := ca.IssueCertificate(context.Background(), CertificateRequest{PublicKey: publicHex}); err == nil {
		t.Fatal("IssueCertificate missing agent id error = nil")
	}
	if _, err := ca.IssueCertificate(context.Background(), CertificateRequest{AgentID: "agent-2"}); err == nil {
		t.Fatal("IssueCertificate missing public key error = nil")
	}
	if _, err := ca.IssueCertificate(context.Background(), CertificateRequest{AgentID: "agent-2", PublicKey: "bad"}); err == nil {
		t.Fatal("IssueCertificate invalid public key error = nil")
	}
	defaultValidity, err := ca.IssueCertificate(context.Background(), CertificateRequest{
		AgentID:   "agent-default-validity",
		PublicKey: publicHex,
	})
	if err != nil {
		t.Fatalf("IssueCertificate default validity: %v", err)
	}
	if defaultValidity.ExpiresAt.Sub(defaultValidity.IssuedAt) < 364*24*time.Hour {
		t.Fatalf("default validity too short: %s", defaultValidity.ExpiresAt.Sub(defaultValidity.IssuedAt))
	}

	expired := *cert
	expired.ExpiresAt = time.Now().Add(-time.Hour)
	if err := ca.VerifyCertificate(context.Background(), &expired); err == nil {
		t.Fatal("VerifyCertificate expired error = nil")
	}
	badEncoding := *cert
	badEncoding.Signature = "not-hex"
	if err := ca.VerifyCertificate(context.Background(), &badEncoding); err == nil {
		t.Fatal("VerifyCertificate bad signature encoding error = nil")
	}
	badSignature := *cert
	badSignature.Signature = hex.EncodeToString(make([]byte, ed25519.SignatureSize))
	if err := ca.VerifyCertificate(context.Background(), &badSignature); err == nil {
		t.Fatal("VerifyCertificate bad signature error = nil")
	}

	if err := ca.RevokeCertificate(context.Background(), "missing-cert"); err == nil {
		t.Fatal("RevokeCertificate missing error = nil")
	}
	if err := ca.RevokeCertificate(context.Background(), cert.CertID); err != nil {
		t.Fatalf("RevokeCertificate: %v", err)
	}
	if !cert.Revoked || cert.RevokedAt == nil {
		t.Fatalf("revoked cert not marked revoked: %#v", cert)
	}
	if err := ca.VerifyCertificate(context.Background(), cert); err == nil {
		t.Fatal("VerifyCertificate revoked error = nil")
	}
}

func TestKeySetAndTokenManagerCoreFlows(t *testing.T) {
	ks, err := NewInMemoryKeySet()
	if err != nil {
		t.Fatalf("NewInMemoryKeySet: %v", err)
	}

	tokenString, err := ks.Sign(context.Background(), jwt.RegisteredClaims{
		Subject:   "agent-1",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	parsed, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, ks.KeyFunc())
	if err != nil {
		t.Fatalf("ParseWithClaims signed token: %v", err)
	}
	if !parsed.Valid {
		t.Fatal("signed token parsed invalid")
	}

	keyFunc := ks.KeyFunc()
	if _, err := keyFunc(&jwt.Token{Method: jwt.SigningMethodHS256, Header: map[string]interface{}{"alg": "HS256"}}); err == nil {
		t.Fatal("KeyFunc wrong signing method error = nil")
	}
	if _, err := keyFunc(&jwt.Token{Method: jwt.SigningMethodEdDSA, Header: map[string]interface{}{"alg": "EdDSA"}}); err == nil {
		t.Fatal("KeyFunc missing kid error = nil")
	}
	if _, err := keyFunc(&jwt.Token{Method: jwt.SigningMethodEdDSA, Header: map[string]interface{}{"alg": "EdDSA", "kid": "missing"}}); err == nil {
		t.Fatal("KeyFunc unknown kid error = nil")
	}

	ks.mu.Lock()
	savedKID := ks.currentKID
	ks.currentKID = "missing"
	ks.mu.Unlock()
	if _, err := ks.Sign(context.Background(), jwt.RegisteredClaims{}); err == nil {
		t.Fatal("Sign missing active key error = nil")
	}
	ks.mu.Lock()
	ks.currentKID = savedKID
	ks.mu.Unlock()

	for i := 0; i < 11; i++ {
		if err := ks.Rotate(); err != nil {
			t.Fatalf("Rotate %d: %v", i, err)
		}
		time.Sleep(time.Nanosecond)
	}
	if len(ks.keys) > 10 {
		t.Fatalf("key count = %d, want <= 10", len(ks.keys))
	}

	tm := NewTokenManager(ks)
	identityToken, err := tm.GenerateToken(&AgentIdentity{
		AgentID:     "agent-token",
		DelegatorID: "user-1",
		Scopes:      []string{"read", "execute"},
	}, time.Hour)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	claims, err := tm.ValidateToken(identityToken)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if claims.Subject != "agent-token" || claims.Type != PrincipalAgent || claims.DelegatorID != "user-1" {
		t.Fatalf("unexpected token claims: %#v", claims)
	}
	if _, err := tm.ValidateToken("not-a-token"); err == nil {
		t.Fatal("ValidateToken malformed token error = nil")
	}
}
