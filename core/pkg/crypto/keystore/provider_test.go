package keystore

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

func TestKeyMetaIsActive(t *testing.T) {
	now := time.Unix(100, 0)
	future := now.Add(time.Hour)
	past := now.Add(-time.Hour)
	revoked := now

	tests := []struct {
		name string
		meta KeyMeta
		want bool
	}{
		{"active", KeyMeta{}, true},
		{"revoked", KeyMeta{RevokedAt: &revoked}, false},
		{"expired", KeyMeta{ExpiresAt: &past}, false},
		{"future expiry", KeyMeta{ExpiresAt: &future}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.meta.IsActive(now); got != tt.want {
				t.Fatalf("IsActive() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMemoryKeyProviderLifecycleAndVerification(t *testing.T) {
	p := NewMemoryKeyProvider()
	if _, err := p.ActiveSigner(); err == nil || !strings.Contains(err.Error(), "no active") {
		t.Fatalf("ActiveSigner() on empty provider error = %v", err)
	}
	if _, err := p.Sealer(); err == nil || !strings.Contains(err.Error(), "no sealer") {
		t.Fatalf("Sealer() on empty provider error = %v", err)
	}

	sealer := fakeSealer{}
	p.SetSealer(sealer)
	gotSealer, err := p.Sealer()
	if err != nil {
		t.Fatalf("Sealer() error = %v", err)
	}
	ciphertext, err := gotSealer.Seal([]byte("plain"))
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	plaintext, err := gotSealer.Open(ciphertext)
	if err != nil || string(plaintext) != "plain" {
		t.Fatalf("Open() = %q, %v", plaintext, err)
	}

	s1, err := p.GenerateKey("k1")
	if err != nil {
		t.Fatalf("GenerateKey(k1) error = %v", err)
	}
	if s1.KID() != "k1" || s1.Algorithm() != "ed25519" || len(s1.PublicKey()) != ed25519.PublicKeySize {
		t.Fatalf("signer metadata = kid %q alg %q public len %d", s1.KID(), s1.Algorithm(), len(s1.PublicKey()))
	}

	data := []byte("payload")
	sig, err := s1.Sign(data)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if len(sig) != ed25519.SignatureSize {
		t.Fatalf("signature length = %d, want %d", len(sig), ed25519.SignatureSize)
	}
	ok, err := p.Verify(context.Background(), "k1", data, sig)
	if err != nil || !ok {
		t.Fatalf("Verify() = %v, %v", ok, err)
	}
	ok, err = p.VerifySignature("k1", data, sig)
	if err != nil || !ok {
		t.Fatalf("VerifySignature() = %v, %v", ok, err)
	}
	ok, err = p.Verify(context.Background(), "k1", []byte("tampered"), sig)
	if err != nil || ok {
		t.Fatalf("Verify() tampered = %v, %v", ok, err)
	}

	s2, err := p.GenerateKey("k2")
	if err != nil {
		t.Fatalf("GenerateKey(k2) error = %v", err)
	}
	active, err := p.ActiveSigner()
	if err != nil || active.KID() != s2.KID() {
		t.Fatalf("ActiveSigner() = %v, %v, want k2", active, err)
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error = %v", err)
	}
	imported := p.ImportKey("k3", priv)
	if imported.KID() != "k3" {
		t.Fatalf("ImportKey() signer KID = %q", imported.KID())
	}

	keys := p.ListKeys()
	if len(keys) != 3 || keys[0].KID != "k1" || keys[1].KID != "k2" || keys[2].KID != "k3" {
		t.Fatalf("ListKeys() = %#v", keys)
	}
	if _, err := p.SignerByKID("unknown"); err == nil || !strings.Contains(err.Error(), "unknown key") {
		t.Fatalf("SignerByKID(unknown) error = %v", err)
	}
	if _, err := p.Verify(context.Background(), "unknown", data, sig); err == nil || !strings.Contains(err.Error(), "unknown key") {
		t.Fatalf("Verify(unknown) error = %v", err)
	}

	if err := p.RevokeKey("missing"); err == nil || !strings.Contains(err.Error(), "unknown key") {
		t.Fatalf("RevokeKey(missing) error = %v", err)
	}
	if err := p.RevokeKey("k3"); err != nil {
		t.Fatalf("RevokeKey(k3) error = %v", err)
	}
	if _, err := p.SignerByKID("k3"); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("SignerByKID(revoked) error = %v", err)
	}

	activeKeys := p.ActiveKeys(time.Now())
	for _, meta := range activeKeys {
		if meta.KID == "k3" {
			t.Fatalf("ActiveKeys() included revoked key: %#v", activeKeys)
		}
	}

	p.mu.Lock()
	p.metas["missing-signer"] = KeyMeta{KID: "missing-signer", CreatedAt: time.Now()}
	p.ordered = append(p.ordered, "missing-signer")
	p.mu.Unlock()
	if _, err := p.SignerByKID("missing-signer"); err == nil || !strings.Contains(err.Error(), "signer not found") {
		t.Fatalf("SignerByKID(missing signer) error = %v", err)
	}

	missingOnly := NewMemoryKeyProvider()
	missingOnly.metas["missing"] = KeyMeta{KID: "missing", CreatedAt: time.Now()}
	missingOnly.ordered = []string{"missing"}
	if _, err := missingOnly.ActiveSigner(); err == nil || !strings.Contains(err.Error(), "no active") {
		t.Fatalf("ActiveSigner() missing signer error = %v", err)
	}

	badPub := NewMemoryKeyProvider()
	badPub.signers["bad"] = fakeSigner{kid: "bad", publicKey: []byte("short")}
	badPub.metas["bad"] = KeyMeta{KID: "bad", CreatedAt: time.Now()}
	badPub.ordered = []string{"bad"}
	if _, err := badPub.Verify(context.Background(), "bad", data, sig); err == nil || !strings.Contains(err.Error(), "invalid public key size") {
		t.Fatalf("Verify(invalid public key) error = %v", err)
	}
}

func TestMemoryKeyProviderInjectedFailures(t *testing.T) {
	restore := replaceProviderHooks(t)
	newEd25519Signer = func(string) (*helmcrypto.Ed25519Signer, error) {
		return nil, errors.New("rng failed")
	}
	_, err := NewMemoryKeyProvider().GenerateKey("bad")
	if err == nil || !strings.Contains(err.Error(), "key generation failed") {
		t.Fatalf("GenerateKey() injected error = %v", err)
	}
	restore()

	p := NewMemoryKeyProvider()
	signer, err := p.GenerateKey("k1")
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	restore = replaceProviderHooks(t)
	decodeSignatureHex = func(string) ([]byte, error) {
		return nil, errors.New("decode failed")
	}
	_, err = signer.Sign([]byte("payload"))
	if err == nil || !strings.Contains(err.Error(), "decode ed25519 signature") {
		t.Fatalf("Sign() decode error = %v", err)
	}
	restore()
}

func replaceProviderHooks(t *testing.T) func() {
	t.Helper()

	oldNewEd25519Signer := newEd25519Signer
	oldDecodeSignatureHex := decodeSignatureHex
	restored := false

	restore := func() {
		if restored {
			return
		}
		newEd25519Signer = oldNewEd25519Signer
		decodeSignatureHex = oldDecodeSignatureHex
		restored = true
	}
	t.Cleanup(restore)
	return restore
}

type fakeSealer struct{}

func (fakeSealer) Seal(plaintext []byte) ([]byte, error) {
	return append([]byte("sealed:"), plaintext...), nil
}

func (fakeSealer) Open(ciphertext []byte) ([]byte, error) {
	return bytes.TrimPrefix(ciphertext, []byte("sealed:")), nil
}

type fakeSigner struct {
	kid       string
	algorithm string
	publicKey []byte
	signature []byte
	signErr   error
}

func (s fakeSigner) Sign([]byte) ([]byte, error) {
	if s.signErr != nil {
		return nil, s.signErr
	}
	return s.signature, nil
}

func (s fakeSigner) KID() string {
	return s.kid
}

func (s fakeSigner) Algorithm() string {
	if s.algorithm == "" {
		return "ed25519"
	}
	return s.algorithm
}

func (s fakeSigner) PublicKey() []byte {
	return s.publicKey
}
