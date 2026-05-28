package tee

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/fxamacker/cbor/v2"
)

func TestNitroCOSEVerifierRejectsNonceMismatchAndDebugZeroPCR(t *testing.T) {
	now := time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC)
	rootDER, leafDER, leafKey := nitroTestCerts(t, now)
	nonce := bytesOf(0xA1, NonceSize)
	pcrs := map[uint][]byte{
		0: bytesOf(0x10, NitroPCRSize),
		1: bytesOf(0x11, NitroPCRSize),
		2: bytesOf(0x12, NitroPCRSize),
		3: bytesOf(0x13, NitroPCRSize),
		4: bytesOf(0x14, NitroPCRSize),
		8: bytesOf(0x18, NitroPCRSize),
	}
	raw := nitroCOSEFixture(t, leafDER, rootDER, leafKey, nonce, pcrs, now, true)
	roots := TrustRoots{AWSNitroRoots: [][]byte{rootDER}, RequireSignedChain: true}
	result, err := Verify(PlatformNitro, raw, nonce, roots)
	if err != nil {
		t.Fatalf("valid Nitro COSE rejected: %v", err)
	}
	if result.ChainTrustedTo != "aws-nitro" || len(result.PCRs) != 6 {
		t.Fatalf("unexpected Nitro result: %+v", result)
	}
	if _, err := Verify(PlatformNitro, raw, bytesOf(0xB2, NonceSize), roots); err != ErrNonceMismatch {
		t.Fatalf("expected nonce mismatch, got %v", err)
	}
	pcrs[0] = make([]byte, NitroPCRSize)
	raw = nitroCOSEFixture(t, leafDER, rootDER, leafKey, nonce, pcrs, now, true)
	if _, err := Verify(PlatformNitro, raw, nonce, roots); err == nil {
		t.Fatal("expected debug-zero PCR rejection")
	}
}

func TestNitroAppraiserRejectsExpiredProfileSyntheticAndPCRMismatch(t *testing.T) {
	now := time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC)
	rootDER, leafDER, leafKey := nitroTestCerts(t, now)
	nonce := bytesOf(0xC3, NonceSize)
	pcr0 := bytesOf(0x20, NitroPCRSize)
	raw := nitroCOSEFixture(t, leafDER, rootDER, leafKey, nonce, map[uint][]byte{
		0: pcr0,
		1: bytesOf(0x21, NitroPCRSize),
		2: bytesOf(0x22, NitroPCRSize),
		3: bytesOf(0x23, NitroPCRSize),
		4: bytesOf(0x24, NitroPCRSize),
		8: bytesOf(0x28, NitroPCRSize),
	}, now, true)
	appraiser := NitroAppraiser{
		Roots:   TrustRoots{AWSNitroRoots: [][]byte{rootDER}},
		Signer:  staticEnvelopeSigner{},
		Subject: "nitro-appraiser-test",
		Clock:   func() time.Time { return now },
	}
	profile := contracts.VerifierProfile{
		ProfileID:           "nitro-prod",
		Platform:            string(PlatformNitro),
		AppraisalPolicyHash: "sha256:appraisal",
		RequiredPCRs:        map[string]string{"PCR0": hex.EncodeToString(pcr0)},
		ExpiresAt:           now.Add(time.Hour),
	}
	env, err := appraiser.Appraise(context.Background(), raw, nonce, profile)
	if err != nil {
		t.Fatalf("valid appraisal rejected: %v", err)
	}
	if env.Signature == "" || env.Synthetic || env.TrustTier != "verified" {
		t.Fatalf("unexpected envelope: %+v", env)
	}
	profile.AllowSynthetic = true
	if _, err := appraiser.Appraise(context.Background(), raw, nonce, profile); err == nil {
		t.Fatal("expected synthetic profile rejection")
	}
	profile.AllowSynthetic = false
	profile.ExpiresAt = now.Add(-time.Second)
	if _, err := appraiser.Appraise(context.Background(), raw, nonce, profile); err == nil {
		t.Fatal("expected expired profile rejection")
	}
	profile.ExpiresAt = now.Add(time.Hour)
	profile.RequiredPCRs["PCR0"] = hex.EncodeToString(bytesOf(0x99, NitroPCRSize))
	if _, err := appraiser.Appraise(context.Background(), raw, nonce, profile); err == nil {
		t.Fatal("expected PCR mismatch rejection")
	}
}

type staticEnvelopeSigner struct{}

func (staticEnvelopeSigner) Sign([]byte) (string, error) { return "sig-attestation-result", nil }

func nitroTestCerts(t *testing.T, now time.Time) ([]byte, []byte, *ecdsa.PrivateKey) {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "AWS Nitro Test Root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "AWS Nitro Test Leaf"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, rootTemplate, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	return rootDER, leafDER, leafKey
}

func nitroCOSEFixture(t *testing.T, leafDER []byte, rootDER []byte, leafKey *ecdsa.PrivateKey, nonce []byte, pcrs map[uint][]byte, now time.Time, tagged bool) []byte {
	t.Helper()
	protected, err := cbor.Marshal(map[int]int{1: int(coseAlgES384)})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := cbor.Marshal(map[string]any{
		"module_id":   "nitro-test",
		"digest":      "SHA384",
		"timestamp":   uint64(now.UnixMilli()),
		"pcrs":        pcrs,
		"certificate": leafDER,
		"cabundle":    [][]byte{rootDER},
		"nonce":       nonce,
	})
	if err != nil {
		t.Fatal(err)
	}
	toSign, err := cbor.Marshal([]any{"Signature1", protected, []byte{}, payload})
	if err != nil {
		t.Fatal(err)
	}
	sum := sha512.Sum384(toSign)
	r, s, err := ecdsa.Sign(rand.Reader, leafKey, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := make([]byte, 96)
	r.FillBytes(signature[:48])
	s.FillBytes(signature[48:])
	content := []any{protected, map[int]any{}, payload, signature}
	var raw []byte
	if tagged {
		raw, err = cbor.Marshal(cbor.Tag{Number: coseSign1Tag, Content: content})
	} else {
		raw, err = cbor.Marshal(content)
	}
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func bytesOf(value byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = value
	}
	return out
}
