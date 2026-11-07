package receiptkeyring

// quantum_posture: describes fixed classical Ed25519 and generated ML-DSA-65
// test signers; no new algorithm is exercised.

import (
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

// The Control Plane's HELM_KERNEL_RECEIPT_KEYRING vector: the Ed25519 seed
// 0x00..0x1f under key id "root".
const vector = `{"keyring_version":"kernel-evaluate-receipt-keyring.v1","keys":[{"key_id":"root","profile":"classical","ed25519_public_key_hex":"03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"}]}`

func TestEncodeIsTheControlPlaneVector(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	body, err := Encode(helmcrypto.NewEd25519SignerFromKey(ed25519.NewKeyFromSeed(seed), "root"))
	if err != nil || string(body) != vector {
		t.Fatalf("Encode = %s, %v", body, err)
	}
	rec := httptest.NewRecorder()
	Write(rec, body)
	if rec.Code != http.StatusOK || rec.Body.String() != vector || rec.Header().Get("Content-Type") != "application/json" ||
		rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Write = %d %v %s", rec.Code, rec.Header(), rec.Body.String())
	}
}

type opaqueSigner struct{ helmcrypto.Signer }

func (opaqueSigner) SignReceipt(*contracts.Receipt) error { return nil }

func TestForRefusesASignerItCannotDescribe(t *testing.T) {
	if _, err := For(opaqueSigner{}); err == nil {
		t.Fatal("a signer of an unknown profile was described")
	}
	if _, err := For(nil); err == nil {
		t.Fatal("a nil signer was described")
	}
	unnamed := helmcrypto.NewEd25519SignerFromKey(ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)), "")
	if _, err := Encode(unnamed); err == nil {
		t.Fatal("a signer without a key id was described")
	}
}
