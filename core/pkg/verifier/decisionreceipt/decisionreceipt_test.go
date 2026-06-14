package decisionreceipt

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

func newKeypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	return pub, priv
}

func sampleReceipt() contracts.ExternalDecisionReceipt {
	return contracts.ExternalDecisionReceipt{
		ReceiptID:    "edr_1",
		Action:       "github.create_issue",
		Verdict:      "allow",
		Subject:      "did:helm:agent:demo",
		SourceVendor: "example-vendor",
		SigningKeyID: "key-1",
	}
}

func adapter(t *testing.T) FormatAdapter {
	t.Helper()
	a, ok := Default().Get(HelmExternalFormatID)
	if !ok {
		t.Fatal("helm_external adapter not registered")
	}
	return a
}

func TestHelmExternalRoundTripTrustedKey(t *testing.T) {
	pub, priv := newKeypair(t)
	signed, err := SignHelmExternal(sampleReceipt(), priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	class, checks := VerifyReceipt(adapter(t), signed, nil, hex.EncodeToString(pub))
	if class != contracts.ClassCryptoConformant {
		t.Fatalf("class=%s, want crypto_conformant; checks=%+v", class, checks)
	}
}

func TestHelmExternalBundleKeyOnlyIsNonConformant(t *testing.T) {
	pub, priv := newKeypair(t)
	signed, _ := SignHelmExternal(sampleReceipt(), priv)
	bundleKeys := []contracts.ExternalVerifierKey{{KeyID: "key-1", Algorithm: "Ed25519", PublicKeyHex: hex.EncodeToString(pub)}}
	class, checks := VerifyReceipt(adapter(t), signed, bundleKeys, "")
	if class != contracts.ClassCryptoCompatibleNonConformant {
		t.Fatalf("class=%s, want crypto_compatible_non_conformant; checks=%+v", class, checks)
	}
}

func TestTamperedSignatureUnverified(t *testing.T) {
	pub, priv := newKeypair(t)
	signed, _ := SignHelmExternal(sampleReceipt(), priv)
	b := []byte(signed.Signature)
	if b[0] == 'a' {
		b[0] = 'b'
	} else {
		b[0] = 'a'
	}
	signed.Signature = string(b)
	if class, _ := VerifyReceipt(adapter(t), signed, nil, hex.EncodeToString(pub)); class != contracts.ClassUnverified {
		t.Fatalf("class=%s, want unverified", class)
	}
}

func TestTamperedBodyUnverified(t *testing.T) {
	pub, priv := newKeypair(t)
	signed, _ := SignHelmExternal(sampleReceipt(), priv)
	signed.Action = "github.delete_repo" // mutate after signing
	if class, _ := VerifyReceipt(adapter(t), signed, nil, hex.EncodeToString(pub)); class != contracts.ClassUnverified {
		t.Fatalf("class=%s, want unverified after body tamper", class)
	}
}

func TestWrongKeyUnverified(t *testing.T) {
	_, priv := newKeypair(t)
	otherPub, _ := newKeypair(t)
	signed, _ := SignHelmExternal(sampleReceipt(), priv)
	if class, _ := VerifyReceipt(adapter(t), signed, nil, hex.EncodeToString(otherPub)); class != contracts.ClassUnverified {
		t.Fatalf("class=%s, want unverified with wrong key", class)
	}
}

func TestNoKeyUnverified(t *testing.T) {
	_, priv := newKeypair(t)
	signed, _ := SignHelmExternal(sampleReceipt(), priv)
	if class, _ := VerifyReceipt(adapter(t), signed, nil, ""); class != contracts.ClassUnverified {
		t.Fatalf("class=%s, want unverified with no key", class)
	}
}

func TestVerifyBundleAutoDetectAndChain(t *testing.T) {
	pub, priv := newKeypair(t)
	r1, _ := SignHelmExternal(sampleReceipt(), priv)
	r2base := sampleReceipt()
	r2base.ReceiptID = "edr_2"
	r2base.PrevReceiptHash = r1.ReceiptHash
	r2, _ := SignHelmExternal(r2base, priv)

	bundle := contracts.ExternalDecisionReceiptBundle{
		SchemaVersion: contracts.ExternalDecisionReceiptBundleVersion,
		FormatID:      HelmExternalFormatID,
		Receipts:      []contracts.ExternalDecisionReceipt{r1, r2},
	}
	raw, _ := json.Marshal(bundle)

	rep, err := Default().VerifyBundle(raw, "", hex.EncodeToString(pub))
	if err != nil {
		t.Fatalf("verify bundle: %v", err)
	}
	if !rep.Verified || rep.Classification != contracts.ClassCryptoConformant {
		t.Fatalf("verified=%v class=%s; checks=%+v", rep.Verified, rep.Classification, rep.Checks)
	}
	if rep.ReceiptCount != 2 {
		t.Fatalf("receipt count=%d", rep.ReceiptCount)
	}
}

func TestVerifyBundleBrokenChainUnverified(t *testing.T) {
	pub, priv := newKeypair(t)
	r1, _ := SignHelmExternal(sampleReceipt(), priv)
	r2base := sampleReceipt()
	r2base.ReceiptID = "edr_2"
	r2base.PrevReceiptHash = "sha256:wrong"
	r2, _ := SignHelmExternal(r2base, priv)
	bundle := contracts.ExternalDecisionReceiptBundle{FormatID: HelmExternalFormatID, Receipts: []contracts.ExternalDecisionReceipt{r1, r2}}
	raw, _ := json.Marshal(bundle)
	rep, _ := Default().VerifyBundle(raw, HelmExternalFormatID, hex.EncodeToString(pub))
	if rep.Verified {
		t.Fatal("expected broken chain to fail verification")
	}
}

type nativeClaimAdapter struct{}

func (nativeClaimAdapter) FormatID() string                                          { return "evil.v1" }
func (nativeClaimAdapter) Kind() contracts.ExternalReceiptKind                       { return contracts.KindHELMNative }
func (nativeClaimAdapter) Detect([]byte) bool                                        { return false }
func (nativeClaimAdapter) Parse([]byte) ([]contracts.ExternalDecisionReceipt, error) { return nil, nil }
func (nativeClaimAdapter) CanonicalSignedBytes(contracts.ExternalDecisionReceipt) ([]byte, error) {
	return nil, nil
}

func TestRegisterRejectsHelmNativeAdapter(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("registering a helm_native adapter must panic")
		}
	}()
	NewRegistry().Register(nativeClaimAdapter{})
}

func TestHelmExternalNormalizesAwayNativeClaim(t *testing.T) {
	pub, priv := newKeypair(t)
	signed, _ := SignHelmExternal(sampleReceipt(), priv)
	rawSigned, _ := json.Marshal(signed)
	var m map[string]any
	if err := json.Unmarshal(rawSigned, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	m["kind"] = string(contracts.KindHELMNative) // forge a native claim
	raw, _ := json.Marshal(m)

	rep, err := Default().VerifyBundle(raw, HelmExternalFormatID, hex.EncodeToString(pub))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if rep.Kind == contracts.KindHELMNative {
		t.Fatal("must never report helm_native kind for an external receipt")
	}
}
