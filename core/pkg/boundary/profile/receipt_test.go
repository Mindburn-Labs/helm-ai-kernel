package profile

import (
	"crypto/ed25519"
	"strings"
	"testing"
)

func sealedFixtureReceipt(t *testing.T) (CompileReceipt, ed25519.PublicKey) {
	t.Helper()
	signer := testSigner(t)
	compiled, err := Compile(fixtureInput(), signer, testCompileOptions())
	if err != nil {
		t.Fatal(err)
	}
	return compiled.Receipt, signer.PublicKeyBytes()
}

func TestCompileReceiptRoundTrip(t *testing.T) {
	receipt, pub := sealedFixtureReceipt(t)
	if err := VerifyCompileReceipt(receipt, pub); err != nil {
		t.Fatalf("sealed receipt must verify: %v", err)
	}
	if receipt.SignerKeyID != "boundary-test-key" {
		t.Fatalf("receipt must carry the signer key id, got %q", receipt.SignerKeyID)
	}
	if !strings.HasPrefix(receipt.Signature, "ed25519:") {
		t.Fatalf("signature must be ed25519-prefixed, got %q", receipt.Signature)
	}
}

func TestCompileReceiptTampersFailVerification(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*CompileReceipt)
	}{
		{"profile id substitution", func(r *CompileReceipt) { r.ProfileID = "other-profile" }},
		{"tier substitution", func(r *CompileReceipt) { r.ModeTier = TierObserve }},
		{"policy input hash flip", func(r *CompileReceipt) {
			r.PolicyInputHash = "sha256:" + strings.Repeat("ab", 32)
		}},
		{"artifact hash flip", func(r *CompileReceipt) {
			r.Artifacts[0].SHA256 = "sha256:" + strings.Repeat("cd", 32)
		}},
		{"artifact set hash flip", func(r *CompileReceipt) {
			r.ArtifactSetHash = "sha256:" + strings.Repeat("ef", 32)
		}},
		{"kernel version substitution", func(r *CompileReceipt) { r.KernelVersion = "9.9.9" }},
		{"record hash cleared", func(r *CompileReceipt) { r.RecordHash = "" }},
		{"signature truncated", func(r *CompileReceipt) { r.Signature = r.Signature[:len(r.Signature)-2] }},
		{"signature uppercased", func(r *CompileReceipt) { r.Signature = strings.ToUpper(r.Signature) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			receipt, pub := sealedFixtureReceipt(t)
			tc.mutate(&receipt)
			if err := VerifyCompileReceipt(receipt, pub); err == nil {
				t.Fatal("tampered receipt must not verify")
			}
		})
	}
}

func TestCompileReceiptWrongPublicKey(t *testing.T) {
	receipt, _ := sealedFixtureReceipt(t)
	wrong := ed25519.NewKeyFromSeed(append([]byte{1}, make([]byte, ed25519.SeedSize-1)...))
	if err := VerifyCompileReceipt(receipt, wrong.Public().(ed25519.PublicKey)); err == nil {
		t.Fatal("verification under the wrong public key must fail")
	}
}

func TestCompileReceiptShapeRejections(t *testing.T) {
	receipt, _ := sealedFixtureReceipt(t)
	unsorted := receipt
	unsorted.Artifacts = append([]ArtifactRef(nil), receipt.Artifacts...)
	unsorted.Artifacts[0], unsorted.Artifacts[1] = unsorted.Artifacts[1], unsorted.Artifacts[0]
	if _, err := CompileReceiptSigningBytes(unsorted); err == nil || !strings.Contains(err.Error(), "sorted") {
		t.Fatalf("unsorted artifacts must be rejected, got %v", err)
	}

	badTier := CompileReceipt{}
	if _, err := SealCompileReceipt(badTier, testSigner(t)); err == nil {
		t.Fatal("empty receipt must not seal")
	}
}
