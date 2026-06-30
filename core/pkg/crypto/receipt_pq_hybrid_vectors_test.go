package crypto

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// Golden conformance vectors for the PQ-hybrid receipt profile
// (protocols/specs/rfc/receipt-pq-hybrid-profile-v1.md). The fixture is
// deterministic: keys derive from fixed seeds (0x42 x 32) and ML-DSA-65 uses
// deterministic signing, so regeneration is byte-identical on any platform.
// Set HELM_UPDATE_VECTORS=1 to rewrite the fixture.

const pqHybridFixturePath = "testdata/receipt_pq_hybrid_profile_v1.json"

type pqHybridVector struct {
	Name        string `json:"name"`
	Profile     string `json:"profile"`
	Signature   string `json:"signature"`
	ExpectValid bool   `json:"expect_valid"`
}

type pqHybridFixture struct {
	RFC              string           `json:"rfc"`
	Ed25519SeedHex   string           `json:"ed25519_seed_hex"`
	MLDSA65SeedHex   string           `json:"mldsa65_seed_hex"`
	Ed25519PublicKey string           `json:"ed25519_public_key"`
	MLDSA65PublicKey string           `json:"mldsa65_public_key"`
	Receipt          pqHybridReceipt  `json:"receipt"`
	Vectors          []pqHybridVector `json:"vectors"`
}

type pqHybridReceipt struct {
	ReceiptID    string `json:"receipt_id"`
	DecisionID   string `json:"decision_id"`
	EffectID     string `json:"effect_id"`
	Status       string `json:"status"`
	OutputHash   string `json:"output_hash"`
	PrevHash     string `json:"prev_hash"`
	LamportClock uint64 `json:"lamport_clock"`
	ArgsHash     string `json:"args_hash"`
}

func pqHybridTestSigners(t *testing.T) (*Ed25519Signer, *MLDSASigner) {
	t.Helper()
	edSeed := bytes.Repeat([]byte{0x42}, ed25519.SeedSize)
	edSigner := NewEd25519SignerFromKey(ed25519.NewKeyFromSeed(edSeed), "pq-hybrid-vector")

	var mldsaSeed [mldsa65.SeedSize]byte
	copy(mldsaSeed[:], bytes.Repeat([]byte{0x42}, mldsa65.SeedSize))
	_, mldsaPriv := mldsa65.NewKeyFromSeed(&mldsaSeed)
	mldsaSigner := NewMLDSASignerFromKey(mldsaPriv, "pq-hybrid-vector")
	return edSigner, mldsaSigner
}

func pqHybridFixtureReceipt() contracts.Receipt {
	return contracts.Receipt{
		ReceiptID:    "rcpt_pq_hybrid_vector_001",
		DecisionID:   "dec_pq_hybrid_vector_001",
		EffectID:     "eff_pq_hybrid_vector_001",
		Status:       "SUCCESS",
		OutputHash:   "5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9",
		PrevHash:     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		LamportClock: 42,
		ArgsHash:     "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b",
	}
}

// corruptHexComponent deterministically flips the first hex digit of a
// signature component so it remains valid hex but fails verification.
func corruptHexComponent(t *testing.T, sigHex string) string {
	t.Helper()
	if len(sigHex) == 0 {
		t.Fatal("empty signature component")
	}
	first := byte('0')
	if sigHex[0] == '0' {
		first = '1'
	}
	return string(first) + sigHex[1:]
}

func buildPQHybridFixture(t *testing.T) pqHybridFixture {
	t.Helper()
	edSigner, mldsaSigner := pqHybridTestSigners(t)
	hybrid, err := NewHybridSignerFromSigners(edSigner, mldsaSigner, "pq-hybrid-vector")
	if err != nil {
		t.Fatalf("hybrid signer: %v", err)
	}

	receipt := pqHybridFixtureReceipt()
	payload := CanonicalizeReceipt(receipt.ReceiptID, receipt.DecisionID, receipt.EffectID, receipt.Status, receipt.OutputHash, receipt.PrevHash, receipt.LamportClock, receipt.ArgsHash)

	hybridSig, err := hybrid.Sign([]byte(payload))
	if err != nil {
		t.Fatalf("hybrid sign: %v", err)
	}
	classicalSig, err := edSigner.Sign([]byte(payload))
	if err != nil {
		t.Fatalf("classical sign: %v", err)
	}

	edSigHex, mldsaSigHex, err := parseHybridSignature(hybridSig)
	if err != nil {
		t.Fatalf("parse hybrid signature: %v", err)
	}

	join := func(ed, mldsa string) string {
		return HybridSigPrefix + HybridSigSeparator + ed + HybridSigSeparator + mldsa
	}

	return pqHybridFixture{
		RFC:              "protocols/specs/rfc/receipt-pq-hybrid-profile-v1.md",
		Ed25519SeedHex:   hex.EncodeToString(bytes.Repeat([]byte{0x42}, ed25519.SeedSize)),
		MLDSA65SeedHex:   hex.EncodeToString(bytes.Repeat([]byte{0x42}, mldsa65.SeedSize)),
		Ed25519PublicKey: edSigner.PublicKey(),
		MLDSA65PublicKey: mldsaSigner.PublicKey(),
		Receipt: pqHybridReceipt{
			ReceiptID:    receipt.ReceiptID,
			DecisionID:   receipt.DecisionID,
			EffectID:     receipt.EffectID,
			Status:       receipt.Status,
			OutputHash:   receipt.OutputHash,
			PrevHash:     receipt.PrevHash,
			LamportClock: receipt.LamportClock,
			ArgsHash:     receipt.ArgsHash,
		},
		Vectors: []pqHybridVector{
			{Name: "hybrid_valid", Profile: ReceiptProfileHybrid, Signature: hybridSig, ExpectValid: true},
			{Name: "hybrid_bad_mldsa_good_ed25519", Profile: ReceiptProfileHybrid, Signature: join(edSigHex, corruptHexComponent(t, mldsaSigHex)), ExpectValid: false},
			{Name: "hybrid_bad_ed25519_good_mldsa", Profile: ReceiptProfileHybrid, Signature: join(corruptHexComponent(t, edSigHex), mldsaSigHex), ExpectValid: false},
			{Name: "hybrid_presented_as_classical", Profile: ReceiptProfileClassical, Signature: hybridSig, ExpectValid: false},
			{Name: "classical_valid", Profile: ReceiptProfileClassical, Signature: classicalSig, ExpectValid: true},
		},
	}
}

func TestReceiptPQHybridGoldenVectors(t *testing.T) {
	built := buildPQHybridFixture(t)

	if os.Getenv("HELM_UPDATE_VECTORS") == "1" {
		data, err := json.MarshalIndent(built, "", "  ")
		if err != nil {
			t.Fatalf("marshal fixture: %v", err)
		}
		if err := os.MkdirAll(filepath.Dir(pqHybridFixturePath), 0o750); err != nil {
			t.Fatalf("mkdir testdata: %v", err)
		}
		if err := os.WriteFile(pqHybridFixturePath, append(data, '\n'), 0o644); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
	}

	raw, err := os.ReadFile(pqHybridFixturePath)
	if err != nil {
		t.Fatalf("read fixture (run with HELM_UPDATE_VECTORS=1 to generate): %v", err)
	}
	var fixture pqHybridFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}

	// Golden determinism: regeneration from fixed seeds must reproduce the
	// committed fixture byte-for-byte.
	builtJSON, _ := json.Marshal(built)
	fixtureJSON, _ := json.Marshal(fixture)
	if !bytes.Equal(builtJSON, fixtureJSON) {
		t.Fatal("committed fixture does not match deterministic regeneration; rerun with HELM_UPDATE_VECTORS=1 and review the diff")
	}

	receipt := pqHybridFixtureReceipt()
	for _, vec := range fixture.Vectors {
		t.Run(vec.Name, func(t *testing.T) {
			r := receipt
			r.Signature = vec.Signature

			profile, valid, err := VerifyReceiptProfile(fixture.Ed25519PublicKey, fixture.MLDSA65PublicKey, &r)
			if vec.Name == "hybrid_presented_as_classical" {
				// Profile detection still reports hybrid; the classical-only
				// acceptance checks in TestReceiptPQHybridProfileConfusion
				// are the normative assertion for this vector.
				if profile != ReceiptProfileHybrid {
					t.Fatalf("expected hybrid profile detection, got %q", profile)
				}
				return
			}
			if profile != vec.Profile {
				t.Fatalf("profile = %q, want %q", profile, vec.Profile)
			}
			if err != nil {
				t.Fatalf("VerifyReceiptProfile error: %v", err)
			}
			if valid != vec.ExpectValid {
				t.Fatalf("VerifyReceiptProfile valid = %v, want %v", valid, vec.ExpectValid)
			}
		})
	}
}

// TestReceiptPQHybridProfileConfusion asserts the RFC §4 fail-closed rules:
// a hybrid envelope presented to a classical-only verifier fails, and a
// hybrid envelope without the PQ public key fails (no silent downgrade).
func TestReceiptPQHybridProfileConfusion(t *testing.T) {
	fixture := buildPQHybridFixture(t)
	receipt := pqHybridFixtureReceipt()
	receipt.Signature = fixture.Vectors[0].Signature // hybrid_valid

	// Classical-only verifier (Ed25519Verifier) must reject the hybrid envelope.
	edPub, err := hex.DecodeString(fixture.Ed25519PublicKey)
	if err != nil {
		t.Fatalf("decode ed25519 pub: %v", err)
	}
	classical, err := NewEd25519Verifier(edPub)
	if err != nil {
		t.Fatalf("classical verifier: %v", err)
	}
	if ok, err := classical.VerifyReceipt(&receipt); err == nil && ok {
		t.Fatal("classical-only verifier accepted a hybrid envelope")
	}

	// Package-level classical verify must also reject it.
	payload := CanonicalizeReceipt(receipt.ReceiptID, receipt.DecisionID, receipt.EffectID, receipt.Status, receipt.OutputHash, receipt.PrevHash, receipt.LamportClock, receipt.ArgsHash)
	if ok, err := Verify(fixture.Ed25519PublicKey, receipt.Signature, []byte(payload)); err == nil && ok {
		t.Fatal("package-level classical Verify accepted a hybrid envelope")
	}

	// Missing PQ key: hybrid receipt must fail, never downgrade to classical.
	if _, valid, err := VerifyReceiptProfile(fixture.Ed25519PublicKey, "", &receipt); err == nil || valid {
		t.Fatalf("hybrid receipt without PQ key must fail closed (valid=%v err=%v)", valid, err)
	}

	// Classical receipt presented where hybrid components exist stays valid
	// under the classical profile (no retroactive invalidation).
	receipt.Signature = fixture.Vectors[4].Signature // classical_valid
	profile, valid, err := VerifyReceiptProfile(fixture.Ed25519PublicKey, fixture.MLDSA65PublicKey, &receipt)
	if err != nil || !valid || profile != ReceiptProfileClassical {
		t.Fatalf("classical receipt must remain valid (profile=%q valid=%v err=%v)", profile, valid, err)
	}

	profile, valid, err = VerifyReceiptRequiredProfile(fixture.Ed25519PublicKey, fixture.MLDSA65PublicKey, &receipt, ReceiptProfileHybrid)
	if err == nil || valid {
		t.Fatalf("hybrid-required verification must reject classical receipt (profile=%q valid=%v err=%v)", profile, valid, err)
	}
	if profile != ReceiptProfileClassical {
		t.Fatalf("profile = %q, want classical", profile)
	}
	if !strings.Contains(err.Error(), `does not satisfy required profile "hybrid"`) {
		t.Fatalf("unexpected downgrade error: %v", err)
	}
}

func TestReceiptRequiredProfileRejectsUnsupportedProfile(t *testing.T) {
	fixture := buildPQHybridFixture(t)
	receipt := pqHybridFixtureReceipt()
	receipt.Signature = fixture.Vectors[4].Signature // classical_valid

	profile, valid, err := VerifyReceiptRequiredProfile(fixture.Ed25519PublicKey, fixture.MLDSA65PublicKey, &receipt, "pqc")
	if err == nil || valid {
		t.Fatalf("unsupported required profile must fail closed (profile=%q valid=%v err=%v)", profile, valid, err)
	}
	if !strings.Contains(err.Error(), `unsupported required receipt profile "pqc"`) {
		t.Fatalf("unexpected unsupported-profile error: %v", err)
	}
}

// TestReceiptPQHybridIssuanceEnvelope asserts the issuance path (HybridSigner
// over a Receipt) produces an envelope the public-key HybridVerifier accepts,
// and that tampering any receipt field invalidates it.
func TestReceiptPQHybridIssuanceEnvelope(t *testing.T) {
	edSigner, mldsaSigner := pqHybridTestSigners(t)
	hybrid, err := NewHybridSignerFromSigners(edSigner, mldsaSigner, "pq-hybrid-vector")
	if err != nil {
		t.Fatalf("hybrid signer: %v", err)
	}

	receipt := pqHybridFixtureReceipt()
	if err := hybrid.SignReceipt(&receipt); err != nil {
		t.Fatalf("sign receipt: %v", err)
	}
	if got := ReceiptSignatureProfile(receipt.Signature); got != ReceiptProfileHybrid {
		t.Fatalf("issued profile = %q, want hybrid", got)
	}

	hv, err := NewHybridVerifier(edSigner.PublicKeyBytes(), mldsaSigner.PublicKeyBytes())
	if err != nil {
		t.Fatalf("hybrid verifier: %v", err)
	}
	if ok, err := hv.VerifyReceipt(&receipt); err != nil || !ok {
		t.Fatalf("hybrid verifier rejected issued receipt (ok=%v err=%v)", ok, err)
	}

	tampered := receipt
	tampered.Status = "FAILURE"
	if ok, err := hv.VerifyReceipt(&tampered); err == nil && ok {
		t.Fatal("hybrid verifier accepted tampered receipt")
	}
}
