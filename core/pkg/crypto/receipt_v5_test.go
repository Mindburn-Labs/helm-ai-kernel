package crypto

import (
	"bytes"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

func v5TestReceipt() *contracts.Receipt {
	return &contracts.Receipt{
		ReceiptID:    "rcpt-1",
		DecisionID:   "dec-1",
		EffectID:     "eff-1",
		Status:       "EXECUTED",
		OutputHash:   "sha256:out",
		PrevHash:     "sha256:prev",
		LamportClock: 7,
		ArgsHash:     "sha256:args",
		Verdict:      "ALLOW",
		ReasonCode:   "POLICY_ALLOW",
		PolicyHash:   "sha256:policy",
		SessionID:    "sess-1",
	}
}

// The HELM-303 headline: governance-meaning fields can no longer be rewritten
// on a persisted receipt without invalidating its signature — including on the
// chain tip, with no successor receipt.
func TestReceiptV5_GovernanceFieldsAreSignatureBound(t *testing.T) {
	signer, err := NewEd25519Signer("v5-key")
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewEd25519Verifier(signer.PublicKeyBytes())
	if err != nil {
		t.Fatal(err)
	}

	tampers := map[string]func(r *contracts.Receipt){
		"Verdict":    func(r *contracts.Receipt) { r.Verdict = "DENY" },
		"ReasonCode": func(r *contracts.Receipt) { r.ReasonCode = "TAMPERED" },
		"PolicyHash": func(r *contracts.Receipt) { r.PolicyHash = "sha256:evil" },
		"SessionID":  func(r *contracts.Receipt) { r.SessionID = "sess-evil" },
	}
	for name, tamper := range tampers {
		t.Run(name, func(t *testing.T) {
			r := v5TestReceipt()
			if err := signer.SignReceipt(r); err != nil {
				t.Fatal(err)
			}
			if r.SignatureVersion != contracts.ReceiptSignatureV5 {
				t.Fatalf("signer must stamp V5, got %q", r.SignatureVersion)
			}
			if ok, err := verifier.VerifyReceipt(r); err != nil || !ok {
				t.Fatalf("untampered V5 receipt must verify (ok=%v err=%v)", ok, err)
			}
			tamper(r)
			if ok, _ := verifier.VerifyReceipt(r); ok {
				t.Fatalf("tampered %s verified — field not bound", name)
			}
		})
	}
}

func TestReceiptV5_PublicVerifierUsesActiveSigningPayload(t *testing.T) {
	signer, err := NewEd25519Signer("v5-public-verifier")
	if err != nil {
		t.Fatal(err)
	}
	receipt := v5TestReceipt()
	if err := signer.SignReceipt(receipt); err != nil {
		t.Fatal(err)
	}

	ok, version, err := VerifyReceiptSignature(signer.PublicKey(), receipt)
	if err != nil || !ok {
		t.Fatalf("fresh V5 receipt must verify through the public helper: ok=%v err=%v", ok, err)
	}
	if version != ReceiptPreimageSignedFieldsV5 {
		t.Fatalf("preimage version = %q, want %q", version, ReceiptPreimageSignedFieldsV5)
	}

	receipt.PolicyHash = "sha256:tampered"
	if ok, _, err := VerifyReceiptSignature(signer.PublicKey(), receipt); err != nil || ok {
		t.Fatalf("tampered V5 receipt must not verify: ok=%v err=%v", ok, err)
	}
}

func TestReceiptV5_DeclaredVersionDoesNotDowngradeToLegacy(t *testing.T) {
	signer, err := NewEd25519Signer("v5-no-downgrade")
	if err != nil {
		t.Fatal(err)
	}
	receipt := v5TestReceipt()
	legacyPayload := ReceiptPreimageV4(receipt)
	receipt.Signature, err = signer.Sign(legacyPayload)
	if err != nil {
		t.Fatal(err)
	}
	receipt.SignatureVersion = contracts.ReceiptSignatureV5

	if ok, _, err := VerifyReceiptSignature(signer.PublicKey(), receipt); err != nil || ok {
		t.Fatalf("declared V5 receipt must not fall back to legacy verification: ok=%v err=%v", ok, err)
	}
}

func TestReceiptV5_JCSEnvelopePreventsFieldBoundaryCollisions(t *testing.T) {
	first := v5TestReceipt()
	first.Verdict = "ALLOW:POLICY"
	first.ReasonCode = "VIOLATION"

	second := v5TestReceipt()
	second.Verdict = "ALLOW"
	second.ReasonCode = "POLICY:VIOLATION"

	firstPayload, err := CanonicalizeReceiptV5(first)
	if err != nil {
		t.Fatal(err)
	}
	secondPayload, err := CanonicalizeReceiptV5(second)
	if err != nil {
		t.Fatal(err)
	}
	if string(firstPayload) == string(secondPayload) {
		t.Fatalf("distinct V5 governance fields must not share a signing payload: %s", firstPayload)
	}
}

func TestDecisionV2_JCSEnvelopePreventsFieldBoundaryCollisions(t *testing.T) {
	first, err := CanonicalizeDecisionV2("dec", "DENY:POLICY", "why", "VIOLATION", "sha256:phenotype", "sha256:policy", "sha256:effect")
	if err != nil {
		t.Fatal(err)
	}
	second, err := CanonicalizeDecisionV2("dec:DENY", "POLICY", "why", "VIOLATION", "sha256:phenotype", "sha256:policy", "sha256:effect")
	if err != nil {
		t.Fatal(err)
	}
	if string(first) == string(second) {
		t.Fatalf("distinct V2 decision fields must not share a signing payload: %s", first)
	}
}

func TestDecisionV2PreimageMatchesGenericJCS(t *testing.T) {
	const (
		id                = "dec-\u2028\"quoted\""
		verdict           = "DENY\ncontrol\x01"
		reason            = "denied: \u2028 prose\nwith control\x02"
		reasonCode        = "POLICY\\DENY"
		phenotypeHash     = "sha256:<phenotype>"
		policyContentHash = "sha256:policy"
		effectDigest      = "sha256:effect"
	)

	got, err := CanonicalizeDecisionV2(id, verdict, reason, reasonCode, phenotypeHash, policyContentHash, effectDigest)
	if err != nil {
		t.Fatal(err)
	}
	want, err := canonicalize.JCS(decisionV2SigningEnvelope{
		SignatureVersion:  contracts.DecisionRecordSignatureV2,
		ID:                id,
		Verdict:           verdict,
		ReasonCode:        reasonCode,
		ReasonHash:        HashReason(reason),
		PhenotypeHash:     phenotypeHash,
		PolicyContentHash: policyContentHash,
		EffectDigest:      effectDigest,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("V2 preimage drifted from JCS\n got: %s\nwant: %s", got, want)
	}

	invalidUTF8 := string([]byte{0xff})
	got, err = CanonicalizeDecisionV2(invalidUTF8, verdict, invalidUTF8, reasonCode, phenotypeHash, policyContentHash, effectDigest)
	if err != nil {
		t.Fatal(err)
	}
	want, err = canonicalize.JCS(decisionV2SigningEnvelope{
		SignatureVersion:  contracts.DecisionRecordSignatureV2,
		ID:                invalidUTF8,
		Verdict:           verdict,
		ReasonCode:        reasonCode,
		ReasonHash:        HashReason(invalidUTF8),
		PhenotypeHash:     phenotypeHash,
		PolicyContentHash: policyContentHash,
		EffectDigest:      effectDigest,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("V2 invalid UTF-8 preimage drifted from JCS\n got: %s\nwant: %s", got, want)
	}
}

// Receipts signed before HELM-303 (no signature_version) keep verifying under
// the legacy V4 preimage: dual-verify, no re-signing of history.
func TestReceiptLegacyV4StillVerifies(t *testing.T) {
	signer, err := NewEd25519Signer("legacy-key")
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewEd25519Verifier(signer.PublicKeyBytes())
	if err != nil {
		t.Fatal(err)
	}

	r := v5TestReceipt()
	// Sign the way a pre-HELM-303 kernel did: legacy preimage, no version.
	legacyPayload := CanonicalizeReceipt(r.ReceiptID, r.DecisionID, r.EffectID, r.Status, r.OutputHash, r.PrevHash, r.LamportClock, r.ArgsHash)
	sig, err := signer.Sign([]byte(legacyPayload))
	if err != nil {
		t.Fatal(err)
	}
	r.Signature = sig
	r.SignatureVersion = ""

	if ok, err := verifier.VerifyReceipt(r); err != nil || !ok {
		t.Fatalf("legacy receipt must keep verifying (ok=%v err=%v)", ok, err)
	}
	// And the documented legacy hole stays visible: verdict mutation on a
	// legacy receipt does NOT break its signature (it breaks the chain hash
	// instead) — that asymmetry is exactly what V5 closes.
	r.Verdict = "DENY"
	if ok, _ := verifier.VerifyReceipt(r); !ok {
		t.Fatal("legacy preimage does not bind Verdict; verification should still pass")
	}
}

func TestReceiptUnknownVersionRejected(t *testing.T) {
	signer, err := NewEd25519Signer("unk-key")
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewEd25519Verifier(signer.PublicKeyBytes())
	if err != nil {
		t.Fatal(err)
	}
	r := v5TestReceipt()
	if err := signer.SignReceipt(r); err != nil {
		t.Fatal(err)
	}
	r.SignatureVersion = "receipt.v99"
	if ok, err := verifier.VerifyReceipt(r); err == nil || ok {
		t.Fatalf("unknown preimage version must be rejected (ok=%v err=%v)", ok, err)
	}
}
