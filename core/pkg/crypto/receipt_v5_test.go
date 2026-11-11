// quantum_posture: test-only coverage of the receipt.v5 and legacy signing
// preimages under the existing Ed25519, ML-DSA-65 and hybrid signers; it adds
// no signature scheme.
package crypto

import (
	"bytes"
	"errors"
	"strconv"
	"strings"
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
// the legacy V4 preimage, for a caller that opts in: dual-verify, no
// re-signing of history. Without the opt-in they are refused, not checked
// (helm-tracker#305).
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

	if ok, err := verifier.VerifyReceipt(r); ok || !errors.Is(err, ErrLegacyReceiptRefused) {
		t.Fatalf("legacy receipt was checked without the opt-in (ok=%v err=%v)", ok, err)
	}
	if ok, err := signer.VerifyReceipt(r); ok || !errors.Is(err, ErrLegacyReceiptRefused) {
		t.Fatalf("legacy receipt was checked by its signer without the opt-in (ok=%v err=%v)", ok, err)
	}
	verifyLegacy := func() (bool, error) {
		_, ok, err := VerifyReceiptProfile(signer.PublicKey(), "", r, AllowLegacyReceiptPreimages)
		return ok, err
	}
	if ok, err := verifyLegacy(); err != nil || !ok {
		t.Fatalf("legacy receipt must keep verifying under the opt-in (ok=%v err=%v)", ok, err)
	}
	if ok, version, err := VerifyReceiptSignature(signer.PublicKey(), r, AllowLegacyReceiptPreimages); err != nil || !ok || version != ReceiptPreimageLegacy {
		t.Fatalf("legacy receipt must verify as %q under the opt-in (ok=%v version=%q err=%v)", ReceiptPreimageLegacy, ok, version, err)
	}
	if payload, err := ReceiptVerifyPayload(r, AllowLegacyReceiptPreimages); err != nil || string(payload) != legacyPayload {
		t.Fatalf("ReceiptVerifyPayload under the opt-in = %q, %v; want the legacy preimage", payload, err)
	}
	if _, err := ReceiptVerifyPayload(r); !errors.Is(err, ErrLegacyReceiptRefused) {
		t.Fatalf("ReceiptVerifyPayload without the opt-in = %v, want ErrLegacyReceiptRefused", err)
	}
	// And the documented legacy hole stays visible: verdict mutation on a
	// legacy receipt does NOT break its signature (it breaks the chain hash
	// instead) — that asymmetry is exactly what V5 closes.
	r.Verdict = "DENY"
	if ok, _ := verifyLegacy(); !ok {
		t.Fatal("legacy preimage does not bind Verdict; verification should still pass")
	}
	// A member the legacy preimage does cover still fails under the opt-in.
	r.Status = "DENIED"
	if ok, err := verifyLegacy(); ok || err != nil {
		t.Fatalf("a legacy receipt with a rewritten signed member verified under the opt-in (ok=%v err=%v)", ok, err)
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

// replayV5AsLegacy re-splits the bytes a receipt.v5 signature covers into the
// eight colon-joined fields of the legacy preimage and returns an unversioned
// receipt that carries the same signature and claims ALLOW. It needs a
// colon-delimited integer in the signed bytes to stand in for lamport_clock; a
// gateway session_id has one.
func replayV5AsLegacy(t *testing.T, signed *contracts.Receipt) *contracts.Receipt {
	t.Helper()
	payload, err := CanonicalizeReceiptV5(signed)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(string(payload), SigSeparator)
	for i := 6; i < len(parts)-1; i++ {
		clock, err := strconv.ParseUint(parts[i], 10, 64)
		if err != nil || strconv.FormatUint(clock, 10) != parts[i] {
			continue
		}
		forged := &contracts.Receipt{
			ReceiptID:    parts[0],
			DecisionID:   parts[1],
			EffectID:     parts[2],
			Status:       parts[3],
			OutputHash:   parts[4],
			PrevHash:     strings.Join(parts[5:i], SigSeparator),
			LamportClock: clock,
			ArgsHash:     strings.Join(parts[i+1:], SigSeparator),
			Verdict:      "ALLOW",
			ToolName:     "payments.transfer",
			Signature:    signed.Signature,
			// Profile metadata is outside both preimages, so the forger
			// copies whatever routes the signature to its own algorithm.
			SignatureProfile:   signed.SignatureProfile,
			SignatureAlgorithm: signed.SignatureAlgorithm,
		}
		if !bytes.Equal(ReceiptPreimageV4(forged), payload) {
			t.Fatal("the planted receipt is not a legacy reading of the signed receipt.v5 bytes; the case proves nothing")
		}
		return forged
	}
	t.Fatal("the signed receipt.v5 bytes hold no colon-delimited integer to stand in for lamport_clock; the case proves nothing")
	return nil
}

// legacyRefused asserts a verifier's answer to an unversioned receipt it was
// not asked to accept: not valid, with an error that says the receipt is
// legacy and names the member it lacks.
func legacyRefused(t *testing.T, path string, valid bool, err error) {
	t.Helper()
	if valid {
		t.Fatalf("%s: a receipt with no signature_version verified without an opt-in", path)
	}
	if err == nil || !strings.Contains(err.Error(), "legacy") || !strings.Contains(err.Error(), "signature_version") {
		t.Fatalf("%s: the refusal must say the receipt is legacy and has no signature_version, got: %v", path, err)
	}
	if !errors.Is(err, ErrLegacyReceiptRefused) {
		t.Fatalf("%s: the refusal must be ErrLegacyReceiptRefused, so a caller can report \"not checked\": %v", path, err)
	}
}

// TestReceiptV5SignatureDoesNotReplayAsLegacy is helm-tracker#305 defect B in
// this package. The legacy preimage is eight fields joined with ":" with no
// escaping and no domain separation, so the JCS bytes of a signed receipt.v5
// DENY can be read back as those eight fields: the same signature then
// verifies for an unversioned receipt that says ALLOW. No key is needed. Every
// receipt verifier here must refuse the unversioned receipt by default, under
// each signature profile.
func TestReceiptV5SignatureDoesNotReplayAsLegacy(t *testing.T) {
	denial := func() *contracts.Receipt {
		r := v5TestReceipt()
		r.Status, r.Verdict, r.ReasonCode = "DENIED", "DENY", "MANDATE_LIMIT_EXCEEDED"
		r.SessionID = "helm-gateway:8:tenant-a:4:ws-a"
		return r
	}
	ed, err := NewEd25519Signer("replay-ed25519")
	if err != nil {
		t.Fatal(err)
	}
	mldsa, err := NewMLDSASigner("replay-mldsa")
	if err != nil {
		t.Fatal(err)
	}
	hybrid, err := NewHybridSignerFromSigners(ed, mldsa, "replay-hybrid")
	if err != nil {
		t.Fatal(err)
	}
	edVerifier, err := NewEd25519Verifier(ed.PublicKeyBytes())
	if err != nil {
		t.Fatal(err)
	}
	mldsaVerifier, err := NewMLDSAVerifier(mldsa.PublicKeyBytes())
	if err != nil {
		t.Fatal(err)
	}
	hybridVerifier, err := NewHybridVerifier(ed.PublicKeyBytes(), mldsa.PublicKeyBytes())
	if err != nil {
		t.Fatal(err)
	}
	ring := NewKeyRing()
	ring.AddKey(ed)
	ring.AddKey(mldsa)
	ring.AddKey(hybrid)

	for name, tc := range map[string]struct {
		signer    Signer
		edPub     string
		mldsaPub  string
		verifiers map[string]func(*contracts.Receipt) (bool, error)
	}{
		"classical": {ed, ed.PublicKey(), "", map[string]func(*contracts.Receipt) (bool, error){
			"Ed25519Signer.VerifyReceipt":   ed.VerifyReceipt,
			"Ed25519Verifier.VerifyReceipt": edVerifier.VerifyReceipt,
			"VerifyReceiptSignature": func(r *contracts.Receipt) (bool, error) {
				ok, _, err := VerifyReceiptSignature(ed.PublicKey(), r)
				return ok, err
			},
		}},
		"pqc": {mldsa, "", mldsa.PublicKey(), map[string]func(*contracts.Receipt) (bool, error){
			"MLDSASigner.VerifyReceipt":   mldsa.VerifyReceipt,
			"MLDSAVerifier.VerifyReceipt": mldsaVerifier.VerifyReceipt,
		}},
		"hybrid": {hybrid, ed.PublicKey(), mldsa.PublicKey(), map[string]func(*contracts.Receipt) (bool, error){
			"HybridVerifier.VerifyReceipt": hybridVerifier.VerifyReceipt,
		}},
	} {
		t.Run(name, func(t *testing.T) {
			genuine := denial()
			if err := tc.signer.SignReceipt(genuine); err != nil {
				t.Fatal(err)
			}
			if _, valid, err := VerifyReceiptProfile(tc.edPub, tc.mldsaPub, genuine); err != nil || !valid {
				t.Fatalf("the genuine receipt.v5 DENY does not verify; the case proves nothing (valid=%v err=%v)", valid, err)
			}
			forged := replayV5AsLegacy(t, genuine)

			_, valid, err := VerifyReceiptProfile(tc.edPub, tc.mldsaPub, forged)
			legacyRefused(t, "VerifyReceiptProfile", valid, err)
			_, valid, err = VerifyReceiptRequiredProfile(tc.edPub, tc.mldsaPub, forged, "")
			legacyRefused(t, "VerifyReceiptRequiredProfile", valid, err)
			if valid, err := ring.VerifyReceipt(forged); valid || err == nil {
				t.Fatalf("KeyRing.VerifyReceipt verified a receipt.v5 signature replayed as a legacy ALLOW (valid=%v err=%v)", valid, err)
			}
			for path, verify := range tc.verifiers {
				valid, err := verify(forged)
				legacyRefused(t, path, valid, err)
			}
			// What the opt-in accepts, and so why it is not the default: the
			// replay verifies under it.
			if _, valid, err := VerifyReceiptProfile(tc.edPub, tc.mldsaPub, forged, AllowLegacyReceiptPreimages); err != nil || !valid {
				t.Fatalf("the legacy preimage has no domain separation, so the replay is expected to verify under the opt-in (valid=%v err=%v)", valid, err)
			}
		})
	}
}
