package crypto

import (
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

func v5TestReceipt() *contracts.Receipt {
	return &contracts.Receipt{
		ReceiptID:  "rcpt-1",
		DecisionID: "dec-1",
		EffectID:   "eff-1",
		Status:     "EXECUTED",
		OutputHash: "sha256:out",
		PrevHash:   "sha256:prev",
		LamportClock: 7,
		ArgsHash:   "sha256:args",
		Verdict:    "ALLOW",
		ReasonCode: "POLICY_ALLOW",
		PolicyHash: "sha256:policy",
		SessionID:  "sess-1",
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
