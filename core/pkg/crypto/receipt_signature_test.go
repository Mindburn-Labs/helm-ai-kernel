package crypto

import (
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

func safeDepReceiptForSignatureTest() *contracts.Receipt {
	return &contracts.Receipt{
		ReceiptID:                    "rcpt-safe-dep-v2",
		DecisionID:                   "dec-safe-dep-v2",
		EffectID:                     "eff-safe-dep-v2",
		Status:                       "SUCCESS",
		OutputHash:                   "sha256:output",
		PrevHash:                     "sha256:previous",
		LamportClock:                 7,
		ArgsHash:                     "sha256:args",
		EmergencyActivationID:        "activation-1",
		EmergencyDelegationSessionID: "delegation-1",
		EmergencyScopeHash:           "sha256:scope",
		SafeDepState:                 string(contracts.SafeDepDegradedNarrowing),
		SafeDepReasonCode:            string(contracts.ReasonSafeDepDegradedNarrowing),
	}
}

func TestReceiptSignatureV2BindsSafeDepAuthorityEvidence(t *testing.T) {
	signer, err := NewEd25519Signer("receipt-v2")
	if err != nil {
		t.Fatal(err)
	}
	receipt := safeDepReceiptForSignatureTest()
	if err := signer.SignReceipt(receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.SignatureVersion != contracts.ReceiptSignatureVersionV2 {
		t.Fatalf("signature version = %q", receipt.SignatureVersion)
	}
	if valid, err := signer.VerifyReceipt(receipt); err != nil || !valid {
		t.Fatalf("signed receipt did not verify: valid=%v err=%v", valid, err)
	}

	tests := []struct {
		name   string
		mutate func(*contracts.Receipt)
	}{
		{name: "activation", mutate: func(r *contracts.Receipt) { r.EmergencyActivationID = "activation-tampered" }},
		{name: "delegation", mutate: func(r *contracts.Receipt) { r.EmergencyDelegationSessionID = "delegation-tampered" }},
		{name: "scope", mutate: func(r *contracts.Receipt) { r.EmergencyScopeHash = "sha256:scope-tampered" }},
		{name: "state", mutate: func(r *contracts.Receipt) { r.SafeDepState = string(contracts.SafeDepTerminalFreeze) }},
		{name: "reason", mutate: func(r *contracts.Receipt) { r.SafeDepReasonCode = string(contracts.ReasonSafeDepTerminalFreeze) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tampered := *receipt
			tt.mutate(&tampered)
			if valid, err := signer.VerifyReceipt(&tampered); err == nil && valid {
				t.Fatal("tampered SafeDep authority evidence verified")
			}
		})
	}
}

func TestReceiptSignatureV2SupportsLegacyReadWithoutDowngrade(t *testing.T) {
	signer, err := NewEd25519Signer("receipt-rollout")
	if err != nil {
		t.Fatal(err)
	}

	legacy := safeDepReceiptForSignatureTest()
	legacy.EmergencyActivationID = ""
	legacy.EmergencyDelegationSessionID = ""
	legacy.EmergencyScopeHash = ""
	legacy.SafeDepState = ""
	legacy.SafeDepReasonCode = ""
	legacyPayload := CanonicalizeReceipt(
		legacy.ReceiptID,
		legacy.DecisionID,
		legacy.EffectID,
		legacy.Status,
		legacy.OutputHash,
		legacy.PrevHash,
		legacy.LamportClock,
		legacy.ArgsHash,
	)
	legacy.Signature, err = signer.Sign([]byte(legacyPayload))
	if err != nil {
		t.Fatal(err)
	}
	if valid, err := signer.VerifyReceipt(legacy); err != nil || !valid {
		t.Fatalf("queued legacy receipt did not verify: valid=%v err=%v", valid, err)
	}
	legacyWithUnsignedEvidence := *legacy
	legacyWithUnsignedEvidence.SafeDepState = string(contracts.SafeDepDegradedNarrowing)
	if valid, err := signer.VerifyReceipt(&legacyWithUnsignedEvidence); err == nil || valid {
		t.Fatalf("legacy receipt with unsigned SafeDep evidence was not rejected: valid=%v err=%v", valid, err)
	}

	v2 := safeDepReceiptForSignatureTest()
	if err := signer.SignReceipt(v2); err != nil {
		t.Fatal(err)
	}
	downgraded := *v2
	downgraded.SignatureVersion = ""
	if valid, err := signer.VerifyReceipt(&downgraded); err == nil && valid {
		t.Fatal("v2 receipt verified after clearing its signature version")
	}

	unknown := *v2
	unknown.SignatureVersion = "helm.receipt.v99"
	if valid, err := signer.VerifyReceipt(&unknown); err == nil || valid {
		t.Fatalf("unknown receipt signature version was not rejected: valid=%v err=%v", valid, err)
	}
}

func TestReceiptSignatureV2RoundTripsPQCAndHybridProfiles(t *testing.T) {
	receipt := safeDepReceiptForSignatureTest()
	pqSigner, err := NewMLDSASigner("receipt-pq-v2")
	if err != nil {
		t.Fatal(err)
	}
	if err := pqSigner.SignReceipt(receipt); err != nil {
		t.Fatal(err)
	}
	if valid, err := pqSigner.VerifyReceipt(receipt); err != nil || !valid {
		t.Fatalf("PQC receipt did not verify: valid=%v err=%v", valid, err)
	}
	pqTampered := *receipt
	pqTampered.EmergencyScopeHash = "sha256:tampered"
	if valid, err := pqSigner.VerifyReceipt(&pqTampered); err == nil && valid {
		t.Fatal("PQC receipt accepted tampered SafeDep scope")
	}

	hybridReceipt := safeDepReceiptForSignatureTest()
	hybridSigner, err := NewHybridSigner("receipt-hybrid-v2")
	if err != nil {
		t.Fatal(err)
	}
	if err := hybridSigner.SignReceipt(hybridReceipt); err != nil {
		t.Fatal(err)
	}
	hybridVerifier, err := NewHybridVerifier(
		hybridSigner.Ed25519Signer().PublicKeyBytes(),
		hybridSigner.MLDSASigner().PublicKeyBytes(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if valid, err := hybridVerifier.VerifyReceipt(hybridReceipt); err != nil || !valid {
		t.Fatalf("hybrid receipt did not verify: valid=%v err=%v", valid, err)
	}
	hybridTampered := *hybridReceipt
	hybridTampered.SafeDepReasonCode = string(contracts.ReasonSafeDepTerminalFreeze)
	if valid, err := hybridVerifier.VerifyReceipt(&hybridTampered); err == nil && valid {
		t.Fatal("hybrid receipt accepted tampered SafeDep reason")
	}
}
