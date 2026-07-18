package crypto

import (
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

func TestIntentSignatureBindsExpiryAndEmergencyAuthority(t *testing.T) {
	signer, err := NewEd25519Signer("intent-test")
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	issuedAt := time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC)
	intent := &contracts.AuthorizedExecutionIntent{
		ID:                           "intent-1",
		DecisionID:                   "decision-1",
		EffectDigestHash:             "sha256:effect",
		IdempotencyKey:               "idem-1",
		IssuedAt:                     issuedAt,
		ExpiresAt:                    issuedAt.Add(5 * time.Minute),
		Signer:                       "kernel",
		AllowedTool:                  "deploy",
		Taint:                        []string{"untrusted"},
		EmergencyActivationID:        "activation-1",
		EmergencyDelegationSessionID: "session-1",
		EmergencyScopeHash:           "sha256:scope",
	}
	if err := signer.SignIntent(intent); err != nil {
		t.Fatalf("sign intent: %v", err)
	}
	if intent.SignatureVersion != contracts.IntentSignatureVersionV2 {
		t.Fatalf("signature version = %q, want %q", intent.SignatureVersion, contracts.IntentSignatureVersionV2)
	}
	verifier, err := NewEd25519Verifier(signer.PublicKeyBytes())
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	if valid, err := verifier.VerifyIntent(intent); err != nil || !valid {
		t.Fatalf("verify signed intent: valid=%v err=%v", valid, err)
	}

	mutations := []struct {
		name string
		edit func(*contracts.AuthorizedExecutionIntent)
	}{
		{"expires_at", func(i *contracts.AuthorizedExecutionIntent) { i.ExpiresAt = i.ExpiresAt.Add(time.Hour) }},
		{"issued_at", func(i *contracts.AuthorizedExecutionIntent) { i.IssuedAt = i.IssuedAt.Add(time.Minute) }},
		{"taint", func(i *contracts.AuthorizedExecutionIntent) { i.Taint = []string{"trusted"} }},
		{"emergency_activation", func(i *contracts.AuthorizedExecutionIntent) { i.EmergencyActivationID = "activation-2" }},
		{"emergency_delegation", func(i *contracts.AuthorizedExecutionIntent) { i.EmergencyDelegationSessionID = "session-2" }},
		{"emergency_scope", func(i *contracts.AuthorizedExecutionIntent) { i.EmergencyScopeHash = "sha256:other" }},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			tampered := *intent
			mutation.edit(&tampered)
			if valid, err := verifier.VerifyIntent(&tampered); err != nil || valid {
				t.Fatalf("tampered intent verified: valid=%v err=%v", valid, err)
			}
		})
	}
}

func TestIntentSignatureLegacyQueueCompatibilityIsVersionExplicit(t *testing.T) {
	signer, err := NewEd25519Signer("legacy-intent-test")
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	issuedAt := time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC)
	legacy := &contracts.AuthorizedExecutionIntent{
		ID:               "legacy-intent-1",
		DecisionID:       "legacy-decision-1",
		EffectDigestHash: "sha256:legacy-effect",
		IssuedAt:         issuedAt,
		ExpiresAt:        issuedAt.Add(5 * time.Minute),
		AllowedTool:      "deploy",
	}
	legacyPayload := CanonicalizeIntent(legacy.ID, legacy.DecisionID, legacy.AllowedTool, legacy.EffectDigestHash)
	legacy.Signature, err = signer.Sign([]byte(legacyPayload))
	if err != nil {
		t.Fatalf("sign legacy intent: %v", err)
	}
	verifier, err := NewEd25519Verifier(signer.PublicKeyBytes())
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	if valid, verifyErr := verifier.VerifyIntent(legacy); verifyErr != nil || !valid {
		t.Fatalf("queued legacy intent did not verify: valid=%v err=%v", valid, verifyErr)
	}

	v2 := *legacy
	if err := signer.SignIntent(&v2); err != nil {
		t.Fatalf("sign v2 intent: %v", err)
	}
	if valid, verifyErr := verifier.VerifyIntent(&v2); verifyErr != nil || !valid {
		t.Fatalf("v2 intent did not verify: valid=%v err=%v", valid, verifyErr)
	}
	downgraded := v2
	downgraded.SignatureVersion = ""
	if valid, verifyErr := verifier.VerifyIntent(&downgraded); verifyErr != nil || valid {
		t.Fatalf("v2 intent accepted after version downgrade: valid=%v err=%v", valid, verifyErr)
	}
	unknown := v2
	unknown.SignatureVersion = "helm.intent.v3"
	if valid, verifyErr := verifier.VerifyIntent(&unknown); verifyErr == nil || valid || !strings.Contains(verifyErr.Error(), "unsupported intent signature version") {
		t.Fatalf("unknown version did not fail closed: valid=%v err=%v", valid, verifyErr)
	}
}
