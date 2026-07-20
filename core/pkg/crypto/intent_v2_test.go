package crypto

import (
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

func TestExecutionIntentV2BindsCompleteAuthority(t *testing.T) {
	signer, err := NewEd25519Signer("intent-v2-key")
	if err != nil {
		t.Fatal(err)
	}

	mutations := map[string]func(*contracts.AuthorizedExecutionIntent){
		"issued_at":       func(intent *contracts.AuthorizedExecutionIntent) { intent.IssuedAt = intent.IssuedAt.Add(time.Second) },
		"expires_at":      func(intent *contracts.AuthorizedExecutionIntent) { intent.ExpiresAt = intent.ExpiresAt.Add(time.Hour) },
		"signer":          func(intent *contracts.AuthorizedExecutionIntent) { intent.Signer = "substituted" },
		"signature_type":  func(intent *contracts.AuthorizedExecutionIntent) { intent.SignatureType = "substituted:key" },
		"idempotency_key": func(intent *contracts.AuthorizedExecutionIntent) { intent.IdempotencyKey = "substituted" },
		"taint":           func(intent *contracts.AuthorizedExecutionIntent) { intent.Taint = append(intent.Taint, "secret") },
		"effect_binding": func(intent *contracts.AuthorizedExecutionIntent) {
			intent.EffectBinding.Params = map[string]any{"command": []string{"/bin/substituted"}}
		},
		"emergency_scope": func(intent *contracts.AuthorizedExecutionIntent) { intent.EmergencyScopeHash = "sha256:substituted" },
	}

	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			intent := completeIntentV2Fixture(t)
			if err := signer.SignIntent(intent); err != nil {
				t.Fatal(err)
			}
			if intent.SignatureVersion != contracts.AuthorizedExecutionIntentSignatureV2 {
				t.Fatalf("signer emitted version %q", intent.SignatureVersion)
			}
			if valid, verifyErr := signer.VerifyIntent(intent); verifyErr != nil || !valid {
				t.Fatalf("fresh V2 intent did not verify: valid=%v err=%v", valid, verifyErr)
			}

			mutate(intent)
			if valid, verifyErr := signer.VerifyIntent(intent); verifyErr == nil && valid {
				t.Fatalf("V2 signature accepted %s mutation", name)
			}
		})
	}
}

func TestExecutionIntentLegacyVerificationIsRejected(t *testing.T) {
	signer, err := NewEd25519Signer("legacy-intent-key")
	if err != nil {
		t.Fatal(err)
	}
	intent := &contracts.AuthorizedExecutionIntent{
		ID:               "intent-legacy",
		DecisionID:       "decision-legacy",
		AllowedTool:      contracts.EffectTypeGeneric,
		EffectDigestHash: "sha256:legacy",
	}
	payload := CanonicalizeIntent(intent.ID, intent.DecisionID, intent.AllowedTool, intent.EffectDigestHash)
	intent.Signature, err = signer.Sign([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if valid, verifyErr := signer.VerifyIntent(intent); verifyErr == nil || valid {
		t.Fatalf("legacy intent retained execution authority: valid=%v err=%v", valid, verifyErr)
	}
}

func completeIntentV2Fixture(t *testing.T) *contracts.AuthorizedExecutionIntent {
	t.Helper()
	binding := &contracts.EffectDigestBinding{
		EffectType:     contracts.EffectTypeRunSandboxedCode,
		Params:         map[string]any{"command": []string{"/bin/example"}},
		IdempotencyKey: "mission:step:1",
		Taint:          []string{"untrusted"},
	}
	digest, err := contracts.CanonicalEffectDigestFromBinding(binding)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	return &contracts.AuthorizedExecutionIntent{
		ID:                           "intent-v2",
		DecisionID:                   "decision-v2",
		EffectDigestHash:             digest,
		EffectBinding:                binding,
		IdempotencyKey:               binding.IdempotencyKey,
		IssuedAt:                     now,
		ExpiresAt:                    now.Add(35 * time.Minute),
		Signer:                       "kernel",
		AllowedTool:                  binding.EffectType,
		Taint:                        append([]string(nil), binding.Taint...),
		EmergencyActivationID:        "activation-1",
		EmergencyDelegationSessionID: "delegation-1",
		EmergencyScopeHash:           "sha256:scope",
	}
}
