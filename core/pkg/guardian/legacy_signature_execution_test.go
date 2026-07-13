package guardian

import (
	"context"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

func TestIssueExecutionIntentRejectsActionMutableLegacyV1Decision(t *testing.T) {
	t.Parallel()

	signer, err := crypto.NewEd25519Signer("legacy-intent")
	if err != nil {
		t.Fatalf("NewEd25519Signer: %v", err)
	}
	effect := &contracts.Effect{
		EffectID:   "effect-destructive",
		EffectType: "EXECUTE_TOOL",
		Params:     map[string]any{"tool_name": "production.deployer", "target": "production"},
	}
	digest, err := canonicalEffectDigest(effect)
	if err != nil {
		t.Fatalf("canonicalEffectDigest: %v", err)
	}
	decision := &contracts.DecisionRecord{
		ID:                "legacy-action-mutation",
		SubjectID:         "principal:alice",
		Action:            "DELETE_PRODUCTION",
		Resource:          "production.deployer",
		Verdict:           string(contracts.VerdictAllow),
		Reason:            "legacy allow",
		PhenotypeHash:     "sha256:phenotype",
		PolicyContentHash: "sha256:policy",
		EffectDigest:      digest,
	}
	decision.Signature, err = signer.Sign([]byte(crypto.CanonicalizeDecision(
		decision.ID,
		decision.Verdict,
		decision.Reason,
		decision.PhenotypeHash,
		decision.PolicyContentHash,
		decision.EffectDigest,
	)))
	if err != nil {
		t.Fatalf("sign legacy decision: %v", err)
	}

	// The v1 preimage omits Action. A legacy verifier still accepts this
	// tampered record for audit/migration, which is why executable paths must
	// reject it before intent issuance.
	decision.Action = "read_status"
	valid, err := signer.VerifyDecision(decision)
	if err != nil || !valid {
		t.Fatalf("legacy decision should remain audit-verifiable: %v, %v", valid, err)
	}

	_, err = NewGuardian(signer, nil, nil).IssueExecutionIntent(context.Background(), decision, effect)
	if err == nil || !strings.Contains(err.Error(), "audit-only") {
		t.Fatalf("legacy action-mutable decision reached intent issuance: %v", err)
	}
}
