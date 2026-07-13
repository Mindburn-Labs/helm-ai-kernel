package executor

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/safedep"
)

func TestSafeExecutorRejectsActionMutableLegacyV1BeforeSafeDepOrDispatch(t *testing.T) {
	t.Parallel()

	signer, err := crypto.NewEd25519Signer("legacy-execution")
	if err != nil {
		t.Fatalf("NewEd25519Signer: %v", err)
	}
	effect := &contracts.Effect{
		EffectID:   "effect-destructive",
		EffectType: "EXECUTE_TOOL",
		Params:     map[string]any{"tool_name": "production.deployer", "target": "production"},
	}
	decision := &contracts.DecisionRecord{
		ID:                "legacy-execution-action-mutation",
		SubjectID:         "principal:alice",
		Action:            "DELETE_PRODUCTION",
		Resource:          "production.deployer",
		Verdict:           string(contracts.VerdictAllow),
		Reason:            "legacy allow",
		PhenotypeHash:     "sha256:phenotype",
		PolicyContentHash: "sha256:policy",
		EffectDigest:      testEffectDigest(t, effect),
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

	// The v1 preimage omits Action. Its mutation remains audit-verifiable, so
	// the executable boundary must stop it before SafeDep can narrow it to a
	// read-only action or the tool driver can dispatch it.
	decision.Action = "read_status"
	valid, err := signer.VerifyDecision(decision)
	if err != nil || !valid {
		t.Fatalf("legacy decision should remain audit-verifiable: %v, %v", valid, err)
	}
	intent := executableTestIntent(decision, effect, time.Now())
	intent.ID = "intent-legacy-execution-action-mutation"
	if err := signer.SignIntent(intent); err != nil {
		t.Fatalf("SignIntent: %v", err)
	}

	mockDriver := &MockDriver{}
	gateCalled := false
	executor := NewSafeExecutor(signer, signer, mockDriver, NewMemoryReceiptStore(), nil, nil, "", nil, nil, nil, nil).
		WithSafeDepAuthorityResolver(safedep.AuthorityResolverFunc(noHazardSafeDepResolver)).
		WithSafeDepGate(safeDepGateFunc(func(context.Context, safedep.GateRequest) (safedep.GateResult, error) {
			gateCalled = true
			return safedep.GateResult{DispatchAllowed: true}, nil
		}))

	_, _, err = executor.Execute(context.Background(), effect, decision, intent)
	if err == nil || !strings.Contains(err.Error(), "audit-only") {
		t.Fatalf("legacy action-mutable decision reached executable path: %v", err)
	}
	if gateCalled {
		t.Fatal("SafeDep gate observed a legacy action-mutable decision")
	}
	if mockDriver.Called {
		t.Fatal("tool driver dispatched a legacy action-mutable decision")
	}
}
