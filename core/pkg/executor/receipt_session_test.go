package executor

import (
	"context"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

func TestSafeExecutorCreatesStandaloneV5SessionWhenInputSessionMissing(t *testing.T) {
	signer, err := crypto.NewEd25519Signer("standalone-session-key")
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Unix(1700000000, 0).UTC()
	executor := NewSafeExecutor(signer, signer, staticDriver{}, NewMemoryReceiptStore(), nil, nil, "", nil, nil, nil, func() time.Time {
		return clock
	})

	receipts := make([]*contracts.Receipt, 0, 2)
	for _, suffix := range []string{"one", "two"} {
		effect := &contracts.Effect{
			EffectID:   "effect-" + suffix,
			EffectType: "EXECUTE_TOOL",
			ArgsHash:   "args-" + suffix,
			Params:     map[string]any{"tool_name": "ls"},
		}
		decision := &contracts.DecisionRecord{
			ID:                "decision-" + suffix,
			Verdict:           string(contracts.VerdictAllow),
			ReasonCode:        "ALLOW_BY_POLICY",
			PolicyContentHash: "policy-" + suffix,
			EffectDigest:      testEffectDigest(t, effect),
		}
		if err := signer.SignDecision(decision); err != nil {
			t.Fatalf("sign decision %s: %v", suffix, err)
		}
		intent := &contracts.AuthorizedExecutionIntent{
			DecisionID:       decision.ID,
			EffectDigestHash: decision.EffectDigest,
			AllowedTool:      "ls",
			ExpiresAt:        clock.Add(time.Hour),
		}
		if err := signer.SignIntent(intent); err != nil {
			t.Fatalf("sign intent %s: %v", suffix, err)
		}
		receipt, _, err := executor.Execute(context.Background(), effect, decision, intent)
		if err != nil {
			t.Fatalf("execute %s: %v", suffix, err)
		}
		if receipt.SignatureVersion != contracts.ReceiptSignatureV5 || receipt.SessionID != standaloneReceiptSessionPrefix+decision.ID {
			t.Fatalf("missing-session receipt did not get signed standalone identity: %+v", receipt)
		}
		if valid, err := signer.VerifyReceipt(receipt); err != nil || !valid {
			t.Fatalf("standalone receipt is not verifiable: valid=%v err=%v", valid, err)
		}
		receipts = append(receipts, receipt)
	}
	if receipts[0].SessionID == receipts[1].SessionID {
		t.Fatalf("standalone receipts share a session identity: %q", receipts[0].SessionID)
	}
}
