package executor

import (
	"context"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

// recordingSigner captures the receipt exactly as it is handed to the signer.
// The point of interest is that instant: a receipt that declares receipt.v5 but
// reaches the signer with empty governance fields authenticates blank strings,
// so the signature is valid and attests nothing.
type recordingSigner struct {
	crypto.Signer
	signed *contracts.Receipt
}

func (s *recordingSigner) SignReceipt(r *contracts.Receipt) error {
	snapshot := *r
	s.signed = &snapshot
	return s.Signer.SignReceipt(r)
}

// The main execution path must populate the fields the V5 preimage binds before
// signing, not after — and not at all was the shipped behaviour.
func TestSafeExecutor_BindsGovernanceFieldsBeforeSigning(t *testing.T) {
	inner, err := crypto.NewEd25519Signer("governance-binding-key")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	signer := &recordingSigner{Signer: inner}
	driver := &MockDriver{}
	executor := NewSafeExecutor(inner, signer, driver, NewMemoryReceiptStore(), nil, nil, "", nil, nil, nil, nil)

	effect := &contracts.Effect{EffectID: "eff-gov", Params: map[string]any{"tool_name": "ls"}}
	decision := &contracts.DecisionRecord{
		ID:                "dec-gov",
		Verdict:           string(contracts.VerdictAllow),
		Reason:            "within policy",
		ReasonCode:        string(contracts.ReasonPolicyViolation),
		PolicyContentHash: "sha256:policy-under-test",
		EffectDigest:      testEffectDigest(t, effect),
		InputContext:      map[string]any{"session_id": "sess-gov"},
	}
	if err := inner.SignDecision(decision); err != nil {
		t.Fatalf("sign decision: %v", err)
	}
	intent := &contracts.AuthorizedExecutionIntent{
		DecisionID:       decision.ID,
		EffectDigestHash: decision.EffectDigest,
		ExpiresAt:        time.Now().Add(time.Hour),
	}
	if err := inner.SignIntent(intent); err != nil {
		t.Fatalf("sign intent: %v", err)
	}

	receipt, _, err := executor.Execute(context.Background(), effect, decision, intent)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if signer.signed == nil {
		t.Fatal("the executor never signed a receipt")
	}

	// Every field the V5 preimage binds must carry its claim at signing time.
	for _, field := range []struct{ name, got, want string }{
		{"verdict", signer.signed.Verdict, decision.Verdict},
		{"reason_code", signer.signed.ReasonCode, decision.ReasonCode},
		{"policy_hash", signer.signed.PolicyHash, decision.PolicyContentHash},
		{"session_id", signer.signed.SessionID, "sess-gov"},
	} {
		if field.got == "" {
			t.Errorf("%s was empty when the receipt was signed — receipt.v5 would authenticate a blank string", field.name)
			continue
		}
		if field.got != field.want {
			t.Errorf("%s = %q at signing time, want %q", field.name, field.got, field.want)
		}
	}

	// And the emitted receipt must actually verify under the version it declares.
	if receipt.SignatureVersion != contracts.ReceiptSignatureV5 {
		t.Fatalf("receipt declares %q, want %q", receipt.SignatureVersion, contracts.ReceiptSignatureV5)
	}
	ok, err := inner.VerifyReceipt(receipt)
	if err != nil || !ok {
		t.Fatalf("executor receipt does not verify (ok=%v err=%v)", ok, err)
	}

	// Rewriting the governance claim on the emitted receipt must break it.
	receipt.Verdict = string(contracts.VerdictDeny)
	if ok, _ := inner.VerifyReceipt(receipt); ok {
		t.Fatal("verdict rewritten on an executor receipt still verifies — the binding is decorative")
	}
}
