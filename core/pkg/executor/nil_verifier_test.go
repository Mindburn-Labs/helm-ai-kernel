package executor

// Regression: an executor with no signature verifier must refuse to execute,
// not panic.
//
// validateGating called e.verifier.VerifyDecision directly. With a nil verifier
// that is a nil-interface dereference, so a SafeExecutor constructed without one
// crashed on the enforcement path instead of denying. A panic is not a safe
// failure mode here: recovered upstream it reads as a transient fault rather
// than a blocked execution, and it produces no decision record.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

func TestExecuteFailsClosedWithoutVerifier(t *testing.T) {
	exec := NewSafeExecutor(
		nil, // no verifier
		nil, nil, nil, nil, nil, "", nil, nil, nil, time.Now,
	)

	effect := &contracts.Effect{EffectID: "eff-1", EffectType: "tool.call"}
	// Bind the effect digest on both sides so gating reaches the verifier call
	// rather than stopping at the earlier digest checks — otherwise this test
	// would pass without ever exercising the guard.
	digest, err := canonicalEffectDigest(effect)
	if err != nil {
		t.Fatalf("canonicalEffectDigest: %v", err)
	}
	decision := &contracts.DecisionRecord{
		ID:           "dec-1",
		Verdict:      string(contracts.VerdictAllow),
		EffectDigest: digest,
	}
	intent := &contracts.AuthorizedExecutionIntent{
		DecisionID:       "dec-1",
		EffectDigestHash: digest,
		ExpiresAt:        time.Now().Add(time.Hour),
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Execute panicked with a nil verifier instead of failing closed: %v", r)
		}
	}()

	receipt, artifact, execErr := exec.Execute(context.Background(), effect, decision, intent)

	if execErr == nil {
		t.Fatal("an executor with no verifier accepted an execution")
	}
	if !strings.Contains(execErr.Error(), "verifier") {
		t.Fatalf("error should name the missing verifier, got: %v", execErr)
	}
	if receipt != nil || artifact != nil {
		t.Fatalf("an ungated execution returned receipt=%v artifact=%v", receipt, artifact)
	}
}

// A typed-nil verifier — an interface holding a nil *Ed25519Verifier — is not
// caught by `== nil`, so it used to reach the method call and panic on the nil
// receiver.
//
// Reaching it takes a signature that survives the earlier checks: an empty
// signature returns early, and a short one is rejected by the length check. A
// full-length signature gets through both and dereferences the receiver — which
// is precisely the shape an attacker supplies, so the earlier guards created a
// false impression that nil was handled.
func TestExecuteFailsClosedWithTypedNilVerifier(t *testing.T) {
	var typedNil *crypto.Ed25519Verifier
	exec := NewSafeExecutor(typedNil, nil, nil, nil, nil, nil, "", nil, nil, nil, time.Now)

	effect := &contracts.Effect{EffectID: "eff-1", EffectType: "tool.call"}
	digest, err := canonicalEffectDigest(effect)
	if err != nil {
		t.Fatalf("canonicalEffectDigest: %v", err)
	}
	decision := &contracts.DecisionRecord{
		ID: "dec-1", Verdict: string(contracts.VerdictAllow),
		EffectDigest: digest, Signature: strings.Repeat("ab", 64),
	}
	intent := &contracts.AuthorizedExecutionIntent{
		DecisionID: "dec-1", EffectDigestHash: digest,
		ExpiresAt: time.Now().Add(time.Hour), Signature: strings.Repeat("cd", 64),
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("a typed-nil verifier panicked instead of failing closed: %v", r)
		}
	}()

	receipt, artifact, execErr := exec.Execute(context.Background(), effect, decision, intent)
	if execErr == nil {
		t.Fatal("a typed-nil verifier accepted an execution")
	}
	if !strings.Contains(execErr.Error(), "verifier") {
		t.Fatalf("error should name the missing verifier, got: %v", execErr)
	}
	if receipt != nil || artifact != nil {
		t.Fatalf("ungated execution returned receipt=%v artifact=%v", receipt, artifact)
	}
}
