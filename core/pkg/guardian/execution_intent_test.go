package guardian

import (
	"context"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	kernelcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	pkg_sandbox "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/sandbox"
)

func TestGuardianIssuesVerifiableSandboxIntentForDefaultRuntime(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	signer, err := kernelcrypto.NewEd25519Signer("sandbox-intent-key")
	if err != nil {
		t.Fatal(err)
	}
	guardian := NewGuardian(signer, nil, nil, WithClock(&testClock{now: now}))
	effect := sandboxTimingEffect(now.Add(time.Hour), 30*time.Minute)
	digest, err := contracts.CanonicalEffectDigest(effect)
	if err != nil {
		t.Fatal(err)
	}
	decision := &contracts.DecisionRecord{
		ID:           "decision-sandbox-runtime",
		Timestamp:    now,
		Verdict:      string(contracts.VerdictAllow),
		EffectDigest: digest,
		InputContext: effect.Params,
	}
	if err := signer.SignDecision(decision); err != nil {
		t.Fatal(err)
	}
	intent, err := guardian.IssueExecutionIntent(context.Background(), decision, effect)
	if err != nil {
		t.Fatal(err)
	}
	if !intent.ExpiresAt.Equal(now.Add(35 * time.Minute)) {
		t.Fatalf("issued sandbox intent expiry=%s", intent.ExpiresAt)
	}
	if intent.EffectBinding == nil || intent.EffectBinding.EffectType != contracts.EffectTypeRunSandboxedCode {
		t.Fatal("issued sandbox intent omitted portable effect semantics")
	}
	if valid, verifyErr := signer.VerifyIntent(intent); verifyErr != nil || !valid {
		t.Fatalf("issued sandbox intent did not verify: valid=%v err=%v", valid, verifyErr)
	}
}

func TestExecutionIntentExpiryCoversSignedSandboxRuntime(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	effect := sandboxTimingEffect(now.Add(time.Hour), 30*time.Minute)

	expiresAt, err := executionIntentExpiresAt(effect, contracts.EffectTypeRunSandboxedCode, now)
	if err != nil {
		t.Fatal(err)
	}
	want := now.Add(35 * time.Minute)
	if !expiresAt.Equal(want) {
		t.Fatalf("sandbox intent expiry=%s want=%s", expiresAt, want)
	}
}

func TestExecutionIntentExpiryNeverEscapesSignedLease(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	leaseExpiry := now.Add(32 * time.Minute)
	effect := sandboxTimingEffect(leaseExpiry, 30*time.Minute)

	expiresAt, err := executionIntentExpiresAt(effect, contracts.EffectTypeRunSandboxedCode, now)
	if err != nil {
		t.Fatal(err)
	}
	if !expiresAt.Equal(leaseExpiry) {
		t.Fatalf("sandbox intent escaped or shortened lease: got=%s want=%s", expiresAt, leaseExpiry)
	}
}

func TestExecutionIntentExpiryRejectsInsufficientDispatchWindow(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	effect := sandboxTimingEffect(now.Add(30*time.Minute+500*time.Millisecond), 30*time.Minute)

	if _, err := executionIntentExpiresAt(effect, contracts.EffectTypeRunSandboxedCode, now); err == nil {
		t.Fatal("sandbox intent accepted a lease without minimum dispatch authority")
	}
}

func TestExecutionIntentExpiryRejectsExpiredLease(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	effect := sandboxTimingEffect(now.Add(-time.Hour), 30*time.Minute)

	if _, err := executionIntentExpiresAt(effect, contracts.EffectTypeRunSandboxedCode, now); err == nil {
		t.Fatal("sandbox intent accepted an expired lease")
	}
}

func TestExecutionIntentExpiryKeepsDefaultForOrdinaryEffects(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	expiresAt, err := executionIntentExpiresAt(&contracts.Effect{EffectType: contracts.EffectTypeGeneric}, contracts.EffectTypeGeneric, now)
	if err != nil {
		t.Fatal(err)
	}
	if !expiresAt.Equal(now.Add(defaultExecutionIntentTTL)) {
		t.Fatalf("ordinary intent expiry=%s", expiresAt)
	}
}

func sandboxTimingEffect(leaseExpiry time.Time, runtimeTimeout time.Duration) *contracts.Effect {
	return &contracts.Effect{
		EffectType: contracts.EffectTypeRunSandboxedCode,
		Params: map[string]any{
			"param.sandbox_execution": map[string]any{
				"lease": map[string]any{"expires_at": leaseExpiry},
				"spec": pkg_sandbox.SandboxSpec{
					Limits: pkg_sandbox.ResourceLimits{Timeout: runtimeTimeout},
				},
			},
		},
	}
}
