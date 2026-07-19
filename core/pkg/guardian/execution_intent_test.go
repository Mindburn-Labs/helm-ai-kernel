package guardian

import (
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	pkg_sandbox "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/sandbox"
)

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
