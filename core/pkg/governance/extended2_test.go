package governance

import (
	"testing"
)

// ─── 1: PolicyEngine load and list ───────────────────────────────

// ─── 2: PolicyEngine evaluate allow ──────────────────────────────

// ─── 3: PolicyEngine evaluate deny ───────────────────────────────

// ─── 4: PolicyEngine missing policy defaults deny ────────────────

// ─── 5: PolicyEngine no policy ID defaults deny ─────────────────

// ─── 6: PolicyEngine compile error rejected ──────────────────────

// ─── 7: DelegationRevocationList revoke and check ────────────────

// ─── 8: DelegationRevocationList double revoke error ─────────────

// ─── 9: PDPAttestation mark suspect ──────────────────────────────

// ─── 10: CompromiseDetector fail-closed for suspect PDP ──────────

// ─── 11: CompromiseDetector below threshold stays valid ──────────

// ─── 12: CompromiseDetector unknown PDP returns expired ──────────

// ─── 13: Compensation escalate on max attempts ──────────────────

// ─── 14: Compensation success on first attempt ──────────────────

// ─── 15: Compensation fallback policy ────────────────────────────

// ─── 16: Compensation NeedsIntervention ──────────────────────────

// ─── 17: Arbitrate STRICTEST_WINS escalate trumps allow ─────────

// ─── 18: Arbitrate PRIORITY_ORDERED highest priority wins ────────

// ─── 19: Arbitrate MOST_SPECIFIC agent beats global ──────────────

// ─── 20: Arbitrate single input returns nil ──────────────────────

// ─── 21: EvolutionGovernance C0 auto-approve ─────────────────────

// ─── 22: EvolutionGovernance C1 reject on test failure ───────────

// ─── 23: EvolutionGovernance C2 requires verification ────────────

// ─── 24: EvolutionGovernance C3 always blocked ───────────────────

// ─── 25: Canary default config ───────────────────────────────────

func TestExt2_CanaryDefaultConfig(t *testing.T) {
	if DefaultCanary.Steps != 3 || DefaultCanary.StepDurationSec != 300 {
		t.Fatalf("unexpected default canary: steps=%d dur=%d", DefaultCanary.Steps, DefaultCanary.StepDurationSec)
	}
}

// ─── 26: Canary fast config ─────────────────────────────────────

func TestExt2_CanaryFastConfig(t *testing.T) {
	if FastCanary.Steps != 1 || FastCanary.StepDurationSec != 30 {
		t.Fatalf("unexpected fast canary: steps=%d dur=%d", FastCanary.Steps, FastCanary.StepDurationSec)
	}
}

// ─── 27: Data classifier detects PII email ───────────────────────

// ─── 28: Data classifier detects private key ─────────────────────

// ─── 29: Data classifier defaults to internal ────────────────────

// ─── 30: CEL PDP fail-closed on cancelled context ────────────────
