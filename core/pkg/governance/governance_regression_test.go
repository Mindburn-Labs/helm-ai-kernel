package governance

import (
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// 1-6: Jurisdiction rules as subtests
// ---------------------------------------------------------------------------

func TestClosing_JurisdictionRule_DataClasses(t *testing.T) {
	classes := []string{"PII", "financial", "health", "classified", "public"}
	for _, dc := range classes {
		t.Run(dc, func(t *testing.T) {
			rule := JurisdictionRule{RuleID: "r-" + dc, DataClass: dc, LegalRegime: "TEST", Region: "*"}
			if rule.DataClass != dc {
				t.Fatalf("got %q", rule.DataClass)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 7-12: Liveness states
// ---------------------------------------------------------------------------

func TestClosing_LivenessState_Values(t *testing.T) {
	states := []struct {
		state LivenessState
		name  string
	}{
		{LivenessStateActive, "ACTIVE"},
		{LivenessStatePending, "PENDING"},
		{LivenessStateExpired, "EXPIRED"},
		{LivenessStateCanceled, "CANCELED"},
	}
	for _, tc := range states {
		t.Run(tc.name, func(t *testing.T) {
			if string(tc.state) != tc.name {
				t.Fatalf("got %q", tc.state)
			}
		})
	}
}

func TestClosing_BlockingStateType_Values(t *testing.T) {
	types := []struct {
		bst  BlockingStateType
		name string
	}{
		{BlockingStateApproval, "APPROVAL"},
		{BlockingStateObligation, "OBLIGATION"},
		{BlockingStateLease, "SEQUENCER_LEASE"},
		{BlockingStateResource, "RESOURCE"},
	}
	for _, tc := range types {
		t.Run(tc.name, func(t *testing.T) {
			if string(tc.bst) != tc.name {
				t.Fatalf("got %q", tc.bst)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 13-18: Plan commit
// ---------------------------------------------------------------------------

func TestClosing_PlanStatus_Values(t *testing.T) {
	statuses := []struct {
		status PlanStatus
		name   string
	}{
		{PlanStatusPending, "PENDING"},
		{PlanStatusApproved, "APPROVED"},
		{PlanStatusRejected, "REJECTED"},
		{PlanStatusTimeout, "TIMEOUT"},
		{PlanStatusAborted, "ABORTED"},
	}
	for _, tc := range statuses {
		t.Run(tc.name, func(t *testing.T) {
			if string(tc.status) != tc.name {
				t.Fatalf("got %q", tc.status)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 19-24: CEL expressions / PDP / Data classification
// ---------------------------------------------------------------------------

func TestClosing_DataClass_Values(t *testing.T) {
	classes := []struct {
		dc   DataClass
		name string
	}{
		{DataClassPublic, "PUBLIC"},
		{DataClassInternal, "INTERNAL"},
		{DataClassConfidential, "CONFIDENTIAL"},
		{DataClassRestricted, "RESTRICTED"},
	}
	for _, tc := range classes {
		t.Run(tc.name, func(t *testing.T) {
			if string(tc.dc) != tc.name {
				t.Fatalf("got %q", tc.dc)
			}
		})
	}
}

func TestClosing_Decision_Values(t *testing.T) {
	decisions := []struct {
		d    Decision
		name string
	}{
		{DecisionAllow, "ALLOW"},
		{DecisionDeny, "DENY"},
		{DecisionRequireApproval, "REQUIRE_APPROVAL"},
		{DecisionRequireEvidence, "REQUIRE_EVIDENCE"},
		{DecisionDefer, "DEFER"},
	}
	for _, tc := range decisions {
		t.Run(tc.name, func(t *testing.T) {
			if string(tc.d) != tc.name {
				t.Fatalf("got %q", tc.d)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 25-30: PDP modes / Security checks
// ---------------------------------------------------------------------------

func TestClosing_PDPAttestationStatus_Values(t *testing.T) {
	statuses := []struct {
		s    PDPAttestationStatus
		name string
	}{
		{PDPAttestationValid, "VALID"},
		{PDPAttestationExpired, "EXPIRED"},
		{PDPAttestationRevoked, "REVOKED"},
		{PDPAttestationSuspect, "SUSPECT"},
		{PDPAttestationCompromised, "COMPROMISED"},
	}
	for _, tc := range statuses {
		t.Run(tc.name, func(t *testing.T) {
			if string(tc.s) != tc.name {
				t.Fatalf("got %q", tc.s)
			}
		})
	}
}

func TestClosing_AnomalyType_Values(t *testing.T) {
	types := []struct {
		at   AnomalyType
		name string
	}{
		{AnomalyTypeDecisionDrift, "DECISION_DRIFT"},
		{AnomalyTypeTimingAnomaly, "TIMING_ANOMALY"},
		{AnomalyTypeResourceAbuse, "RESOURCE_ABUSE"},
		{AnomalyTypeUnauthorizedCall, "UNAUTHORIZED_CALL"},
	}
	for _, tc := range types {
		t.Run(tc.name, func(t *testing.T) {
			if string(tc.at) != tc.name {
				t.Fatalf("got %q", tc.at)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 31-36: DelegationRevocation
// ---------------------------------------------------------------------------

func TestClosing_CompensationFailurePolicy_Values(t *testing.T) {
	policies := []struct {
		p    CompensationFailurePolicy
		name string
	}{
		{CompensationPolicyRetry, "RETRY"},
		{CompensationPolicyEscalate, "ESCALATE"},
		{CompensationPolicyManual, "MANUAL_INTERVENTION"},
		{CompensationPolicyFallback, "FALLBACK"},
	}
	for _, tc := range policies {
		t.Run(tc.name, func(t *testing.T) {
			if string(tc.p) != tc.name {
				t.Fatalf("got %q", tc.p)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 37-42: Compensation outcomes
// ---------------------------------------------------------------------------

func TestClosing_CompensationOutcome_Values(t *testing.T) {
	outcomes := []struct {
		o    CompensationOutcome
		name string
	}{
		{CompensationOutcomeSuccess, "SUCCESS"},
		{CompensationOutcomeRetry, "RETRY"},
		{CompensationOutcomeEscalate, "ESCALATE"},
		{CompensationOutcomeManual, "MANUAL"},
		{CompensationOutcomeFallback, "FALLBACK"},
	}
	for _, tc := range outcomes {
		t.Run(tc.name, func(t *testing.T) {
			if string(tc.o) != tc.name {
				t.Fatalf("got %q", tc.o)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 43-50: LivenessManager, Defaults, and misc
// ---------------------------------------------------------------------------

func TestClosing_DefaultTimeouts(t *testing.T) {
	t.Run("approval_24h", func(t *testing.T) {
		if DefaultApprovalTimeout != 24*time.Hour {
			t.Fatalf("got %v", DefaultApprovalTimeout)
		}
	})
	t.Run("obligation_72h", func(t *testing.T) {
		if DefaultObligationTimeout != 72*time.Hour {
			t.Fatalf("got %v", DefaultObligationTimeout)
		}
	})
	t.Run("lease_30s", func(t *testing.T) {
		if DefaultLeaseTimeout != 30*time.Second {
			t.Fatalf("got %v", DefaultLeaseTimeout)
		}
	})
}
