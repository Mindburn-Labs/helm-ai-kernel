package governance

import (
	"context"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// 1-6: Jurisdiction rules as subtests
// ---------------------------------------------------------------------------

func TestClosing_JurisdictionResolver_BasicResolve(t *testing.T) {
	r := NewJurisdictionResolver()
	r.AddRule(JurisdictionRule{RuleID: "r1", LegalRegime: "EU/GDPR", Region: "EU", Priority: 1})
	t.Run("resolves_EU", func(t *testing.T) {
		ctx, err := r.Resolve("entity1", "cp1", "ds1", "EU")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ctx.LegalRegime != "EU/GDPR" {
			t.Fatalf("got %q", ctx.LegalRegime)
		}
	})
	t.Run("missing_region_errors", func(t *testing.T) {
		_, err := r.Resolve("entity1", "", "", "JP")
		if err == nil {
			t.Fatal("expected error for unknown region")
		}
	})
	t.Run("empty_entity_errors", func(t *testing.T) {
		_, err := r.Resolve("", "", "", "EU")
		if err == nil {
			t.Fatal("expected error for empty entity")
		}
	})
	t.Run("context_id_set", func(t *testing.T) {
		ctx, _ := r.Resolve("e", "", "", "EU")
		if ctx.ContextID == "" {
			t.Fatal("context ID should be set")
		}
	})
}

func TestClosing_JurisdictionResolver_WildcardRegion(t *testing.T) {
	r := NewJurisdictionResolver()
	r.AddRule(JurisdictionRule{RuleID: "global", LegalRegime: "GLOBAL", Region: "*", Priority: 0})
	regions := []string{"US", "EU", "JP", "BR", "IN"}
	for _, region := range regions {
		t.Run(region, func(t *testing.T) {
			ctx, err := r.Resolve("entity", "", "", region)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if ctx.LegalRegime != "GLOBAL" {
				t.Fatalf("got %q", ctx.LegalRegime)
			}
		})
	}
}

func TestClosing_JurisdictionResolver_Conflicts(t *testing.T) {
	r := NewJurisdictionResolver()
	r.AddRule(JurisdictionRule{RuleID: "r1", LegalRegime: "EU/GDPR", Region: "EU", Priority: 1})
	r.AddRule(JurisdictionRule{RuleID: "r2", LegalRegime: "UK/FCA", Region: "EU", Priority: 1})
	ctx, err := r.Resolve("entity", "", "", "EU")
	t.Run("resolves_without_error", func(t *testing.T) {
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("has_conflicts", func(t *testing.T) {
		if len(ctx.Conflicts) == 0 {
			t.Fatal("expected conflicts")
		}
	})
	t.Run("regime_empty_on_equal_priority_conflict", func(t *testing.T) {
		if ctx.LegalRegime != "" {
			t.Fatalf("expected empty regime for equal-priority conflict, got %q", ctx.LegalRegime)
		}
	})
}

func TestClosing_JurisdictionResolver_PriorityResolution(t *testing.T) {
	r := NewJurisdictionResolver()
	r.AddRule(JurisdictionRule{RuleID: "low", LegalRegime: "LOW", Region: "US", Priority: 1})
	r.AddRule(JurisdictionRule{RuleID: "high", LegalRegime: "HIGH", Region: "US", Priority: 10})
	t.Run("highest_priority_wins", func(t *testing.T) {
		ctx, _ := r.Resolve("entity", "", "", "US")
		if ctx.LegalRegime != "HIGH" {
			t.Fatalf("got %q, want HIGH", ctx.LegalRegime)
		}
	})
	t.Run("content_hash_set", func(t *testing.T) {
		ctx, _ := r.Resolve("entity", "", "", "US")
		if ctx.ContentHash == "" {
			t.Fatal("content hash should be set")
		}
	})
	t.Run("sha256_prefix", func(t *testing.T) {
		ctx, _ := r.Resolve("entity", "", "", "US")
		if len(ctx.ContentHash) < 7 || ctx.ContentHash[:7] != "sha256:" {
			t.Fatalf("expected sha256: prefix, got %q", ctx.ContentHash)
		}
	})
}

func TestClosing_JurisdictionResolver_WithClock(t *testing.T) {
	fixedTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	r := NewJurisdictionResolver().WithClock(func() time.Time { return fixedTime })
	r.AddRule(JurisdictionRule{RuleID: "r1", LegalRegime: "TEST", Region: "US"})
	t.Run("uses_clock", func(t *testing.T) {
		ctx, _ := r.Resolve("e", "", "", "US")
		if !ctx.Timestamp.Equal(fixedTime) {
			t.Fatalf("got %v, want %v", ctx.Timestamp, fixedTime)
		}
	})
	t.Run("returns_resolver", func(t *testing.T) {
		if r == nil {
			t.Fatal("should return non-nil")
		}
	})
	t.Run("chain_call", func(t *testing.T) {
		r2 := NewJurisdictionResolver().WithClock(func() time.Time { return fixedTime })
		if r2 == nil {
			t.Fatal("should return non-nil")
		}
	})
}

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

func TestClosing_NewBlockingState_Types(t *testing.T) {
	t.Run("approval", func(t *testing.T) {
		bs := NewApprovalState("a1", 0)
		if bs.StateType != BlockingStateApproval {
			t.Fatalf("got %q", bs.StateType)
		}
		if bs.Timeout != DefaultApprovalTimeout {
			t.Fatalf("got %v, want %v", bs.Timeout, DefaultApprovalTimeout)
		}
	})
	t.Run("obligation", func(t *testing.T) {
		bs := NewObligationState("o1", 0)
		if bs.StateType != BlockingStateObligation {
			t.Fatalf("got %q", bs.StateType)
		}
	})
	t.Run("lease", func(t *testing.T) {
		bs := NewSequencerLease("l1", 0)
		if bs.StateType != BlockingStateLease {
			t.Fatalf("got %q", bs.StateType)
		}
	})
	t.Run("custom_timeout", func(t *testing.T) {
		bs := NewApprovalState("a2", 5*time.Minute)
		if bs.Timeout != 5*time.Minute {
			t.Fatalf("got %v", bs.Timeout)
		}
	})
}

func TestClosing_BlockingState_Lifecycle(t *testing.T) {
	bs := NewBlockingState("s1", BlockingStateApproval, time.Hour)
	t.Run("starts_pending", func(t *testing.T) {
		if bs.State != LivenessStatePending {
			t.Fatalf("got %q", bs.State)
		}
	})
	t.Run("not_expired", func(t *testing.T) {
		if bs.IsExpired() {
			t.Fatal("should not be expired")
		}
	})
	t.Run("time_remaining_positive", func(t *testing.T) {
		if bs.TimeRemaining() <= 0 {
			t.Fatal("should have time remaining")
		}
	})
	bs.Resolve()
	t.Run("resolved_to_active", func(t *testing.T) {
		if bs.State != LivenessStateActive {
			t.Fatalf("got %q", bs.State)
		}
	})
}

func TestClosing_BlockingState_Cancel(t *testing.T) {
	bs := NewBlockingState("s2", BlockingStateObligation, time.Hour)
	bs.Cancel()
	t.Run("state_is_canceled", func(t *testing.T) {
		if bs.State != LivenessStateCanceled {
			t.Fatalf("got %q", bs.State)
		}
	})
	t.Run("resolved_at_set", func(t *testing.T) {
		if bs.ResolvedAt == nil {
			t.Fatal("resolved_at should be set")
		}
	})
	t.Run("extend_fails", func(t *testing.T) {
		err := bs.Extend(time.Hour)
		if err == nil {
			t.Fatal("extend should fail on canceled state")
		}
	})
}

func TestClosing_LivenessManager_RegisterResolve(t *testing.T) {
	lm := NewLivenessManager()
	defer lm.Shutdown()
	bs := NewApprovalState("a1", time.Hour)
	t.Run("register", func(t *testing.T) {
		err := lm.Register(bs)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("duplicate_register_errors", func(t *testing.T) {
		err := lm.Register(bs)
		if err == nil {
			t.Fatal("expected error for duplicate")
		}
	})
	t.Run("get", func(t *testing.T) {
		got, err := lm.Get("a1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.StateID != "a1" {
			t.Fatalf("got %q", got.StateID)
		}
	})
	t.Run("resolve", func(t *testing.T) {
		err := lm.Resolve("a1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// 13-18: Plan commit
// ---------------------------------------------------------------------------

func TestClosing_PlanCommitController_SubmitPlan(t *testing.T) {
	pc := NewPlanCommitController()
	plan := &ExecutionPlan{PlanID: "p1", EffectType: "DEPLOY", Principal: "admin"}
	t.Run("submit_succeeds", func(t *testing.T) {
		ref, err := pc.SubmitPlan(plan)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ref.PlanID != "p1" {
			t.Fatalf("got %q", ref.PlanID)
		}
		if ref.PlanHash == "" {
			t.Fatal("hash should not be empty")
		}
	})
	t.Run("duplicate_errors", func(t *testing.T) {
		_, err := pc.SubmitPlan(plan)
		if err == nil {
			t.Fatal("expected error for duplicate")
		}
	})
	t.Run("nil_plan_errors", func(t *testing.T) {
		_, err := pc.SubmitPlan(nil)
		if err == nil {
			t.Fatal("expected error for nil plan")
		}
	})
	t.Run("empty_id_errors", func(t *testing.T) {
		_, err := pc.SubmitPlan(&ExecutionPlan{})
		if err == nil {
			t.Fatal("expected error for empty PlanID")
		}
	})
}

func TestClosing_PlanCommitController_ApproveReject(t *testing.T) {
	pc := NewPlanCommitController()
	pc.SubmitPlan(&ExecutionPlan{PlanID: "approve-me", EffectType: "DEPLOY"})
	t.Run("approve", func(t *testing.T) {
		err := pc.Approve("approve-me", "admin")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("approve_nonpending_errors", func(t *testing.T) {
		err := pc.Approve("approve-me", "admin")
		if err == nil {
			t.Fatal("expected error")
		}
	})
	pc.SubmitPlan(&ExecutionPlan{PlanID: "reject-me", EffectType: "DEPLOY"})
	t.Run("reject", func(t *testing.T) {
		err := pc.Reject("reject-me", "admin", "too risky")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("reject_nonpending_errors", func(t *testing.T) {
		err := pc.Reject("reject-me", "admin", "again")
		if err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestClosing_PlanCommitController_Abort(t *testing.T) {
	pc := NewPlanCommitController()
	pc.SubmitPlan(&ExecutionPlan{PlanID: "abort-me", EffectType: "DEPLOY"})
	t.Run("abort", func(t *testing.T) {
		err := pc.Abort("abort-me")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("abort_nonpending_errors", func(t *testing.T) {
		err := pc.Abort("abort-me")
		if err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("abort_unknown_errors", func(t *testing.T) {
		err := pc.Abort("nonexistent")
		if err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestClosing_PlanCommitController_PendingCount(t *testing.T) {
	pc := NewPlanCommitController()
	t.Run("initially_zero", func(t *testing.T) {
		if pc.PendingCount() != 0 {
			t.Fatalf("got %d", pc.PendingCount())
		}
	})
	pc.SubmitPlan(&ExecutionPlan{PlanID: "p1", EffectType: "X"})
	pc.SubmitPlan(&ExecutionPlan{PlanID: "p2", EffectType: "Y"})
	t.Run("two_pending", func(t *testing.T) {
		if pc.PendingCount() != 2 {
			t.Fatalf("got %d", pc.PendingCount())
		}
	})
	pc.Approve("p1", "admin")
	t.Run("one_after_approve", func(t *testing.T) {
		if pc.PendingCount() != 1 {
			t.Fatalf("got %d", pc.PendingCount())
		}
	})
}

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

func TestClosing_PlanCommitController_WaitForApproval(t *testing.T) {
	pc := NewPlanCommitController().WithAfter(func(d time.Duration) <-chan time.Time {
		ch := make(chan time.Time, 1)
		ch <- time.Now()
		return ch
	})
	ref, _ := pc.SubmitPlan(&ExecutionPlan{PlanID: "timeout-me", EffectType: "X"})
	t.Run("timeout_decision", func(t *testing.T) {
		dec, err := pc.WaitForApproval(*ref, time.Millisecond)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dec.Status != PlanStatusTimeout {
			t.Fatalf("got %q, want TIMEOUT", dec.Status)
		}
	})
	t.Run("unknown_plan_errors", func(t *testing.T) {
		_, err := pc.WaitForApproval(PlanRef{PlanID: "unknown"}, time.Second)
		if err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("hash_mismatch_errors", func(t *testing.T) {
		ref2, _ := pc.SubmitPlan(&ExecutionPlan{PlanID: "mismatch", EffectType: "X"})
		_, err := pc.WaitForApproval(PlanRef{PlanID: ref2.PlanID, PlanHash: "wrong"}, time.Second)
		if err == nil {
			t.Fatal("expected error")
		}
	})
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

func TestClosing_Classifier_Classification(t *testing.T) {
	c := NewClassifier()
	cases := []struct {
		name    string
		content string
		want    DataClass
	}{
		{"plain_text", "hello world", DataClassInternal},
		{"email_pii", "contact user@example.com", DataClassConfidential},
		{"ssn", "SSN: 123-45-6789", DataClassConfidential},
		{"private_key", "-----BEGIN PRIVATE KEY-----", DataClassRestricted},
		{"root_password", "root_password=secret", DataClassRestricted},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := c.Classify(tc.content)
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestClosing_Classifier_APIKey(t *testing.T) {
	c := NewClassifier()
	t.Run("detects_api_key", func(t *testing.T) {
		got := c.Classify("token: sk-abcdefghijklmnopqrstuvwxyz")
		if got != DataClassConfidential {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("short_prefix_not_matched", func(t *testing.T) {
		got := c.Classify("sk-short")
		if got != DataClassInternal {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("no_match", func(t *testing.T) {
		got := c.Classify("normal text without secrets")
		if got != DataClassInternal {
			t.Fatalf("got %q", got)
		}
	})
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

func TestClosing_CELPolicyDecisionPoint_Evaluate(t *testing.T) {
	pdp, err := NewCELPolicyDecisionPoint("hash-v1", nil)
	if err != nil {
		t.Fatalf("failed to create PDP: %v", err)
	}
	t.Run("deny_by_default", func(t *testing.T) {
		resp, _ := pdp.Evaluate(context.Background(), PDPRequest{
			Effect: EffectDescriptor{EffectType: "UNKNOWN_TYPE"},
		})
		if resp.Decision != DecisionDeny {
			t.Fatalf("got %q, want DENY", resp.Decision)
		}
	})
	t.Run("allow_data_write", func(t *testing.T) {
		resp, _ := pdp.Evaluate(context.Background(), PDPRequest{
			Effect: EffectDescriptor{EffectType: "DATA_WRITE"},
		})
		if resp.Decision != DecisionAllow {
			t.Fatalf("got %q, want ALLOW", resp.Decision)
		}
	})
	t.Run("require_approval_deploy", func(t *testing.T) {
		resp, _ := pdp.Evaluate(context.Background(), PDPRequest{
			Effect: EffectDescriptor{EffectType: "DEPLOY"},
		})
		if resp.Decision != DecisionRequireApproval {
			t.Fatalf("got %q, want REQUIRE_APPROVAL", resp.Decision)
		}
	})
	t.Run("policy_version_set", func(t *testing.T) {
		if pdp.PolicyVersion() != "hash-v1" {
			t.Fatalf("got %q", pdp.PolicyVersion())
		}
	})
}

func TestClosing_CELPolicyDecisionPoint_UpdatePolicy(t *testing.T) {
	pdp, _ := NewCELPolicyDecisionPoint("v1", nil)
	pdp.UpdatePolicyBundle("v2")
	t.Run("updated", func(t *testing.T) {
		if pdp.PolicyVersion() != "v2" {
			t.Fatalf("got %q", pdp.PolicyVersion())
		}
	})
	t.Run("evaluate_uses_new_version", func(t *testing.T) {
		resp, _ := pdp.Evaluate(context.Background(), PDPRequest{
			Effect: EffectDescriptor{EffectType: "DATA_WRITE"},
		})
		if resp.PolicyVersion != "v2" {
			t.Fatalf("got %q", resp.PolicyVersion)
		}
	})
	t.Run("trace_has_version", func(t *testing.T) {
		resp, _ := pdp.Evaluate(context.Background(), PDPRequest{
			Effect: EffectDescriptor{EffectType: "NOTIFY"},
		})
		if resp.Trace.InputsHashes["policy_version"] != "v2" {
			t.Fatal("trace should reference new version")
		}
	})
}

// ---------------------------------------------------------------------------
// 25-30: PDP modes / Security checks
// ---------------------------------------------------------------------------

func TestClosing_PDPAttestation_Lifecycle(t *testing.T) {
	att := NewPDPAttestation("pdp-1", time.Hour)
	t.Run("initial_valid", func(t *testing.T) {
		if !att.IsValid() {
			t.Fatal("should be valid initially")
		}
	})
	t.Run("status_valid", func(t *testing.T) {
		if att.Status != PDPAttestationValid {
			t.Fatalf("got %q", att.Status)
		}
	})
	att.MarkSuspect()
	t.Run("suspect", func(t *testing.T) {
		if att.Status != PDPAttestationSuspect {
			t.Fatalf("got %q", att.Status)
		}
	})
	att.MarkCompromised()
	t.Run("compromised", func(t *testing.T) {
		if att.Status != PDPAttestationCompromised {
			t.Fatalf("got %q", att.Status)
		}
	})
	att2 := NewPDPAttestation("pdp-2", time.Hour)
	att2.Revoke()
	t.Run("revoked", func(t *testing.T) {
		if att2.Status != PDPAttestationRevoked {
			t.Fatalf("got %q", att2.Status)
		}
	})
}

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

func TestClosing_CompromiseDetector_Anomalies(t *testing.T) {
	cd := NewCompromiseDetector()
	att := NewPDPAttestation("pdp-1", time.Hour)
	cd.RegisterAttestation(att)
	t.Run("report_low_severity", func(t *testing.T) {
		a := cd.ReportAnomaly("pdp-1", AnomalyTypeTimingAnomaly, "slow", 3)
		if a == nil {
			t.Fatal("anomaly should not be nil")
		}
	})
	t.Run("still_valid", func(t *testing.T) {
		if cd.GetPDPStatus("pdp-1") != PDPAttestationValid {
			t.Fatalf("low severity should not change status")
		}
	})
	t.Run("report_high_severity", func(t *testing.T) {
		cd.ReportAnomaly("pdp-1", AnomalyTypeTimingAnomaly, "very slow", 8)
		if cd.GetPDPStatus("pdp-1") != PDPAttestationSuspect {
			t.Fatal("high severity should mark suspect")
		}
	})
	t.Run("should_fail_closed", func(t *testing.T) {
		if !cd.ShouldFailClosed("pdp-1") {
			t.Fatal("suspect PDP should fail closed")
		}
	})
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

func TestClosing_CompromiseDetector_UnknownPDP(t *testing.T) {
	cd := NewCompromiseDetector()
	t.Run("unknown_returns_expired", func(t *testing.T) {
		if cd.GetPDPStatus("unknown") != PDPAttestationExpired {
			t.Fatal("unknown PDP should return EXPIRED")
		}
	})
	t.Run("should_not_fail_closed_for_unknown", func(t *testing.T) {
		// EXPIRED is not in the fail-closed set
		if cd.ShouldFailClosed("unknown") {
			t.Fatal("EXPIRED should not trigger fail-closed")
		}
	})
	t.Run("register_then_check", func(t *testing.T) {
		att := NewPDPAttestation("new", time.Hour)
		cd.RegisterAttestation(att)
		if cd.GetPDPStatus("new") != PDPAttestationValid {
			t.Fatal("newly registered should be VALID")
		}
	})
}

func TestClosing_CompromiseDetector_FailClosedStates(t *testing.T) {
	failClosedStatuses := []PDPAttestationStatus{PDPAttestationSuspect, PDPAttestationCompromised, PDPAttestationRevoked}
	for _, status := range failClosedStatuses {
		t.Run(string(status), func(t *testing.T) {
			cd := NewCompromiseDetector()
			att := NewPDPAttestation("pdp", time.Hour)
			att.Status = status
			cd.RegisterAttestation(att)
			if !cd.ShouldFailClosed("pdp") {
				t.Fatalf("status %s should trigger fail-closed", status)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 31-36: DelegationRevocation
// ---------------------------------------------------------------------------

func TestClosing_DelegationRevocationList_RevokeCheck(t *testing.T) {
	drl := NewDelegationRevocationList()
	t.Run("not_revoked_initially", func(t *testing.T) {
		if drl.IsRevoked("d1") {
			t.Fatal("should not be revoked")
		}
	})
	t.Run("revoke", func(t *testing.T) {
		err := drl.Revoke("d1", "admin", "reason")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("is_revoked", func(t *testing.T) {
		if !drl.IsRevoked("d1") {
			t.Fatal("should be revoked")
		}
	})
	t.Run("double_revoke_errors", func(t *testing.T) {
		err := drl.Revoke("d1", "admin", "again")
		if err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestClosing_DelegationRevocationList_GetEntry(t *testing.T) {
	drl := NewDelegationRevocationList()
	drl.Revoke("d1", "admin", "test")
	t.Run("entry_exists", func(t *testing.T) {
		entry, ok := drl.GetEntry("d1")
		if !ok || entry == nil {
			t.Fatal("entry should exist")
		}
	})
	t.Run("entry_fields", func(t *testing.T) {
		entry, _ := drl.GetEntry("d1")
		if entry.DelegationID != "d1" {
			t.Fatalf("got %q", entry.DelegationID)
		}
		if entry.RevokedBy != "admin" {
			t.Fatalf("got %q", entry.RevokedBy)
		}
	})
	t.Run("missing_entry", func(t *testing.T) {
		_, ok := drl.GetEntry("nonexistent")
		if ok {
			t.Fatal("should not exist")
		}
	})
}

func TestClosing_DelegationRevocationList_PruneExpired(t *testing.T) {
	drl := NewDelegationRevocationList()
	drl.Revoke("d1", "admin", "test")
	pastTime := time.Now().Add(-time.Hour)
	drl.Entries["d1"].ExpiresAt = &pastTime
	t.Run("prune_removes_expired", func(t *testing.T) {
		count := drl.PruneExpired()
		if count != 1 {
			t.Fatalf("got %d, want 1", count)
		}
	})
	t.Run("no_longer_revoked", func(t *testing.T) {
		if drl.IsRevoked("d1") {
			t.Fatal("should not be revoked after prune")
		}
	})
	t.Run("prune_again_zero", func(t *testing.T) {
		count := drl.PruneExpired()
		if count != 0 {
			t.Fatalf("got %d, want 0", count)
		}
	})
}

func TestClosing_DelegationRevocationList_Version(t *testing.T) {
	drl := NewDelegationRevocationList()
	t.Run("version_set", func(t *testing.T) {
		if drl.Version != "1.0.0" {
			t.Fatalf("got %q", drl.Version)
		}
	})
	t.Run("entries_empty", func(t *testing.T) {
		if len(drl.Entries) != 0 {
			t.Fatalf("got %d entries", len(drl.Entries))
		}
	})
	t.Run("entries_not_nil", func(t *testing.T) {
		if drl.Entries == nil {
			t.Fatal("entries should be initialized")
		}
	})
}

func TestClosing_CompensationState_Lifecycle(t *testing.T) {
	cs := NewCompensationState("tx1", "op1", CompensationPolicyRetry)
	t.Run("initial_count_zero", func(t *testing.T) {
		if cs.AttemptCount != 0 {
			t.Fatalf("got %d", cs.AttemptCount)
		}
	})
	t.Run("record_failure_retries", func(t *testing.T) {
		outcome := cs.RecordAttempt(false, "err1")
		if outcome != CompensationOutcomeRetry {
			t.Fatalf("got %q", outcome)
		}
	})
	t.Run("record_success", func(t *testing.T) {
		outcome := cs.RecordAttempt(true, "")
		if outcome != CompensationOutcomeSuccess {
			t.Fatalf("got %q", outcome)
		}
	})
}

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

func TestClosing_CompensationState_MaxAttempts_Escalate(t *testing.T) {
	cs := NewCompensationState("tx", "op", CompensationPolicyEscalate)
	cs.RecordAttempt(false, "e1")
	cs.RecordAttempt(false, "e2")
	t.Run("third_attempt_escalates", func(t *testing.T) {
		outcome := cs.RecordAttempt(false, "e3")
		if outcome != CompensationOutcomeEscalate {
			t.Fatalf("got %q", outcome)
		}
	})
	t.Run("escalated_at_set", func(t *testing.T) {
		if cs.EscalatedAt == nil {
			t.Fatal("escalated_at should be set")
		}
	})
	t.Run("needs_intervention", func(t *testing.T) {
		if !cs.NeedsIntervention() {
			t.Fatal("should need intervention")
		}
	})
}

func TestClosing_CompensationState_MaxAttempts_Manual(t *testing.T) {
	cs := NewCompensationState("tx", "op", CompensationPolicyManual)
	cs.RecordAttempt(false, "e1")
	cs.RecordAttempt(false, "e2")
	t.Run("third_attempt_manual", func(t *testing.T) {
		outcome := cs.RecordAttempt(false, "e3")
		if outcome != CompensationOutcomeManual {
			t.Fatalf("got %q", outcome)
		}
	})
	t.Run("needs_intervention", func(t *testing.T) {
		if !cs.NeedsIntervention() {
			t.Fatal("should need intervention")
		}
	})
	t.Run("max_attempts_set", func(t *testing.T) {
		if cs.MaxAttempts != MaxCompensationAttempts {
			t.Fatalf("got %d", cs.MaxAttempts)
		}
	})
}

func TestClosing_CompensationState_MaxAttempts_Fallback(t *testing.T) {
	cs := NewCompensationState("tx", "op", CompensationPolicyFallback)
	cs.RecordAttempt(false, "e1")
	cs.RecordAttempt(false, "e2")
	t.Run("third_attempt_fallback", func(t *testing.T) {
		outcome := cs.RecordAttempt(false, "e3")
		if outcome != CompensationOutcomeFallback {
			t.Fatalf("got %q", outcome)
		}
	})
	t.Run("fallback_executed", func(t *testing.T) {
		if !cs.FallbackExecuted {
			t.Fatal("fallback should be marked executed")
		}
	})
	t.Run("last_error_set", func(t *testing.T) {
		if cs.LastError != "e3" {
			t.Fatalf("got %q", cs.LastError)
		}
	})
}

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

func TestClosing_CompensationState_NoIntervention(t *testing.T) {
	cs := NewCompensationState("tx", "op", CompensationPolicyRetry)
	t.Run("no_intervention_initially", func(t *testing.T) {
		if cs.NeedsIntervention() {
			t.Fatal("should not need intervention initially")
		}
	})
	cs.RecordAttempt(false, "err")
	t.Run("still_no_intervention", func(t *testing.T) {
		if cs.NeedsIntervention() {
			t.Fatal("should not need intervention after 1 attempt")
		}
	})
	t.Run("attempt_count", func(t *testing.T) {
		if cs.AttemptCount != 1 {
			t.Fatalf("got %d", cs.AttemptCount)
		}
	})
}

func TestClosing_MaxCompensationAttempts_Value(t *testing.T) {
	t.Run("is_three", func(t *testing.T) {
		if MaxCompensationAttempts != 3 {
			t.Fatalf("got %d", MaxCompensationAttempts)
		}
	})
	t.Run("positive", func(t *testing.T) {
		if MaxCompensationAttempts <= 0 {
			t.Fatal("should be positive")
		}
	})
	t.Run("used_by_default", func(t *testing.T) {
		cs := NewCompensationState("tx", "op", CompensationPolicyRetry)
		if cs.MaxAttempts != MaxCompensationAttempts {
			t.Fatalf("got %d", cs.MaxAttempts)
		}
	})
}

// ---------------------------------------------------------------------------
// 43-50: LivenessManager, Defaults, and misc
// ---------------------------------------------------------------------------

func TestClosing_LivenessManager_Cancel(t *testing.T) {
	lm := NewLivenessManager()
	defer lm.Shutdown()
	bs := NewApprovalState("c1", time.Hour)
	lm.Register(bs)
	t.Run("cancel", func(t *testing.T) {
		err := lm.Cancel("c1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("state_canceled", func(t *testing.T) {
		got, _ := lm.Get("c1")
		if got.State != LivenessStateCanceled {
			t.Fatalf("got %q", got.State)
		}
	})
	t.Run("cancel_unknown_errors", func(t *testing.T) {
		err := lm.Cancel("nonexistent")
		if err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestClosing_LivenessManager_ActiveCount(t *testing.T) {
	lm := NewLivenessManager()
	defer lm.Shutdown()
	t.Run("initially_zero", func(t *testing.T) {
		if lm.ActiveCount() != 0 {
			t.Fatalf("got %d", lm.ActiveCount())
		}
	})
	lm.Register(NewApprovalState("a1", time.Hour))
	lm.Register(NewApprovalState("a2", time.Hour))
	t.Run("two_active", func(t *testing.T) {
		if lm.ActiveCount() != 2 {
			t.Fatalf("got %d", lm.ActiveCount())
		}
	})
	lm.Cancel("a1")
	t.Run("one_after_cancel", func(t *testing.T) {
		if lm.ActiveCount() != 1 {
			t.Fatalf("got %d", lm.ActiveCount())
		}
	})
}

func TestClosing_LivenessManager_PendingApprovals(t *testing.T) {
	lm := NewLivenessManager()
	defer lm.Shutdown()
	lm.Register(NewApprovalState("a1", time.Hour))
	lm.Register(NewObligationState("o1", time.Hour))
	t.Run("one_approval", func(t *testing.T) {
		approvals := lm.PendingApprovals()
		if len(approvals) != 1 {
			t.Fatalf("got %d", len(approvals))
		}
	})
	t.Run("approval_id", func(t *testing.T) {
		approvals := lm.PendingApprovals()
		if approvals[0].StateID != "a1" {
			t.Fatalf("got %q", approvals[0].StateID)
		}
	})
	t.Run("resolve_removes_from_pending", func(t *testing.T) {
		lm.Resolve("a1")
		approvals := lm.PendingApprovals()
		if len(approvals) != 0 {
			t.Fatalf("got %d", len(approvals))
		}
	})
}

func TestClosing_LivenessManager_Shutdown(t *testing.T) {
	lm := NewLivenessManager()
	lm.Register(NewApprovalState("s1", time.Hour))
	lm.Register(NewApprovalState("s2", time.Hour))
	t.Run("shutdown_no_panic", func(t *testing.T) {
		lm.Shutdown()
	})
	t.Run("double_shutdown_no_panic", func(t *testing.T) {
		lm.Shutdown()
	})
	t.Run("get_after_shutdown", func(t *testing.T) {
		_, err := lm.Get("s1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

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

func TestClosing_BlockingState_Extend(t *testing.T) {
	bs := NewBlockingState("ext", BlockingStateApproval, time.Hour)
	t.Run("extend_pending", func(t *testing.T) {
		err := bs.Extend(2 * time.Hour)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("remaining_after_extend", func(t *testing.T) {
		rem := bs.TimeRemaining()
		if rem < time.Hour {
			t.Fatalf("expected > 1h, got %v", rem)
		}
	})
	t.Run("extend_resolved_fails", func(t *testing.T) {
		bs.Resolve()
		err := bs.Extend(time.Hour)
		if err == nil {
			t.Fatal("should fail on resolved state")
		}
	})
}

func TestClosing_BlockingState_OnExpire(t *testing.T) {
	called := false
	bs := NewBlockingState("e1", BlockingStateApproval, time.Hour)
	bs.OnExpire(func(s *BlockingState) {
		called = true
	})
	bs.Expire()
	t.Run("callback_called", func(t *testing.T) {
		if !called {
			t.Fatal("expire callback should have been called")
		}
	})
	t.Run("state_expired", func(t *testing.T) {
		if bs.State != LivenessStateExpired {
			t.Fatalf("got %q", bs.State)
		}
	})
	t.Run("no_callback_no_panic", func(t *testing.T) {
		bs2 := NewBlockingState("e2", BlockingStateApproval, time.Hour)
		bs2.Expire() // No callback registered, should not panic
	})
}

func TestClosing_LivenessManager_ResolveExpired_Errors(t *testing.T) {
	lm := NewLivenessManager()
	defer lm.Shutdown()
	bs := NewBlockingState("exp", BlockingStateApproval, time.Nanosecond)
	time.Sleep(time.Millisecond)
	lm.Register(bs)
	t.Run("resolve_expired_errors", func(t *testing.T) {
		time.Sleep(time.Millisecond)
		err := lm.Resolve("exp")
		if err == nil {
			t.Fatal("expected error for expired state")
		}
	})
	t.Run("resolve_unknown_errors", func(t *testing.T) {
		err := lm.Resolve("unknown")
		if err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("get_unknown_errors", func(t *testing.T) {
		_, err := lm.Get("unknown")
		if err == nil {
			t.Fatal("expected error")
		}
	})
}
