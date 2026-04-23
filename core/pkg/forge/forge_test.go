package forge

import (
	"context"
	"testing"
	"time"
)

// ─── Candidate Queue ──────────────────────────────────────────────────────────

func TestCandidateQueue_Enqueue_Get(t *testing.T) {
	ctx := context.Background()
	q := NewInMemoryCandidateQueue()

	c := Candidate{
		CandidateID:  "cand-1",
		SkillID:      "skill-1",
		TenantID:     "tenant-a",
		SelfModClass: "C0",
		Status:       CandidateQueued,
		QueuedAt:     time.Now(),
	}

	if err := q.Enqueue(ctx, c); err != nil {
		t.Fatalf("Enqueue: unexpected error: %v", err)
	}

	got, err := q.Get(ctx, "cand-1")
	if err != nil {
		t.Fatalf("Get: unexpected error: %v", err)
	}
	if got.CandidateID != "cand-1" {
		t.Errorf("CandidateID: got %q, want %q", got.CandidateID, "cand-1")
	}
	if got.TenantID != "tenant-a" {
		t.Errorf("TenantID: got %q, want %q", got.TenantID, "tenant-a")
	}
}

func TestCandidateQueue_EnqueueDuplicate(t *testing.T) {
	ctx := context.Background()
	q := NewInMemoryCandidateQueue()

	c := Candidate{CandidateID: "dup-1", TenantID: "t", SelfModClass: "C0"}
	if err := q.Enqueue(ctx, c); err != nil {
		t.Fatalf("first Enqueue: %v", err)
	}

	if err := q.Enqueue(ctx, c); err == nil {
		t.Fatal("expected error for duplicate CandidateID, got nil")
	}
}

func TestCandidateQueue_EnqueueEmptyID(t *testing.T) {
	ctx := context.Background()
	q := NewInMemoryCandidateQueue()

	if err := q.Enqueue(ctx, Candidate{TenantID: "t", SelfModClass: "C0"}); err == nil {
		t.Fatal("expected error for empty CandidateID, got nil")
	}
}

func TestCandidateQueue_Dequeue_FIFO(t *testing.T) {
	ctx := context.Background()
	q := NewInMemoryCandidateQueue()

	for _, id := range []string{"c-1", "c-2", "c-3"} {
		if err := q.Enqueue(ctx, Candidate{
			CandidateID:  id,
			TenantID:     "t",
			SelfModClass: "C0",
			Status:       CandidateQueued,
		}); err != nil {
			t.Fatalf("Enqueue %s: %v", id, err)
		}
	}

	// Dequeue should return in insertion order.
	for _, want := range []string{"c-1", "c-2", "c-3"} {
		got, err := q.Dequeue(ctx)
		if err != nil {
			t.Fatalf("Dequeue: %v", err)
		}
		if got == nil {
			t.Fatalf("expected candidate %q, got nil", want)
		}
		if got.CandidateID != want {
			t.Errorf("Dequeue order: got %q, want %q", got.CandidateID, want)
		}
	}

	// Queue should be empty now.
	empty, err := q.Dequeue(ctx)
	if err != nil {
		t.Fatalf("Dequeue on empty queue: %v", err)
	}
	if empty != nil {
		t.Errorf("expected nil from empty queue, got %+v", empty)
	}
}

func TestCandidateQueue_DequeueSkipsNonQueued(t *testing.T) {
	ctx := context.Background()
	q := NewInMemoryCandidateQueue()

	// Add an evaluating candidate first, then a queued one.
	if err := q.Enqueue(ctx, Candidate{
		CandidateID:  "eval-1",
		TenantID:     "t",
		SelfModClass: "C1",
		Status:       CandidateEvaluating,
	}); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if err := q.Enqueue(ctx, Candidate{
		CandidateID:  "queued-2",
		TenantID:     "t",
		SelfModClass: "C0",
		Status:       CandidateQueued,
	}); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	got, err := q.Dequeue(ctx)
	if err != nil {
		t.Fatalf("Dequeue: %v", err)
	}
	if got == nil {
		t.Fatal("expected candidate, got nil")
	}
	if got.CandidateID != "queued-2" {
		t.Errorf("expected queued-2, got %q", got.CandidateID)
	}
}

func TestCandidateQueue_List(t *testing.T) {
	ctx := context.Background()
	q := NewInMemoryCandidateQueue()

	_ = q.Enqueue(ctx, Candidate{CandidateID: "a1", TenantID: "alpha", SelfModClass: "C0", Status: CandidateQueued})
	_ = q.Enqueue(ctx, Candidate{CandidateID: "b1", TenantID: "beta", SelfModClass: "C1", Status: CandidateQueued})
	_ = q.Enqueue(ctx, Candidate{CandidateID: "a2", TenantID: "alpha", SelfModClass: "C0", Status: CandidateQueued})

	list, err := q.List(ctx, "alpha")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("List(alpha): got %d items, want 2", len(list))
	}
	if list[0].CandidateID != "a1" || list[1].CandidateID != "a2" {
		t.Errorf("List order: got [%s, %s], want [a1, a2]", list[0].CandidateID, list[1].CandidateID)
	}
}

func TestCandidateQueue_UpdateStatus(t *testing.T) {
	ctx := context.Background()
	q := NewInMemoryCandidateQueue()

	_ = q.Enqueue(ctx, Candidate{CandidateID: "upd-1", TenantID: "t", SelfModClass: "C0", Status: CandidateQueued})

	if err := q.UpdateStatus(ctx, "upd-1", CandidateEvaluating); err != nil {
		t.Fatalf("UpdateStatus: %v", err)
	}

	got, _ := q.Get(ctx, "upd-1")
	if got.Status != CandidateEvaluating {
		t.Errorf("Status: got %q, want %q", got.Status, CandidateEvaluating)
	}
}

func TestCandidateQueue_UpdateStatus_NotFound(t *testing.T) {
	ctx := context.Background()
	q := NewInMemoryCandidateQueue()

	if err := q.UpdateStatus(ctx, "ghost", CandidateReady); err == nil {
		t.Fatal("expected error for missing candidate, got nil")
	}
}

func TestCandidateQueue_Get_NotFound(t *testing.T) {
	ctx := context.Background()
	q := NewInMemoryCandidateQueue()

	if _, err := q.Get(ctx, "no-such-id"); err == nil {
		t.Fatal("expected error, got nil")
	}
}

// ─── Evaluator Profiles ───────────────────────────────────────────────────────

func TestDefaultProfiles_AllClassesPresent(t *testing.T) {
	profiles := DefaultProfiles()
	classes := map[string]bool{"C0": false, "C1": false, "C2": false, "C3": false}
	for _, p := range profiles {
		classes[p.SelfModClass] = true
	}
	for class, found := range classes {
		if !found {
			t.Errorf("DefaultProfiles missing class %q", class)
		}
	}
}

func TestGetProfile_KnownClasses(t *testing.T) {
	for _, class := range []string{"C0", "C1", "C2", "C3"} {
		p, err := GetProfile(class)
		if err != nil {
			t.Errorf("GetProfile(%q): unexpected error: %v", class, err)
			continue
		}
		if p.SelfModClass != class {
			t.Errorf("GetProfile(%q): SelfModClass = %q", class, p.SelfModClass)
		}
	}
}

func TestGetProfile_UnknownClass(t *testing.T) {
	if _, err := GetProfile("C99"); err == nil {
		t.Fatal("expected error for unknown class, got nil")
	}
}

func TestProfile_C0_AutoPromote(t *testing.T) {
	p, _ := GetProfile("C0")
	if !p.AutoPromote {
		t.Error("C0 profile: AutoPromote should be true")
	}
	if p.RequireApproval {
		t.Error("C0 profile: RequireApproval should be false")
	}
	if p.MaxEvalTimeMs != 30_000 {
		t.Errorf("C0 MaxEvalTimeMs: got %d, want 30000", p.MaxEvalTimeMs)
	}
}

func TestProfile_C1_RequiresApproval(t *testing.T) {
	p, _ := GetProfile("C1")
	if p.AutoPromote {
		t.Error("C1 profile: AutoPromote should be false")
	}
	if !p.RequireApproval {
		t.Error("C1 profile: RequireApproval should be true")
	}
	if p.MaxEvalTimeMs != 60_000 {
		t.Errorf("C1 MaxEvalTimeMs: got %d, want 60000", p.MaxEvalTimeMs)
	}
}

func TestProfile_C2_ContainmentCheck(t *testing.T) {
	p, _ := GetProfile("C2")
	if !containsCheck(p.RequiredChecks, CheckContainmentCheck) {
		t.Errorf("C2 profile missing %q check", CheckContainmentCheck)
	}
	if p.MaxEvalTimeMs != 300_000 {
		t.Errorf("C2 MaxEvalTimeMs: got %d, want 300000", p.MaxEvalTimeMs)
	}
}

func TestProfile_C3_AdversarialAndMutationChecks(t *testing.T) {
	p, _ := GetProfile("C3")
	for _, check := range []string{CheckAdversarialTest, CheckMutationBoundaryCheck} {
		if !containsCheck(p.RequiredChecks, check) {
			t.Errorf("C3 profile missing %q check", check)
		}
	}
	if p.MaxEvalTimeMs != 600_000 {
		t.Errorf("C3 MaxEvalTimeMs: got %d, want 600000", p.MaxEvalTimeMs)
	}
}

func TestEvaluate_C0_PassAll(t *testing.T) {
	profile, _ := GetProfile("C0")
	c := Candidate{CandidateID: "ev-c0", SelfModClass: "C0"}

	result, err := Evaluate(c, *profile)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !result.Passed {
		t.Error("C0 evaluation should pass by default (sandbox_test + schema_validation)")
	}
	if len(result.CheckResults) != len(profile.RequiredChecks) {
		t.Errorf("CheckResults count: got %d, want %d", len(result.CheckResults), len(profile.RequiredChecks))
	}
}

func TestEvaluate_C2_FailHigherChecks(t *testing.T) {
	// Default check fn passes only sandbox_test + schema_validation.
	// C2 requires additional checks — should fail.
	profile, _ := GetProfile("C2")
	c := Candidate{CandidateID: "ev-c2", SelfModClass: "C2"}

	result, err := Evaluate(c, *profile)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if result.Passed {
		t.Error("C2 evaluation should fail with default fake (capability_audit and above not implemented)")
	}
}

func TestEvaluateWithChecks_AllPass(t *testing.T) {
	profile, _ := GetProfile("C3")
	c := Candidate{CandidateID: "ev-c3-all", SelfModClass: "C3"}

	alwaysPass := func(_ Candidate, _ string) (bool, string) { return true, "" }

	result, err := EvaluateWithChecks(c, *profile, alwaysPass)
	if err != nil {
		t.Fatalf("EvaluateWithChecks: %v", err)
	}
	if !result.Passed {
		t.Error("expected all checks to pass")
	}
}

func TestEvaluateWithChecks_SingleFail(t *testing.T) {
	profile, _ := GetProfile("C1")
	c := Candidate{CandidateID: "ev-c1-fail", SelfModClass: "C1"}

	failCapability := func(_ Candidate, check string) (bool, string) {
		if check == CheckCapabilityAudit {
			return false, "capability not permitted"
		}
		return true, ""
	}

	result, err := EvaluateWithChecks(c, *profile, failCapability)
	if err != nil {
		t.Fatalf("EvaluateWithChecks: %v", err)
	}
	if result.Passed {
		t.Error("expected overall failure when capability_audit fails")
	}
	// Verify the failing check is recorded.
	found := false
	for _, cr := range result.CheckResults {
		if cr.CheckName == CheckCapabilityAudit && !cr.Passed {
			found = true
		}
	}
	if !found {
		t.Error("capability_audit failure not recorded in CheckResults")
	}
}

// ─── Canary Evidence ──────────────────────────────────────────────────────────

func TestCollectEvidence_BasicFields(t *testing.T) {
	ev := CollectEvidence("cand-canary-1", 25, 1000, 10, 50, 120)

	if ev.CandidateID != "cand-canary-1" {
		t.Errorf("CandidateID: got %q, want %q", ev.CandidateID, "cand-canary-1")
	}
	if ev.RolloutPct != 25 {
		t.Errorf("RolloutPct: got %d, want 25", ev.RolloutPct)
	}
	if ev.Observations != 1000 {
		t.Errorf("Observations: got %d, want 1000", ev.Observations)
	}
	if ev.ErrorCount != 10 {
		t.Errorf("ErrorCount: got %d, want 10", ev.ErrorCount)
	}
	if ev.LatencyP99Ms != 120 {
		t.Errorf("LatencyP99Ms: got %d, want 120", ev.LatencyP99Ms)
	}
	if len(ev.VerdictHistory) == 0 {
		t.Fatal("VerdictHistory should not be empty")
	}
}

func TestCollectEvidence_PhaseMapping(t *testing.T) {
	cases := []struct {
		pct   int
		phase string
	}{
		{0, "ramp_5"},
		{5, "ramp_5"},
		{6, "ramp_25"},
		{25, "ramp_25"},
		{26, "ramp_50"},
		{50, "ramp_50"},
		{51, "ramp_100"},
		{100, "ramp_100"},
	}

	for _, tc := range cases {
		ev := CollectEvidence("x", tc.pct, 100, 0, 10, 10)
		if ev.VerdictHistory[0].Phase != tc.phase {
			t.Errorf("pct=%d: phase=%q, want %q", tc.pct, ev.VerdictHistory[0].Phase, tc.phase)
		}
	}
}

func TestShouldEscalate_HealthyCanary(t *testing.T) {
	// 1 % error rate, p99 = 100 ms — should not escalate.
	ev := CollectEvidence("ok-1", 100, 1000, 10, 30, 100)
	escalate, reason := ShouldEscalate(ev)
	if escalate {
		t.Errorf("expected no escalation for healthy canary, got reason: %q", reason)
	}
}

func TestShouldEscalate_HighErrorRate(t *testing.T) {
	// 6 % error rate (60/1000) — exceeds 5 % threshold.
	ev := CollectEvidence("err-high", 100, 1000, 60, 30, 100)
	escalate, reason := ShouldEscalate(ev)
	if !escalate {
		t.Error("expected escalation for high error rate, got none")
	}
	if reason == "" {
		t.Error("escalation reason should not be empty")
	}
}

func TestShouldEscalate_HighP99(t *testing.T) {
	// p99 = 250 ms — exceeds 200 ms threshold.
	ev := CollectEvidence("p99-high", 50, 1000, 0, 60, 250)
	escalate, reason := ShouldEscalate(ev)
	if !escalate {
		t.Error("expected escalation for high p99, got none")
	}
	if reason == "" {
		t.Error("escalation reason should not be empty")
	}
}

func TestShouldEscalate_ExplicitFailVerdict(t *testing.T) {
	ev := CollectEvidence("fail-verdict", 5, 100, 0, 10, 10)
	// Inject a "fail" verdict directly.
	ev.VerdictHistory = append(ev.VerdictHistory, CanaryVerdict{
		Timestamp: time.Now(),
		Phase:     "ramp_5",
		Verdict:   "fail",
		Reason:    "smoke test failed",
	})

	escalate, reason := ShouldEscalate(ev)
	if !escalate {
		t.Error("expected escalation when verdict=fail in history")
	}
	if reason == "" {
		t.Error("escalation reason should not be empty")
	}
}

func TestShouldEscalate_NilEvidence(t *testing.T) {
	escalate, _ := ShouldEscalate(nil)
	if !escalate {
		t.Error("nil evidence should trigger escalation (fail-closed)")
	}
}

func TestShouldEscalate_ExactThresholdBoundary(t *testing.T) {
	// Exactly 5 % error rate — should NOT escalate (strict greater-than).
	ev := CollectEvidence("boundary", 100, 100, 5, 30, 100)
	escalate, _ := ShouldEscalate(ev)
	if escalate {
		t.Error("5%% error rate exactly at threshold should not escalate (strictly >5%%)")
	}

	// p99 exactly 200 ms — should NOT escalate.
	ev2 := CollectEvidence("boundary-p99", 100, 100, 0, 50, 200)
	escalate2, _ := ShouldEscalate(ev2)
	if escalate2 {
		t.Error("p99=200ms exactly at threshold should not escalate (strictly >200ms)")
	}
}

// ─── Promotion Policies ───────────────────────────────────────────────────────

func TestDefaultPromotionPolicies_AllClasses(t *testing.T) {
	policies := DefaultPromotionPolicies()
	classes := map[string]bool{"C0": false, "C1": false, "C2": false, "C3": false}
	for _, p := range policies {
		classes[p.SelfModClass] = true
	}
	for class, found := range classes {
		if !found {
			t.Errorf("DefaultPromotionPolicies missing class %q", class)
		}
	}
}

func TestGetPromotionPolicy_UnknownClass(t *testing.T) {
	if _, err := GetPromotionPolicy("X9"); err == nil {
		t.Fatal("expected error for unknown class, got nil")
	}
}

func TestCanPromote_C0_AutoPromote(t *testing.T) {
	// C0: no canary, no approval needed.
	policy, _ := GetPromotionPolicy("C0")
	c := Candidate{CandidateID: "c0-promo", SelfModClass: "C0", Status: CandidateReady}

	ok, reason := CanPromote(c, nil, *policy, 0, 0)
	if !ok {
		t.Errorf("C0 should auto-promote, got reason: %q", reason)
	}
}

func TestCanPromote_C0_WrongStatus(t *testing.T) {
	policy, _ := GetPromotionPolicy("C0")
	c := Candidate{CandidateID: "c0-queued", SelfModClass: "C0", Status: CandidateQueued}

	ok, reason := CanPromote(c, nil, *policy, 0, 0)
	if ok {
		t.Error("candidate not in CandidateReady status should not promote")
	}
	if reason == "" {
		t.Error("reason should not be empty when promotion is denied")
	}
}

func TestCanPromote_C1_RequiresCanaryAndApproval(t *testing.T) {
	policy, _ := GetPromotionPolicy("C1")
	c := Candidate{CandidateID: "c1-promo", SelfModClass: "C1", Status: CandidateReady}

	// Missing evidence.
	ok, _ := CanPromote(c, nil, *policy, 1, 20*time.Minute)
	if ok {
		t.Error("C1 without canary evidence should not promote")
	}

	// Evidence provided but rollout too low.
	ev := CollectEvidence("c1-promo", 10, 500, 0, 20, 80) // 10% rollout < 25% min
	ok, reason := CanPromote(c, ev, *policy, 1, 20*time.Minute)
	if ok {
		t.Errorf("C1 with <25%% rollout should not promote, reason: %q", reason)
	}

	// Good evidence + insufficient soak time.
	ev2 := CollectEvidence("c1-promo", 25, 1000, 5, 30, 90) // 5% error rate exactly at threshold
	ok, _ = CanPromote(c, ev2, *policy, 1, 5*time.Minute)   // only 5 min < 10 min
	if ok {
		t.Error("C1 with insufficient soak time should not promote")
	}

	// Good evidence + sufficient time + 1 approver.
	ev3 := CollectEvidence("c1-promo", 25, 1000, 0, 20, 80)
	ok, reason = CanPromote(c, ev3, *policy, 1, 15*time.Minute)
	if !ok {
		t.Errorf("C1 with good evidence and approval should promote, reason: %q", reason)
	}
}

func TestCanPromote_C1_MissingApproval(t *testing.T) {
	policy, _ := GetPromotionPolicy("C1")
	c := Candidate{CandidateID: "c1-noapprove", SelfModClass: "C1", Status: CandidateReady}
	ev := CollectEvidence("c1-noapprove", 25, 1000, 0, 20, 80)

	ok, reason := CanPromote(c, ev, *policy, 0, 15*time.Minute) // 0 approvers
	if ok {
		t.Errorf("C1 without approval should not promote, reason: %q", reason)
	}
	_ = reason
}

func TestCanPromote_C2_RequiresCanaryAndApproval(t *testing.T) {
	policy, _ := GetPromotionPolicy("C2")
	c := Candidate{CandidateID: "c2-promo", SelfModClass: "C2", Status: CandidateReady}

	// All gates met: ≥50% rollout, ≥30 min soak, ≥1 approver, healthy canary.
	ev := CollectEvidence("c2-promo", 50, 2000, 10, 40, 150)
	ok, reason := CanPromote(c, ev, *policy, 1, 35*time.Minute)
	if !ok {
		t.Errorf("C2 with all gates met should promote, reason: %q", reason)
	}
}

func TestCanPromote_C2_EscalatingCanaryBlocks(t *testing.T) {
	policy, _ := GetPromotionPolicy("C2")
	c := Candidate{CandidateID: "c2-escalate", SelfModClass: "C2", Status: CandidateReady}

	// High error rate forces escalation.
	ev := CollectEvidence("c2-escalate", 50, 1000, 100, 50, 180) // 10% error rate
	ok, reason := CanPromote(c, ev, *policy, 1, 35*time.Minute)
	if ok {
		t.Errorf("C2 with escalating canary should not promote, reason: %q", reason)
	}
	_ = reason
}

func TestCanPromote_C3_TwoApproversRequired(t *testing.T) {
	policy, _ := GetPromotionPolicy("C3")
	c := Candidate{CandidateID: "c3-promo", SelfModClass: "C3", Status: CandidateReady}

	ev := CollectEvidence("c3-promo", 100, 5000, 10, 50, 150)

	// 1 approver — insufficient.
	ok, reason := CanPromote(c, ev, *policy, 1, 70*time.Minute)
	if ok {
		t.Errorf("C3 with only 1 approver should not promote, reason: %q", reason)
	}
	_ = reason

	// 2 approvers — sufficient.
	ok, reason = CanPromote(c, ev, *policy, 2, 70*time.Minute)
	if !ok {
		t.Errorf("C3 with 2 approvers should promote, reason: %q", reason)
	}
}

func TestCanPromote_C3_FullCanaryRequired(t *testing.T) {
	policy, _ := GetPromotionPolicy("C3")
	c := Candidate{CandidateID: "c3-partial", SelfModClass: "C3", Status: CandidateReady}

	// 50% rollout — less than C3 min 100%.
	ev := CollectEvidence("c3-partial", 50, 2500, 5, 40, 120)
	ok, reason := CanPromote(c, ev, *policy, 2, 70*time.Minute)
	if ok {
		t.Errorf("C3 with <100%% rollout should not promote, reason: %q", reason)
	}
	_ = reason
}

func TestCanPromote_ClassMismatch(t *testing.T) {
	// Candidate is C1 but policy is C2.
	c2Policy, _ := GetPromotionPolicy("C2")
	c := Candidate{CandidateID: "mismatch", SelfModClass: "C1", Status: CandidateReady}

	ok, reason := CanPromote(c, nil, *c2Policy, 0, 0)
	if ok {
		t.Errorf("class mismatch should block promotion, reason: %q", reason)
	}
}

func TestCanPromote_EvidenceCandidateMismatch(t *testing.T) {
	policy, _ := GetPromotionPolicy("C1")
	c := Candidate{CandidateID: "real-cand", SelfModClass: "C1", Status: CandidateReady}
	ev := CollectEvidence("other-cand", 25, 1000, 0, 20, 80) // different CandidateID

	ok, reason := CanPromote(c, ev, *policy, 1, 15*time.Minute)
	if ok {
		t.Errorf("evidence for wrong candidate should block promotion, reason: %q", reason)
	}
	_ = reason
}

// ─── helpers ──────────────────────────────────────────────────────────────────

func containsCheck(checks []string, target string) bool {
	for _, c := range checks {
		if c == target {
			return true
		}
	}
	return false
}
