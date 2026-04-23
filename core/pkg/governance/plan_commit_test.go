package governance

import (
	"testing"
	"time"
)

func immediateAfter(ts time.Time) func(time.Duration) <-chan time.Time {
	return func(time.Duration) <-chan time.Time {
		ch := make(chan time.Time, 1)
		ch <- ts
		return ch
	}
}

func TestPlanCommitController_SubmitAndApprove(t *testing.T) {
	pc := NewPlanCommitController()
	plan := &ExecutionPlan{
		PlanID:      "plan-1",
		EffectType:  "INFRA_DESTROY",
		EffectClass: "E4",
		Principal:   "agent-1",
		Description: "Destroy production DB",
	}

	ref, err := pc.SubmitPlan(plan)
	if err != nil {
		t.Fatalf("SubmitPlan failed: %v", err)
	}
	if ref.PlanID != "plan-1" {
		t.Errorf("ref.PlanID = %s, want plan-1", ref.PlanID)
	}
	if ref.PlanHash == "" {
		t.Error("ref.PlanHash must not be empty")
	}

	// Approve in background
	go func() {
		time.Sleep(10 * time.Millisecond)
		pc.Approve("plan-1", "admin")
	}()

	decision, err := pc.WaitForApproval(*ref, 1*time.Second)
	if err != nil {
		t.Fatalf("WaitForApproval failed: %v", err)
	}
	if decision.Status != PlanStatusApproved {
		t.Errorf("status = %s, want APPROVED", decision.Status)
	}
	if decision.Approver != "admin" {
		t.Errorf("approver = %s, want admin", decision.Approver)
	}
}

func TestPlanCommitController_SubmitAndReject(t *testing.T) {
	pc := NewPlanCommitController()
	plan := &ExecutionPlan{
		PlanID:      "plan-2",
		EffectType:  "SOFTWARE_PUBLISH",
		EffectClass: "E4",
		Principal:   "agent-2",
		Description: "Publish npm package",
	}

	ref, err := pc.SubmitPlan(plan)
	if err != nil {
		t.Fatalf("SubmitPlan failed: %v", err)
	}

	go func() {
		time.Sleep(10 * time.Millisecond)
		pc.Reject("plan-2", "security-lead", "unapproved version")
	}()

	decision, err := pc.WaitForApproval(*ref, 1*time.Second)
	if err != nil {
		t.Fatalf("WaitForApproval failed: %v", err)
	}
	if decision.Status != PlanStatusRejected {
		t.Errorf("status = %s, want REJECTED", decision.Status)
	}
	if decision.Reason != "unapproved version" {
		t.Errorf("reason = %s, want 'unapproved version'", decision.Reason)
	}
}

func TestPlanCommitController_Timeout(t *testing.T) {
	ts := time.Date(2026, 3, 8, 12, 0, 0, 0, time.UTC)
	pc := NewPlanCommitController().
		WithClock(func() time.Time { return ts }).
		WithAfter(immediateAfter(ts))
	plan := &ExecutionPlan{
		PlanID:      "plan-3",
		EffectType:  "DATA_EGRESS",
		EffectClass: "E4",
		Principal:   "agent-3",
		Description: "Transfer data",
	}

	ref, err := pc.SubmitPlan(plan)
	if err != nil {
		t.Fatalf("SubmitPlan failed: %v", err)
	}

	decision, err := pc.WaitForApproval(*ref, 50*time.Millisecond)
	if err != nil {
		t.Fatalf("WaitForApproval failed: %v", err)
	}
	if decision.Status != PlanStatusTimeout {
		t.Errorf("status = %s, want TIMEOUT", decision.Status)
	}
	if !decision.Timestamp.Equal(ts) {
		t.Errorf("timeout timestamp = %v, want %v", decision.Timestamp, ts)
	}
}

func TestPlanCommitController_DoubleSubmitError(t *testing.T) {
	pc := NewPlanCommitController()
	plan := &ExecutionPlan{PlanID: "dup", EffectType: "X"}

	_, err := pc.SubmitPlan(plan)
	if err != nil {
		t.Fatalf("first submit failed: %v", err)
	}
	_, err = pc.SubmitPlan(plan)
	if err == nil {
		t.Error("duplicate plan submission should fail")
	}
}

func TestPlanCommitController_NilPlanError(t *testing.T) {
	pc := NewPlanCommitController()
	_, err := pc.SubmitPlan(nil)
	if err == nil {
		t.Error("nil plan should cause error")
	}
}

func TestPlanCommitController_EmptyIDError(t *testing.T) {
	pc := NewPlanCommitController()
	_, err := pc.SubmitPlan(&ExecutionPlan{})
	if err == nil {
		t.Error("empty PlanID should cause error")
	}
}

func TestPlanCommitController_Abort(t *testing.T) {
	pc := NewPlanCommitController()
	plan := &ExecutionPlan{PlanID: "abort-me", EffectType: "X"}
	ref, _ := pc.SubmitPlan(plan)

	go func() {
		time.Sleep(10 * time.Millisecond)
		pc.Abort("abort-me")
	}()

	decision, err := pc.WaitForApproval(*ref, 1*time.Second)
	if err != nil {
		t.Fatalf("WaitForApproval failed: %v", err)
	}
	if decision.Status != PlanStatusAborted {
		t.Errorf("status = %s, want ABORTED", decision.Status)
	}
}

func TestPlanCommitController_PendingCount(t *testing.T) {
	pc := NewPlanCommitController()
	pc.SubmitPlan(&ExecutionPlan{PlanID: "p1", EffectType: "X"})
	pc.SubmitPlan(&ExecutionPlan{PlanID: "p2", EffectType: "Y"})

	if pc.PendingCount() != 2 {
		t.Errorf("pending = %d, want 2", pc.PendingCount())
	}

	pc.Approve("p1", "admin")
	if pc.PendingCount() != 1 {
		t.Errorf("pending after approve = %d, want 1", pc.PendingCount())
	}
}

func TestPlanCommitController_HashMismatch(t *testing.T) {
	pc := NewPlanCommitController()
	plan := &ExecutionPlan{PlanID: "h1", EffectType: "X"}
	pc.SubmitPlan(plan)

	badRef := PlanRef{PlanID: "h1", PlanHash: "wrong-hash"}
	_, err := pc.WaitForApproval(badRef, 50*time.Millisecond)
	if err == nil {
		t.Error("wrong hash should error")
	}
}
