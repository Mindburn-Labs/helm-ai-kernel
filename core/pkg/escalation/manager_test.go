package escalation

import (
	"context"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

func testDecision() *contracts.JudgmentDecision {
	return &contracts.JudgmentDecision{
		Verdict:         contracts.VerdictJudgmentRequired,
		MatchedRule:     "R001",
		TaxonomyVersion: "1.0.0",
		Reasoning:       "funds transfer requires approval",
		EscalationTemplate: &contracts.EscalationTemplate{
			ApproverRoles:  []string{"finance-admin"},
			Quorum:         1,
			TimeoutSeconds: 300,
			OnTimeout:      "deny",
		},
	}
}

func testHeldEffect() contracts.HeldEffect {
	return contracts.HeldEffect{
		EffectType:    "FUNDS_TRANSFER",
		EffectClass:   "E3",
		PayloadHash:   "sha256:abc123",
		Description:   "Transfer $500 to vendor-001",
		EstimatedCost: 50000,
		BlastRadius:   "single_record",
	}
}

func testEscalationContext() contracts.EscalationContext {
	return contracts.EscalationContext{
		Plan: &contracts.EscalationPlan{
			Summary: "Transfer funds to vendor-001",
			Steps:   []string{"Validate vendor", "Execute transfer", "Confirm receipt"},
		},
		Risks: []contracts.IdentifiedRisk{
			{Category: "financial", Severity: "medium", Description: "Vendor payment of $500"},
		},
		RollbackPlan: &contracts.RollbackPlan{
			Strategy:    "automatic",
			Description: "Reverse transfer within 24 hours",
			TimeWindow:  86400,
		},
	}
}

func TestCreateIntent(t *testing.T) {
	mgr := NewManager()

	intent, err := mgr.CreateIntent(
		context.Background(),
		testDecision(),
		testHeldEffect(),
		testEscalationContext(),
		"run-001",
		"env-001",
	)
	if err != nil {
		t.Fatal(err)
	}
	if intent.IntentID == "" {
		t.Fatal("expected intent ID")
	}
	if intent.Status != contracts.EscalationStatusPending {
		t.Fatalf("expected PENDING, got %s", intent.Status)
	}
	if intent.HeldEffect.EffectType != "FUNDS_TRANSFER" {
		t.Fatal("expected FUNDS_TRANSFER")
	}
	if mgr.PendingCount() != 1 {
		t.Fatalf("expected 1 pending, got %d", mgr.PendingCount())
	}
}

func TestApproveIntent(t *testing.T) {
	mgr := NewManager()

	intent, _ := mgr.CreateIntent(
		context.Background(),
		testDecision(),
		testHeldEffect(),
		testEscalationContext(),
		"run-001", "env-001",
	)

	receipt, err := mgr.Approve(context.Background(), intent.IntentID, "admin-001")
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Outcome != contracts.EscalationStatusApproved {
		t.Fatalf("expected APPROVED, got %s", receipt.Outcome)
	}
	if receipt.ApprovedBy[0] != "admin-001" {
		t.Fatal("expected admin-001")
	}
	if receipt.ContentHash == "" {
		t.Fatal("expected content hash")
	}
	if mgr.PendingCount() != 0 {
		t.Fatalf("expected 0 pending, got %d", mgr.PendingCount())
	}
}

func TestDenyIntent(t *testing.T) {
	mgr := NewManager()

	intent, _ := mgr.CreateIntent(
		context.Background(),
		testDecision(),
		testHeldEffect(),
		testEscalationContext(),
		"run-001", "env-001",
	)

	receipt, err := mgr.Deny(context.Background(), intent.IntentID, "admin-002", "Too risky")
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Outcome != contracts.EscalationStatusDenied {
		t.Fatalf("expected DENIED, got %s", receipt.Outcome)
	}
	if receipt.DeniedBy != "admin-002" {
		t.Fatal("expected admin-002")
	}
	if receipt.DenyReason != "Too risky" {
		t.Fatal("expected reason")
	}
}

func TestTimeoutIntent(t *testing.T) {
	now := time.Now()
	elapsed := int64(0)
	mgr := NewManager().WithClock(func() time.Time {
		return now.Add(time.Duration(elapsed) * time.Second)
	})

	intent, _ := mgr.CreateIntent(
		context.Background(),
		testDecision(),
		testHeldEffect(),
		testEscalationContext(),
		"run-001", "env-001",
	)

	// Advance past timeout (300s)
	elapsed = 301

	receipts, err := mgr.CheckTimeouts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(receipts) != 1 {
		t.Fatalf("expected 1 timed-out receipt, got %d", len(receipts))
	}
	if receipts[0].Outcome != contracts.EscalationStatusTimedOut {
		t.Fatalf("expected TIMED_OUT, got %s", receipts[0].Outcome)
	}

	// Check intent status updated
	updated, _ := mgr.GetIntent(intent.IntentID)
	if updated.Status != contracts.EscalationStatusTimedOut {
		t.Fatalf("expected intent status TIMED_OUT, got %s", updated.Status)
	}
}

func TestDoubleApproveRejected(t *testing.T) {
	mgr := NewManager()

	intent, _ := mgr.CreateIntent(
		context.Background(),
		testDecision(),
		testHeldEffect(),
		testEscalationContext(),
		"run-001", "env-001",
	)

	_, err := mgr.Approve(context.Background(), intent.IntentID, "admin-001")
	if err != nil {
		t.Fatal(err)
	}

	// Second approval should fail
	_, err = mgr.Approve(context.Background(), intent.IntentID, "admin-002")
	if err == nil {
		t.Fatal("expected error on double approve")
	}
}

func TestApproveExpiredReturnsTimeout(t *testing.T) {
	now := time.Now()
	mgr := NewManager().WithClock(func() time.Time {
		return now.Add(400 * time.Second) // Past 300s timeout
	})

	// Create with normal time
	mgr2 := NewManager()
	intent, _ := mgr2.CreateIntent(
		context.Background(),
		testDecision(),
		testHeldEffect(),
		testEscalationContext(),
		"run-001", "env-001",
	)

	// Copy intent to expired manager
	mgr.mu.Lock()
	mgr.intents[intent.IntentID] = intent
	mgr.mu.Unlock()

	receipt, err := mgr.Approve(context.Background(), intent.IntentID, "admin-001")
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Outcome != contracts.EscalationStatusTimedOut {
		t.Fatalf("expected TIMED_OUT for expired approval, got %s", receipt.Outcome)
	}
}

// TestApproveQuorumRequiresDistinctApprovers is the separation-of-duties gate:
// a satisfied quorum can NEVER be recorded from a single approver.
//
// MUTATION CHECK: remove the `if len(set) < quorum { return nil, nil }` guard in
// Approve (so any single approver falls through to APPROVED) and this test fails
// at the first assertion, proving it pins the distinct-approver requirement.
func TestApproveQuorumRequiresDistinctApprovers(t *testing.T) {
	mgr := NewManager()

	dec := testDecision()
	dec.EscalationTemplate.Quorum = 2 // require two DISTINCT approvers

	intent, err := mgr.CreateIntent(
		context.Background(),
		dec,
		testHeldEffect(),
		testEscalationContext(),
		"run-001", "env-001",
	)
	if err != nil {
		t.Fatal(err)
	}

	// One approver must NOT satisfy a 2-party quorum.
	receipt, err := mgr.Approve(context.Background(), intent.IntentID, "approver-1")
	if err != nil {
		t.Fatal(err)
	}
	if receipt != nil {
		t.Fatalf("a single approver must not resolve a quorum-2 intent, got receipt %+v", receipt)
	}
	got, _ := mgr.GetIntent(intent.IntentID)
	if got.Status != contracts.EscalationStatusPending {
		t.Fatalf("intent must remain PENDING after one of two approvers, got %s", got.Status)
	}

	// The same approver repeating must be rejected — it cannot self-satisfy quorum.
	if _, err := mgr.Approve(context.Background(), intent.IntentID, "approver-1"); err == nil {
		t.Fatal("expected error when the same approver approves twice")
	}
	got, _ = mgr.GetIntent(intent.IntentID)
	if got.Status != contracts.EscalationStatusPending {
		t.Fatalf("intent must still be PENDING after a duplicate approval, got %s", got.Status)
	}

	// A second DISTINCT approver satisfies the quorum.
	receipt, err = mgr.Approve(context.Background(), intent.IntentID, "approver-2")
	if err != nil {
		t.Fatal(err)
	}
	if receipt == nil || receipt.Outcome != contracts.EscalationStatusApproved {
		t.Fatalf("two distinct approvers must satisfy quorum-2, got %+v", receipt)
	}
	if len(receipt.ApprovedBy) != 2 {
		t.Fatalf("expected 2 distinct approvers recorded, got %v", receipt.ApprovedBy)
	}
	if receipt.ApprovedBy[0] != "approver-1" || receipt.ApprovedBy[1] != "approver-2" {
		t.Fatalf("expected [approver-1 approver-2], got %v", receipt.ApprovedBy)
	}
	if mgr.PendingCount() != 0 {
		t.Fatalf("expected 0 pending after quorum met, got %d", mgr.PendingCount())
	}
}
