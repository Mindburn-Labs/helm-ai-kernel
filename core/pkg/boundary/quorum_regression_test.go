package boundary

// F-08 regression: a single credential must not be able to satisfy a
// multi-party approval quorum, and a requester must not approve their own
// request.
//
// Before this change the approver identity was a plain `actor` string taken
// from the request body, deduplicated by string equality. One holder of the
// shared admin key satisfied a 2-of-2 quorum by posting /approve twice with two
// different names — defeating the dual-control interlock that gates
// high-risk actions.

import (
	"time"

	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

func newApprovalForTest(t *testing.T, r *SurfaceRegistry, id string, quorum int, requester string) {
	t.Helper()
	now := time.Unix(1700000000, 0).UTC()
	if _, err := r.PutApproval(contracts.ApprovalCeremony{
		CreatedAt:   now,
		UpdatedAt:   now,
		ApprovalID:  id,
		Subject:     "payments.transfer",
		Action:      "EXECUTE",
		State:       contracts.ApprovalCeremonyPending,
		RequestedBy: requester,
		Quorum:      quorum,
	}); err != nil {
		t.Fatalf("PutApproval: %v", err)
	}
}

func TestF08_SingleCallerCannotSatisfyTwoPartyQuorum(t *testing.T) {
	r := NewSurfaceRegistry(func() time.Time { return time.Unix(1700000000, 0).UTC() })
	newApprovalForTest(t, r, "ap-1", 2, "requester@example")

	// One admin token, two asserted names — the original bypass.
	if _, err := r.TransitionApproval("ap-1", contracts.ApprovalCeremonyAllowed, "alice", "rcpt-1", "ok"); err != nil {
		t.Fatalf("first approve: %v", err)
	}
	got, err := r.TransitionApproval("ap-1", contracts.ApprovalCeremonyAllowed, "bob", "rcpt-1", "ok")
	if err != nil {
		t.Fatalf("second approve: %v", err)
	}

	if got.State == contracts.ApprovalCeremonyAllowed {
		t.Fatalf("a 2-of-2 quorum was satisfied by one caller asserting two names "+
			"(approvers=%v) — dual control is not enforced", got.Approvers)
	}
	if got.State != contracts.ApprovalCeremonyPending {
		t.Fatalf("state = %q, want Pending", got.State)
	}
	t.Logf("refused as expected: %s", got.Reason)
}

func TestF08_RequesterCannotApproveOwnRequest(t *testing.T) {
	r := NewSurfaceRegistry(func() time.Time { return time.Unix(1700000000, 0).UTC() })
	newApprovalForTest(t, r, "ap-2", 1, "carol@example")

	_, err := r.TransitionApproval("ap-2", contracts.ApprovalCeremonyAllowed, "carol@example", "rcpt-2", "ok")
	if err == nil {
		t.Fatal("the requester approved their own request — separation of duties is not enforced")
	}
	t.Logf("refused as expected: %v", err)
}

// Single-approver ceremonies are unaffected: this is the ordinary path and must
// keep working, otherwise the fix would just break approvals wholesale.
func TestF08_SingleApproverCeremonyStillCompletes(t *testing.T) {
	r := NewSurfaceRegistry(func() time.Time { return time.Unix(1700000000, 0).UTC() })
	newApprovalForTest(t, r, "ap-3", 1, "requester@example")

	got, err := r.TransitionApproval("ap-3", contracts.ApprovalCeremonyAllowed, "dave@example", "rcpt-3", "ok")
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if got.State != contracts.ApprovalCeremonyAllowed {
		t.Fatalf("single-approver ceremony did not complete: state=%q reason=%q", got.State, got.Reason)
	}
}

// Denial and revocation must remain available regardless of quorum: refusing to
// fake dual control must never strip the ability to stop something.
func TestF08_DenyAndRevokeRemainAvailableUnderMultiPartyQuorum(t *testing.T) {
	r := NewSurfaceRegistry(func() time.Time { return time.Unix(1700000000, 0).UTC() })
	newApprovalForTest(t, r, "ap-4", 3, "requester@example")

	got, err := r.TransitionApproval("ap-4", contracts.ApprovalCeremonyDenied, "eve@example", "", "not ok")
	if err != nil {
		t.Fatalf("deny: %v", err)
	}
	if got.State != contracts.ApprovalCeremonyDenied {
		t.Fatalf("deny was blocked under a multi-party quorum: state=%q", got.State)
	}
}
