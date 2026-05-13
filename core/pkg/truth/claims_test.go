package truth_test

import (
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/truth"
)

func TestClaimRegistry_RegisterAndGet(t *testing.T) {
	reg := truth.NewInMemoryClaimRegistry()

	claim := &truth.ClaimRecord{
		ClaimID:            "c1",
		Statement:          "API returns 200 for /health",
		VerificationMethod: "HTTP GET",
		Owner:              "infra-team",
	}
	if err := reg.Register(claim); err != nil {
		t.Fatalf("register failed: %v", err)
	}

	got, err := reg.Get("c1")
	if err != nil {
		t.Fatalf("get failed: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil")
	}
	if got.Statement != "API returns 200 for /health" {
		t.Fatalf("statement mismatch: %s", got.Statement)
	}
	if got.Status != truth.ClaimStatusPending {
		t.Fatalf("expected PENDING, got %s", got.Status)
	}
}

func TestClaimRegistry_DuplicateRegister(t *testing.T) {
	reg := truth.NewInMemoryClaimRegistry()

	claim := &truth.ClaimRecord{ClaimID: "c1", Statement: "test"}
	_ = reg.Register(claim)
	if err := reg.Register(claim); err == nil {
		t.Fatal("expected duplicate error")
	}
}

func TestClaimRegistry_Verify(t *testing.T) {
	now := time.Date(2026, 4, 2, 12, 0, 0, 0, time.UTC)
	reg := truth.NewInMemoryClaimRegistry().WithClock(fixedClock(now))

	_ = reg.Register(&truth.ClaimRecord{ClaimID: "c1", Statement: "test"})
	if err := reg.Verify("c1", []string{"sha256:proof1", "sha256:proof2"}); err != nil {
		t.Fatalf("verify failed: %v", err)
	}

	got, _ := reg.Get("c1")
	if got.Status != truth.ClaimStatusVerified {
		t.Fatalf("expected VERIFIED, got %s", got.Status)
	}
	if len(got.EvidenceRefs) != 2 {
		t.Fatalf("expected 2 evidence refs, got %d", len(got.EvidenceRefs))
	}
	if got.VerifiedAt != now {
		t.Fatalf("verified_at mismatch: %v", got.VerifiedAt)
	}
}

func TestClaimRegistry_Refute(t *testing.T) {
	reg := truth.NewInMemoryClaimRegistry()

	_ = reg.Register(&truth.ClaimRecord{ClaimID: "c1", Statement: "test"})
	if err := reg.Refute("c1", "Evidence shows otherwise"); err != nil {
		t.Fatalf("refute failed: %v", err)
	}

	got, _ := reg.Get("c1")
	if got.Status != truth.ClaimStatusRefuted {
		t.Fatalf("expected REFUTED, got %s", got.Status)
	}
	if got.RefutationReason != "Evidence shows otherwise" {
		t.Fatalf("refutation reason mismatch: %s", got.RefutationReason)
	}
}

func TestClaimRegistry_CannotVerifyRefuted(t *testing.T) {
	reg := truth.NewInMemoryClaimRegistry()

	_ = reg.Register(&truth.ClaimRecord{ClaimID: "c1", Statement: "test"})
	_ = reg.Refute("c1", "wrong")

	if err := reg.Verify("c1", []string{"sha256:proof"}); err == nil {
		t.Fatal("expected error verifying refuted claim")
	}
}

func TestClaimRegistry_VerifyNotFound(t *testing.T) {
	reg := truth.NewInMemoryClaimRegistry()
	if err := reg.Verify("nonexistent", []string{}); err == nil {
		t.Fatal("expected not found error")
	}
}

func TestClaimRegistry_RefuteNotFound(t *testing.T) {
	reg := truth.NewInMemoryClaimRegistry()
	if err := reg.Refute("nonexistent", "reason"); err == nil {
		t.Fatal("expected not found error")
	}
}

func TestClaimRegistry_GetNotFound(t *testing.T) {
	reg := truth.NewInMemoryClaimRegistry()
	got, err := reg.Get("nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatal("expected nil for not found")
	}
}

func TestClaimRegistry_ListByStatus(t *testing.T) {
	reg := truth.NewInMemoryClaimRegistry()

	_ = reg.Register(&truth.ClaimRecord{ClaimID: "c1", Statement: "test1"})
	_ = reg.Register(&truth.ClaimRecord{ClaimID: "c2", Statement: "test2"})
	_ = reg.Register(&truth.ClaimRecord{ClaimID: "c3", Statement: "test3"})
	_ = reg.Verify("c1", []string{"proof"})
	_ = reg.Refute("c2", "wrong")

	pending, _ := reg.ListByStatus(truth.ClaimStatusPending)
	if len(pending) != 1 {
		t.Fatalf("expected 1 pending, got %d", len(pending))
	}

	verified, _ := reg.ListByStatus(truth.ClaimStatusVerified)
	if len(verified) != 1 {
		t.Fatalf("expected 1 verified, got %d", len(verified))
	}

	refuted, _ := reg.ListByStatus(truth.ClaimStatusRefuted)
	if len(refuted) != 1 {
		t.Fatalf("expected 1 refuted, got %d", len(refuted))
	}
}

func TestClaimRegistry_ListAll(t *testing.T) {
	reg := truth.NewInMemoryClaimRegistry()

	_ = reg.Register(&truth.ClaimRecord{ClaimID: "c1", Statement: "test1"})
	_ = reg.Register(&truth.ClaimRecord{ClaimID: "c2", Statement: "test2"})

	all, _ := reg.ListAll()
	if len(all) != 2 {
		t.Fatalf("expected 2, got %d", len(all))
	}
}

func TestClaimRegistry_RegisterForcesStatus(t *testing.T) {
	reg := truth.NewInMemoryClaimRegistry()

	// Even if caller sets status, Register forces PENDING.
	claim := &truth.ClaimRecord{
		ClaimID:   "c1",
		Statement: "test",
		Status:    truth.ClaimStatusVerified, // Should be overridden.
	}
	_ = reg.Register(claim)

	got, _ := reg.Get("c1")
	if got.Status != truth.ClaimStatusPending {
		t.Fatalf("expected PENDING, got %s", got.Status)
	}
}

func TestClaimRegistry_ReVerify(t *testing.T) {
	reg := truth.NewInMemoryClaimRegistry()

	_ = reg.Register(&truth.ClaimRecord{ClaimID: "c1", Statement: "test"})
	_ = reg.Verify("c1", []string{"proof1"})
	// Re-verify with additional evidence.
	if err := reg.Verify("c1", []string{"proof2"}); err != nil {
		t.Fatalf("re-verify failed: %v", err)
	}

	got, _ := reg.Get("c1")
	if len(got.EvidenceRefs) != 2 {
		t.Fatalf("expected 2 evidence refs after re-verify, got %d", len(got.EvidenceRefs))
	}
}
