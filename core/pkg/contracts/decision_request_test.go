package contracts_test

import (
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// ──────────────────────────────────────────────────────────────
// Validation tests
// ──────────────────────────────────────────────────────────────

func TestDecisionRequest_Validate_Valid(t *testing.T) {
	dr := validDecisionRequest()
	if err := dr.Validate(); err != nil {
		t.Fatalf("expected valid, got error: %v", err)
	}
}

func TestDecisionRequest_Validate_MissingRequestID(t *testing.T) {
	dr := validDecisionRequest()
	dr.RequestID = ""
	if err := dr.Validate(); err == nil {
		t.Fatal("expected error for missing request_id")
	}
}

func TestDecisionRequest_Validate_MissingTitle(t *testing.T) {
	dr := validDecisionRequest()
	dr.Title = ""
	if err := dr.Validate(); err == nil {
		t.Fatal("expected error for missing title")
	}
}

func TestDecisionRequest_Validate_TitleTooLong(t *testing.T) {
	dr := validDecisionRequest()
	dr.Title = string(make([]byte, 121)) // 121 chars
	if err := dr.Validate(); err == nil {
		t.Fatal("expected error for title > 120 chars")
	}
}

func TestDecisionRequest_Validate_MissingKind(t *testing.T) {
	dr := validDecisionRequest()
	dr.Kind = ""
	if err := dr.Validate(); err == nil {
		t.Fatal("expected error for missing kind")
	}
}

func TestDecisionRequest_Validate_TooFewOptions(t *testing.T) {
	dr := validDecisionRequest()
	dr.Options = dr.Options[:1] // Only 1 concrete option
	if err := dr.Validate(); err == nil {
		t.Fatal("expected error for < 2 concrete options")
	}
}

func TestDecisionRequest_Validate_TooManyOptions(t *testing.T) {
	dr := validDecisionRequest()
	// Add options to get 8 concrete options
	for i := 3; i <= 8; i++ {
		dr.Options = append(dr.Options, contracts.DecisionOption{
			ID:    "opt-" + string(rune('a'+i)),
			Label: "Option " + string(rune('A'+i)),
		})
	}
	if err := dr.Validate(); err == nil {
		t.Fatal("expected error for > 7 concrete options")
	}
}

func TestDecisionRequest_Validate_MetaOptionsNotCounted(t *testing.T) {
	dr := validDecisionRequest()
	// Add skip + something_else — these should NOT count toward the 7 limit
	dr.Options = append(dr.Options,
		contracts.DecisionOption{ID: "skip", Label: "Skip", IsSkip: true},
		contracts.DecisionOption{ID: "other", Label: "Something else", IsSomethingElse: true},
	)
	if err := dr.Validate(); err != nil {
		t.Fatalf("meta options should not count toward limit: %v", err)
	}
}

func TestDecisionRequest_Validate_DuplicateOptionID(t *testing.T) {
	dr := validDecisionRequest()
	dr.Options[1].ID = dr.Options[0].ID // duplicate
	if err := dr.Validate(); err == nil {
		t.Fatal("expected error for duplicate option ID")
	}
}

func TestDecisionRequest_Validate_EmptyOptionID(t *testing.T) {
	dr := validDecisionRequest()
	dr.Options[0].ID = ""
	if err := dr.Validate(); err == nil {
		t.Fatal("expected error for empty option ID")
	}
}

// ──────────────────────────────────────────────────────────────
// Resolution tests
// ──────────────────────────────────────────────────────────────

func TestDecisionRequest_Resolve_Success(t *testing.T) {
	dr := validDecisionRequest()
	err := dr.Resolve("opt-a", "operator@mindburn.org")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if dr.Status != contracts.DecisionStatusResolved {
		t.Errorf("expected RESOLVED, got %s", dr.Status)
	}
	if dr.ResolvedOptionID != "opt-a" {
		t.Errorf("expected opt-a, got %s", dr.ResolvedOptionID)
	}
	if dr.ResolvedBy != "operator@mindburn.org" {
		t.Errorf("expected operator@mindburn.org, got %s", dr.ResolvedBy)
	}
	if dr.ResolvedAt == nil {
		t.Fatal("ResolvedAt must be set")
	}
}

func TestDecisionRequest_Resolve_InvalidOption(t *testing.T) {
	dr := validDecisionRequest()
	err := dr.Resolve("nonexistent", "operator@mindburn.org")
	if err == nil {
		t.Fatal("expected error for unknown option ID")
	}
}

func TestDecisionRequest_Resolve_NotPending(t *testing.T) {
	dr := validDecisionRequest()
	_ = dr.Resolve("opt-a", "operator@mindburn.org")

	// Try resolving again — should fail
	err := dr.Resolve("opt-b", "other@mindburn.org")
	if err == nil {
		t.Fatal("expected error for resolving non-pending request")
	}
}

func TestDecisionRequest_IsBlocking(t *testing.T) {
	dr := validDecisionRequest()
	if !dr.IsBlocking() {
		t.Fatal("pending request should be blocking")
	}

	_ = dr.Resolve("opt-a", "operator@mindburn.org")
	if dr.IsBlocking() {
		t.Fatal("resolved request should not be blocking")
	}
}

// ──────────────────────────────────────────────────────────────
// Skip tests
// ──────────────────────────────────────────────────────────────

func TestDecisionRequest_Skip_Allowed(t *testing.T) {
	dr := validDecisionRequest()
	dr.SkipAllowed = true

	err := dr.Skip("operator@mindburn.org")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dr.Status != contracts.DecisionStatusSkipped {
		t.Errorf("expected SKIPPED, got %s", dr.Status)
	}
}

func TestDecisionRequest_Skip_NotAllowed(t *testing.T) {
	dr := validDecisionRequest()
	dr.SkipAllowed = false

	err := dr.Skip("operator@mindburn.org")
	if err == nil {
		t.Fatal("expected error for skip not allowed")
	}
}

func TestDecisionRequest_Skip_NotPending(t *testing.T) {
	dr := validDecisionRequest()
	dr.SkipAllowed = true
	_ = dr.Resolve("opt-a", "operator@mindburn.org")

	err := dr.Skip("other@mindburn.org")
	if err == nil {
		t.Fatal("expected error for skipping non-pending request")
	}
}

// ──────────────────────────────────────────────────────────────
// Expiry tests
// ──────────────────────────────────────────────────────────────

func TestDecisionRequest_CheckExpiry_Expired(t *testing.T) {
	dr := validDecisionRequest()
	dr.ExpiresAt = time.Now().UTC().Add(-1 * time.Hour) // Already expired

	expired := dr.CheckExpiry()
	if !expired {
		t.Fatal("expected decision to be expired")
	}
	if dr.Status != contracts.DecisionStatusExpired {
		t.Errorf("expected EXPIRED, got %s", dr.Status)
	}
}

func TestDecisionRequest_CheckExpiry_NotExpired(t *testing.T) {
	dr := validDecisionRequest()
	dr.ExpiresAt = time.Now().UTC().Add(1 * time.Hour) // Future

	expired := dr.CheckExpiry()
	if expired {
		t.Fatal("expected decision to not be expired")
	}
	if dr.Status != contracts.DecisionStatusPending {
		t.Errorf("expected PENDING, got %s", dr.Status)
	}
}

func TestDecisionRequest_CheckExpiry_NoExpiry(t *testing.T) {
	dr := validDecisionRequest()
	// ExpiresAt is zero (no expiry set)

	expired := dr.CheckExpiry()
	if expired {
		t.Fatal("expected decision with no expiry to not be expired")
	}
}

func TestDecisionRequest_CheckExpiry_AlreadyResolved(t *testing.T) {
	dr := validDecisionRequest()
	_ = dr.Resolve("opt-a", "operator@mindburn.org")
	dr.ExpiresAt = time.Now().UTC().Add(-1 * time.Hour)

	expired := dr.CheckExpiry()
	if expired {
		t.Fatal("resolved decisions should not become expired")
	}
}

// ──────────────────────────────────────────────────────────────
// Concurrency test — multiple runs produce distinct decisions
// ──────────────────────────────────────────────────────────────

func TestDecisionRequest_ConcurrentRuns(t *testing.T) {
	// Simulate 3 concurrent runs each producing a blocker
	decisions := make([]*contracts.DecisionRequest, 3)
	for i := range decisions {
		dr := validDecisionRequest()
		dr.RequestID = "dr-" + string(rune('0'+i))
		dr.RunID = "run-" + string(rune('0'+i))
		decisions[i] = &dr
	}

	// All should be independently resolvable
	for i, dr := range decisions {
		optID := "opt-a"
		if i%2 == 1 {
			optID = "opt-b"
		}
		if err := dr.Resolve(optID, "operator"); err != nil {
			t.Fatalf("decision %d failed to resolve: %v", i, err)
		}
	}

	// Verify all are resolved with correct options
	for i, dr := range decisions {
		if dr.Status != contracts.DecisionStatusResolved {
			t.Errorf("decision %d should be RESOLVED, got %s", i, dr.Status)
		}
	}
}

// ──────────────────────────────────────────────────────────────
// Kind coverage
// ──────────────────────────────────────────────────────────────

func TestDecisionRequestKind_AllValues(t *testing.T) {
	kinds := []contracts.DecisionRequestKind{
		contracts.DecisionKindApproval,
		contracts.DecisionKindPolicyChoice,
		contracts.DecisionKindClarification,
		contracts.DecisionKindSpending,
		contracts.DecisionKindIrreversible,
		contracts.DecisionKindSensitivePolicy,
		contracts.DecisionKindNaming,
	}

	for _, k := range kinds {
		if k == "" {
			t.Error("kind constant must not be empty string")
		}
	}

	if len(kinds) != 7 {
		t.Errorf("expected 7 kind values, got %d", len(kinds))
	}
}

// ──────────────────────────────────────────────────────────────
// Test helper
// ──────────────────────────────────────────────────────────────

func validDecisionRequest() contracts.DecisionRequest {
	return contracts.DecisionRequest{
		RequestID: "dr-test-001",
		Kind:      contracts.DecisionKindApproval,
		Title:     "Approve production deployment",
		Options: []contracts.DecisionOption{
			{ID: "opt-a", Label: "Approve", IsDefault: true},
			{ID: "opt-b", Label: "Deny"},
		},
		RunID:     "run-42",
		Priority:  contracts.DecisionPriorityNormal,
		Status:    contracts.DecisionStatusPending,
		CreatedAt: time.Now().UTC(),
	}
}
