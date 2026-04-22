package contracts

import (
	"testing"
	"time"
)

func TestApprovalBindingValid(t *testing.T) {
	binding := NewApprovalBinding("b-001", "sha256:abc123", "approval-001", 10*time.Minute)

	now := binding.BoundAt.Add(5 * time.Minute)
	if !binding.IsValid(now) {
		t.Error("binding should be valid within validity window")
	}
}

func TestApprovalBindingExpired(t *testing.T) {
	binding := NewApprovalBinding("b-002", "sha256:abc123", "approval-001", 10*time.Minute)

	now := binding.BoundAt.Add(15 * time.Minute)
	if binding.IsValid(now) {
		t.Error("binding should be expired after validity window")
	}
}

func TestApprovalBindingDrift(t *testing.T) {
	binding := NewApprovalBinding("b-003", "sha256:abc123", "approval-001", 10*time.Minute)

	// No drift with same hash
	drifted := binding.CheckDrift("sha256:abc123")
	if drifted {
		t.Error("same hash should not trigger drift")
	}

	// Drift with different hash
	drifted = binding.CheckDrift("sha256:def456")
	if !drifted {
		t.Error("different hash should trigger drift")
	}

	// Binding should now be invalid
	if binding.IsValid(binding.BoundAt) {
		t.Error("drifted binding should be invalid")
	}

	if binding.DriftReason == "" {
		t.Error("drift reason should be set")
	}
}

func TestHashPlanDeterminism(t *testing.T) {
	plan := struct {
		Name    string `json:"name"`
		Version int    `json:"version"`
	}{"test-plan", 1}

	h1, err := HashPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := HashPlan(plan)
	if err != nil {
		t.Fatal(err)
	}

	if h1 != h2 {
		t.Error("same plan should produce same hash")
	}
	if h1 == "" {
		t.Error("hash should not be empty")
	}
}
