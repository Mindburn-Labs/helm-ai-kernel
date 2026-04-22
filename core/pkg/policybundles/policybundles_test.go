package policybundles

import (
	"context"
	"testing"
	"time"
)

func TestBundleManager_CreateAndGet(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryBundleStore()
	mgr := NewBundleManager(store)

	bundle := &PolicyBundle{
		BundleID:     "test-bundle-1",
		Name:         "Test Bundle",
		Jurisdiction: "US",
		Category:     "retention",
		Version:      1,
		Rules: []PolicyRule{
			{
				RuleID:      "r-1",
				Name:        "Rule One",
				Description: "First rule",
				Condition:   "resource.type == 'secret'",
				Action:      "encrypt",
				Priority:    100,
			},
		},
	}

	if err := mgr.CreateBundle(ctx, bundle); err != nil {
		t.Fatalf("CreateBundle failed: %v", err)
	}

	// Should be in draft status.
	got, err := mgr.GetBundle(ctx, "test-bundle-1")
	if err != nil {
		t.Fatalf("GetBundle failed: %v", err)
	}
	if got.Status != BundleStatusDraft {
		t.Errorf("expected status draft, got %s", got.Status)
	}
	if got.ContentHash == "" {
		t.Error("content hash should be computed")
	}
}

func TestBundleManager_CreateValidation(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryBundleStore()
	mgr := NewBundleManager(store)

	err := mgr.CreateBundle(ctx, &PolicyBundle{Name: "No ID"})
	if err == nil {
		t.Error("create without bundle_id should fail")
	}
}

func TestBundleManager_AssignToTenant(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryBundleStore()
	mgr := NewBundleManager(store)

	mgr.CreateBundle(ctx, &PolicyBundle{
		BundleID:     "b-1",
		Name:         "Bundle",
		Jurisdiction: "EU",
		Category:     "approval",
		Version:      1,
		Rules:        []PolicyRule{{RuleID: "r-1", Name: "R1", Condition: "true", Action: "log", Priority: 1}},
	})

	err := mgr.AssignBundle(ctx, &BundleAssignment{
		AssignmentID: "a-1",
		BundleID:     "b-1",
		TenantID:     "t-001",
	})
	if err != nil {
		t.Fatalf("AssignBundle failed: %v", err)
	}

	assignments, err := mgr.ListAssignments(ctx, "t-001")
	if err != nil {
		t.Fatalf("ListAssignments failed: %v", err)
	}
	if len(assignments) != 1 {
		t.Errorf("expected 1 assignment, got %d", len(assignments))
	}

	// Assign nonexistent bundle should fail.
	err = mgr.AssignBundle(ctx, &BundleAssignment{
		AssignmentID: "a-2",
		BundleID:     "nonexistent",
		TenantID:     "t-001",
	})
	if err == nil {
		t.Error("assigning nonexistent bundle should fail")
	}
}

func TestBundleManager_VersionIncrement(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryBundleStore()
	mgr := NewBundleManager(store)

	mgr.CreateBundle(ctx, &PolicyBundle{
		BundleID:     "b-versioned",
		Name:         "Versioned Bundle",
		Jurisdiction: "global",
		Category:     "retention",
		Version:      1,
		Rules:        []PolicyRule{{RuleID: "r-1", Name: "Old Rule", Condition: "true", Action: "log", Priority: 1}},
	})

	v1, _ := mgr.GetBundle(ctx, "b-versioned")
	v1Hash := v1.ContentHash

	// Create new version with different rules.
	newRules := []PolicyRule{
		{RuleID: "r-2", Name: "New Rule", Condition: "false", Action: "deny", Priority: 50},
	}
	v2, err := mgr.NewVersion(ctx, "b-versioned", newRules)
	if err != nil {
		t.Fatalf("NewVersion failed: %v", err)
	}

	if v2.Version != 2 {
		t.Errorf("expected version 2, got %d", v2.Version)
	}
	if v2.ContentHash == v1Hash {
		t.Error("new version should have different content hash")
	}
	if v2.Status != BundleStatusDraft {
		t.Errorf("new version should be draft, got %s", v2.Status)
	}
}

func TestBundleManager_ContentHashDeterminism(t *testing.T) {
	ctx := context.Background()

	// Create the same bundle twice and verify hashes match.
	rules := []PolicyRule{
		{RuleID: "r-b", Name: "Rule B", Description: "Second", Condition: "b", Action: "deny", Priority: 200},
		{RuleID: "r-a", Name: "Rule A", Description: "First", Condition: "a", Action: "log", Priority: 100},
	}

	store1 := NewInMemoryBundleStore()
	mgr1 := NewBundleManager(store1).WithClock(func() time.Time {
		return time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	})
	mgr1.CreateBundle(ctx, &PolicyBundle{
		BundleID:     "det-test",
		Name:         "Determinism Test",
		Jurisdiction: "global",
		Category:     "retention",
		Version:      1,
		Rules:        rules,
	})

	store2 := NewInMemoryBundleStore()
	mgr2 := NewBundleManager(store2).WithClock(func() time.Time {
		return time.Date(2026, 4, 2, 0, 0, 0, 0, time.UTC) // Different time
	})
	// Copy rules to avoid shared slice mutation.
	rules2 := []PolicyRule{
		{RuleID: "r-b", Name: "Rule B", Description: "Second", Condition: "b", Action: "deny", Priority: 200},
		{RuleID: "r-a", Name: "Rule A", Description: "First", Condition: "a", Action: "log", Priority: 100},
	}
	mgr2.CreateBundle(ctx, &PolicyBundle{
		BundleID:     "det-test",
		Name:         "Determinism Test",
		Jurisdiction: "global",
		Category:     "retention",
		Version:      1,
		Rules:        rules2,
	})

	b1, _ := store1.Get(ctx, "det-test")
	b2, _ := store2.Get(ctx, "det-test")

	if b1.ContentHash != b2.ContentHash {
		t.Errorf("content hashes should be deterministic regardless of creation time:\n  h1=%s\n  h2=%s", b1.ContentHash, b2.ContentHash)
	}
}

func TestBundleManager_RulePriorityOrdering(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryBundleStore()
	mgr := NewBundleManager(store)

	// Rules in reverse priority order.
	mgr.CreateBundle(ctx, &PolicyBundle{
		BundleID:     "ordered",
		Name:         "Ordered Bundle",
		Jurisdiction: "global",
		Category:     "approval",
		Version:      1,
		Rules: []PolicyRule{
			{RuleID: "r-high", Name: "High", Condition: "true", Action: "deny", Priority: 300},
			{RuleID: "r-low", Name: "Low", Condition: "true", Action: "log", Priority: 100},
			{RuleID: "r-mid", Name: "Mid", Condition: "true", Action: "encrypt", Priority: 200},
		},
	})

	got, _ := mgr.GetBundle(ctx, "ordered")
	if got.Rules[0].Priority != 100 {
		t.Errorf("first rule priority should be 100 (lowest), got %d", got.Rules[0].Priority)
	}
	if got.Rules[1].Priority != 200 {
		t.Errorf("second rule priority should be 200, got %d", got.Rules[1].Priority)
	}
	if got.Rules[2].Priority != 300 {
		t.Errorf("third rule priority should be 300 (highest), got %d", got.Rules[2].Priority)
	}
}

func TestBundleManager_ActivateAndDeprecate(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryBundleStore()
	mgr := NewBundleManager(store)

	mgr.CreateBundle(ctx, &PolicyBundle{
		BundleID:     "lifecycle",
		Name:         "Lifecycle Bundle",
		Jurisdiction: "UK",
		Category:     "access_control",
		Version:      1,
		Rules:        []PolicyRule{{RuleID: "r-1", Name: "R", Condition: "true", Action: "log", Priority: 1}},
	})

	// Activate.
	if err := mgr.ActivateBundle(ctx, "lifecycle"); err != nil {
		t.Fatalf("ActivateBundle failed: %v", err)
	}
	got, _ := mgr.GetBundle(ctx, "lifecycle")
	if got.Status != BundleStatusActive {
		t.Errorf("expected active, got %s", got.Status)
	}
	if got.ActivatedAt == nil {
		t.Error("ActivatedAt should be set")
	}

	// Cannot activate again.
	if err := mgr.ActivateBundle(ctx, "lifecycle"); err == nil {
		t.Error("activating already-active bundle should fail")
	}

	// Deprecate.
	if err := mgr.DeprecateBundle(ctx, "lifecycle"); err != nil {
		t.Fatalf("DeprecateBundle failed: %v", err)
	}
	got, _ = mgr.GetBundle(ctx, "lifecycle")
	if got.Status != BundleStatusDeprecated {
		t.Errorf("expected deprecated, got %s", got.Status)
	}

	// Cannot deprecate again.
	if err := mgr.DeprecateBundle(ctx, "lifecycle"); err == nil {
		t.Error("deprecating already-deprecated bundle should fail")
	}
}

func TestBuiltinBundles(t *testing.T) {
	retention := RetentionBundle()
	if len(retention.Rules) != 2 {
		t.Errorf("retention bundle should have 2 rules, got %d", len(retention.Rules))
	}
	if retention.Category != "retention" {
		t.Errorf("expected category retention, got %s", retention.Category)
	}

	approval := ApprovalBundle()
	if len(approval.Rules) != 2 {
		t.Errorf("approval bundle should have 2 rules, got %d", len(approval.Rules))
	}

	residency := DataResidencyBundle("EU")
	if residency.Jurisdiction != "EU" {
		t.Errorf("expected jurisdiction EU, got %s", residency.Jurisdiction)
	}
	if len(residency.Rules) != 2 {
		t.Errorf("residency bundle should have 2 rules, got %d", len(residency.Rules))
	}
}

func TestBundleManager_ListByJurisdiction(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryBundleStore()
	mgr := NewBundleManager(store)

	mgr.CreateBundle(ctx, &PolicyBundle{
		BundleID: "b-us", Name: "US Bundle", Jurisdiction: "US", Category: "retention", Version: 1,
		Rules: []PolicyRule{{RuleID: "r", Name: "R", Condition: "true", Action: "log", Priority: 1}},
	})
	mgr.CreateBundle(ctx, &PolicyBundle{
		BundleID: "b-eu", Name: "EU Bundle", Jurisdiction: "EU", Category: "retention", Version: 1,
		Rules: []PolicyRule{{RuleID: "r", Name: "R", Condition: "true", Action: "log", Priority: 1}},
	})

	us, _ := mgr.ListBundles(ctx, "US")
	if len(us) != 1 {
		t.Errorf("expected 1 US bundle, got %d", len(us))
	}

	all, _ := mgr.ListBundles(ctx, "")
	if len(all) != 2 {
		t.Errorf("expected 2 total bundles, got %d", len(all))
	}
}

func TestBundleManager_RemoveAssignment(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryBundleStore()
	mgr := NewBundleManager(store)

	mgr.CreateBundle(ctx, &PolicyBundle{
		BundleID: "b-rm", Name: "Remove Test", Jurisdiction: "global", Category: "approval", Version: 1,
		Rules: []PolicyRule{{RuleID: "r", Name: "R", Condition: "true", Action: "log", Priority: 1}},
	})

	mgr.AssignBundle(ctx, &BundleAssignment{
		AssignmentID: "a-rm",
		BundleID:     "b-rm",
		TenantID:     "t-001",
	})

	if err := mgr.RemoveAssignment(ctx, "a-rm"); err != nil {
		t.Fatalf("RemoveAssignment failed: %v", err)
	}

	assignments, _ := mgr.ListAssignments(ctx, "t-001")
	if len(assignments) != 0 {
		t.Errorf("expected 0 assignments after removal, got %d", len(assignments))
	}

	// Remove nonexistent.
	if err := mgr.RemoveAssignment(ctx, "nonexistent"); err == nil {
		t.Error("removing nonexistent assignment should fail")
	}
}
