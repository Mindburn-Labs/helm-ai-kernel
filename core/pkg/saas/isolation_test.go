package saas

import (
	"testing"
	"time"
)

func TestIsolationAuditor_Clean(t *testing.T) {
	now := time.Date(2026, 4, 12, 10, 0, 0, 0, time.UTC)
	auditor := newIsolationAuditorWithClock(fixedClock(now))

	// All resources belong to the tenant.
	resources := map[string]string{
		"workspace-1":  "t-001",
		"workspace-2":  "t-001",
		"evidence-001": "t-001",
		"policy-001":   "t-001",
	}

	result := auditor.Audit("t-001", resources)

	if !result.Passed {
		t.Error("audit should pass when all resources belong to tenant")
	}
	if result.CrossTenantLeaks != 0 {
		t.Errorf("CrossTenantLeaks = %d, want 0", result.CrossTenantLeaks)
	}
	if result.ResourcesAudited != 4 {
		t.Errorf("ResourcesAudited = %d, want 4", result.ResourcesAudited)
	}
	if result.TenantID != "t-001" {
		t.Errorf("TenantID = %s, want t-001", result.TenantID)
	}
	if result.AuditID == "" {
		t.Error("AuditID should be generated")
	}
	if !result.AuditedAt.Equal(now) {
		t.Errorf("AuditedAt = %v, want %v", result.AuditedAt, now)
	}
}

func TestIsolationAuditor_Leak(t *testing.T) {
	now := time.Date(2026, 4, 12, 10, 0, 0, 0, time.UTC)
	auditor := newIsolationAuditorWithClock(fixedClock(now))

	// One resource belongs to a different tenant (cross-tenant leak).
	resources := map[string]string{
		"workspace-1":  "t-001",
		"workspace-2":  "t-001",
		"evidence-001": "t-002", // LEAK: belongs to t-002
		"policy-001":   "t-001",
	}

	result := auditor.Audit("t-001", resources)

	if result.Passed {
		t.Error("audit should fail when cross-tenant leak detected")
	}
	if result.CrossTenantLeaks != 1 {
		t.Errorf("CrossTenantLeaks = %d, want 1", result.CrossTenantLeaks)
	}
	if result.ResourcesAudited != 4 {
		t.Errorf("ResourcesAudited = %d, want 4", result.ResourcesAudited)
	}
}

func TestIsolationAuditor_MultipleLeaks(t *testing.T) {
	auditor := NewIsolationAuditor()

	resources := map[string]string{
		"workspace-1": "t-002", // LEAK
		"workspace-2": "t-003", // LEAK
		"policy-001":  "t-001",
	}

	result := auditor.Audit("t-001", resources)

	if result.Passed {
		t.Error("audit should fail with multiple leaks")
	}
	if result.CrossTenantLeaks != 2 {
		t.Errorf("CrossTenantLeaks = %d, want 2", result.CrossTenantLeaks)
	}
}

func TestIsolationAuditor_EmptyResources(t *testing.T) {
	auditor := NewIsolationAuditor()

	result := auditor.Audit("t-001", map[string]string{})

	if !result.Passed {
		t.Error("audit with no resources should pass (no leaks possible)")
	}
	if result.CrossTenantLeaks != 0 {
		t.Errorf("CrossTenantLeaks = %d, want 0", result.CrossTenantLeaks)
	}
	if result.ResourcesAudited != 0 {
		t.Errorf("ResourcesAudited = %d, want 0", result.ResourcesAudited)
	}
}

func TestIsolationAuditor_ContentHash(t *testing.T) {
	now := time.Date(2026, 4, 12, 10, 0, 0, 0, time.UTC)
	auditor := newIsolationAuditorWithClock(fixedClock(now))

	resources := map[string]string{
		"workspace-1": "t-001",
		"workspace-2": "t-001",
	}

	result := auditor.Audit("t-001", resources)

	if result.ContentHash == "" {
		t.Error("ContentHash should be computed")
	}
	if result.ContentHash == "hash-error" {
		t.Error("ContentHash should not be error marker")
	}

	// Verify determinism: same inputs produce same hash.
	result2 := auditor.Audit("t-001", resources)
	if result.ContentHash != result2.ContentHash {
		t.Errorf("ContentHash should be deterministic: %s != %s", result.ContentHash, result2.ContentHash)
	}

	// Different inputs produce different hash.
	resources["workspace-3"] = "t-002" // add a leak
	result3 := auditor.Audit("t-001", resources)
	if result.ContentHash == result3.ContentHash {
		t.Error("ContentHash should differ for different audit results")
	}
}
