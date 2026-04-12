package saas

import (
	"testing"
	"time"
)

func TestMeteringService_RecordEvent(t *testing.T) {
	now := time.Date(2026, 4, 12, 10, 0, 0, 0, time.UTC)
	svc := newMeteringServiceWithClock(fixedClock(now))

	svc.RecordEvent(BillingEvent{
		EventID:   "e-001",
		TenantID:  "t-001",
		EventType: "DECISION",
		Quantity:  5,
		Timestamp: now,
	})
	svc.RecordEvent(BillingEvent{
		EventID:   "e-002",
		TenantID:  "t-001",
		EventType: "RECEIPT",
		Quantity:  3,
		Timestamp: now,
	})

	usage := svc.GetUsage("t-001", now.Add(-time.Hour), now.Add(time.Hour))
	if usage.TenantID != "t-001" {
		t.Errorf("TenantID = %s, want t-001", usage.TenantID)
	}
	if usage.DecisionCount != 5 {
		t.Errorf("DecisionCount = %d, want 5", usage.DecisionCount)
	}
	if usage.ReceiptCount != 3 {
		t.Errorf("ReceiptCount = %d, want 3", usage.ReceiptCount)
	}
}

func TestMeteringService_UsageAggregation(t *testing.T) {
	baseTime := time.Date(2026, 4, 12, 0, 0, 0, 0, time.UTC)
	svc := newMeteringServiceWithClock(fixedClock(baseTime))

	// Events at different times.
	svc.RecordEvent(BillingEvent{
		EventID:   "e-001",
		TenantID:  "t-001",
		EventType: "ALLOW",
		Quantity:  10,
		Timestamp: baseTime.Add(1 * time.Hour),
	})
	svc.RecordEvent(BillingEvent{
		EventID:   "e-002",
		TenantID:  "t-001",
		EventType: "DENY",
		Quantity:  3,
		Timestamp: baseTime.Add(2 * time.Hour),
	})
	svc.RecordEvent(BillingEvent{
		EventID:   "e-003",
		TenantID:  "t-001",
		EventType: "EVIDENCE_PACK",
		Quantity:  2048, // 2048 MB = 2 GB
		Timestamp: baseTime.Add(3 * time.Hour),
	})
	svc.RecordEvent(BillingEvent{
		EventID:   "e-004",
		TenantID:  "t-001",
		EventType: "ZK_PROOF",
		Quantity:  500,
		Timestamp: baseTime.Add(4 * time.Hour),
	})
	// Event outside the window (before).
	svc.RecordEvent(BillingEvent{
		EventID:   "e-005",
		TenantID:  "t-001",
		EventType: "DECISION",
		Quantity:  100,
		Timestamp: baseTime.Add(-1 * time.Hour),
	})
	// Event at exact boundary (should be excluded: [from, to) is half-open).
	svc.RecordEvent(BillingEvent{
		EventID:   "e-006",
		TenantID:  "t-001",
		EventType: "DECISION",
		Quantity:  200,
		Timestamp: baseTime.Add(5 * time.Hour),
	})

	from := baseTime
	to := baseTime.Add(5 * time.Hour)
	usage := svc.GetUsage("t-001", from, to)

	if usage.AllowCount != 10 {
		t.Errorf("AllowCount = %d, want 10", usage.AllowCount)
	}
	if usage.DenyCount != 3 {
		t.Errorf("DenyCount = %d, want 3", usage.DenyCount)
	}
	// ALLOW and DENY both increment DecisionCount.
	if usage.DecisionCount != 13 {
		t.Errorf("DecisionCount = %d, want 13", usage.DecisionCount)
	}
	if usage.EvidencePacksGB != 2.0 {
		t.Errorf("EvidencePacksGB = %f, want 2.0", usage.EvidencePacksGB)
	}
	if usage.ComputeMillis != 500 {
		t.Errorf("ComputeMillis = %d, want 500", usage.ComputeMillis)
	}
}

func TestMeteringService_EmptyUsage(t *testing.T) {
	svc := NewMeteringService()

	now := time.Now().UTC()
	usage := svc.GetUsage("nonexistent", now.Add(-time.Hour), now.Add(time.Hour))

	if usage.TenantID != "nonexistent" {
		t.Errorf("TenantID = %s, want nonexistent", usage.TenantID)
	}
	if usage.DecisionCount != 0 {
		t.Errorf("DecisionCount = %d, want 0", usage.DecisionCount)
	}
}

func TestMeteringService_MultiTenant(t *testing.T) {
	baseTime := time.Date(2026, 4, 12, 0, 0, 0, 0, time.UTC)
	svc := newMeteringServiceWithClock(fixedClock(baseTime))

	// Tenant A events.
	svc.RecordEvent(BillingEvent{
		EventID:   "e-001",
		TenantID:  "t-001",
		EventType: "DECISION",
		Quantity:  10,
		Timestamp: baseTime.Add(1 * time.Hour),
	})

	// Tenant B events.
	svc.RecordEvent(BillingEvent{
		EventID:   "e-002",
		TenantID:  "t-002",
		EventType: "DECISION",
		Quantity:  20,
		Timestamp: baseTime.Add(1 * time.Hour),
	})
	svc.RecordEvent(BillingEvent{
		EventID:   "e-003",
		TenantID:  "t-002",
		EventType: "RECEIPT",
		Quantity:  5,
		Timestamp: baseTime.Add(2 * time.Hour),
	})

	from := baseTime
	to := baseTime.Add(24 * time.Hour)

	// Per-tenant usage should be independent.
	usageA := svc.GetUsage("t-001", from, to)
	if usageA.DecisionCount != 10 {
		t.Errorf("Tenant A DecisionCount = %d, want 10", usageA.DecisionCount)
	}
	if usageA.ReceiptCount != 0 {
		t.Errorf("Tenant A ReceiptCount = %d, want 0", usageA.ReceiptCount)
	}

	usageB := svc.GetUsage("t-002", from, to)
	if usageB.DecisionCount != 20 {
		t.Errorf("Tenant B DecisionCount = %d, want 20", usageB.DecisionCount)
	}
	if usageB.ReceiptCount != 5 {
		t.Errorf("Tenant B ReceiptCount = %d, want 5", usageB.ReceiptCount)
	}

	// GetAllUsage should return both tenants.
	all := svc.GetAllUsage(from, to)
	if len(all) != 2 {
		t.Errorf("GetAllUsage returned %d tenants, want 2", len(all))
	}
	if all["t-001"].DecisionCount != 10 {
		t.Errorf("All[t-001] DecisionCount = %d, want 10", all["t-001"].DecisionCount)
	}
	if all["t-002"].DecisionCount != 20 {
		t.Errorf("All[t-002] DecisionCount = %d, want 20", all["t-002"].DecisionCount)
	}
}

func TestMeteringService_GetAllUsage_ExcludesInactive(t *testing.T) {
	baseTime := time.Date(2026, 4, 12, 0, 0, 0, 0, time.UTC)
	svc := newMeteringServiceWithClock(fixedClock(baseTime))

	// Tenant with events outside the query window.
	svc.RecordEvent(BillingEvent{
		EventID:   "e-001",
		TenantID:  "t-001",
		EventType: "DECISION",
		Quantity:  10,
		Timestamp: baseTime.Add(-24 * time.Hour),
	})

	// Tenant with events inside the window.
	svc.RecordEvent(BillingEvent{
		EventID:   "e-002",
		TenantID:  "t-002",
		EventType: "DECISION",
		Quantity:  5,
		Timestamp: baseTime.Add(1 * time.Hour),
	})

	from := baseTime
	to := baseTime.Add(24 * time.Hour)

	all := svc.GetAllUsage(from, to)
	if len(all) != 1 {
		t.Errorf("GetAllUsage returned %d tenants, want 1 (inactive excluded)", len(all))
	}
	if _, exists := all["t-001"]; exists {
		t.Error("t-001 should be excluded (no activity in window)")
	}
	if _, exists := all["t-002"]; !exists {
		t.Error("t-002 should be included")
	}
}
