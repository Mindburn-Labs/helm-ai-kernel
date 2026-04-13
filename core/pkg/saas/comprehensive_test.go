package saas

import (
	"strings"
	"testing"
	"time"
)

var compFixedTime = time.Date(2026, 4, 12, 0, 0, 0, 0, time.UTC)

func compClock() time.Time { return compFixedTime }

func TestCreateTenantSuccess(t *testing.T) {
	svc := newOnboardingServiceWithClock(compClock)
	rec, err := svc.CreateTenant("t1", "Acme", "starter")
	if err != nil || rec.Status != TenantActive || rec.Plan != "starter" {
		t.Fatalf("create failed: err=%v status=%s", err, rec.Status)
	}
}

func TestCreateTenantDuplicate(t *testing.T) {
	svc := newOnboardingServiceWithClock(compClock)
	svc.CreateTenant("t1", "Acme", "starter")
	_, err := svc.CreateTenant("t1", "Acme2", "enterprise")
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("expected duplicate error, got %v", err)
	}
}

func TestCreateTenantEmptyID(t *testing.T) {
	svc := newOnboardingServiceWithClock(compClock)
	_, err := svc.CreateTenant("", "Acme", "starter")
	if err == nil {
		t.Fatal("expected error for empty tenant_id")
	}
}

func TestSuspendAndActivate(t *testing.T) {
	svc := newOnboardingServiceWithClock(compClock)
	svc.CreateTenant("t1", "Acme", "starter")
	if err := svc.SuspendTenant("t1", "billing"); err != nil {
		t.Fatalf("suspend: %v", err)
	}
	rec, _ := svc.GetTenant("t1")
	if rec.Status != TenantSuspended {
		t.Fatalf("expected SUSPENDED, got %s", rec.Status)
	}
	if err := svc.ActivateTenant("t1"); err != nil {
		t.Fatalf("activate: %v", err)
	}
	rec, _ = svc.GetTenant("t1")
	if rec.Status != TenantActive {
		t.Fatalf("expected ACTIVE, got %s", rec.Status)
	}
}

func TestSuspendNonActiveFails(t *testing.T) {
	svc := newOnboardingServiceWithClock(compClock)
	svc.CreateTenant("t1", "Acme", "starter")
	svc.SuspendTenant("t1", "r")
	err := svc.SuspendTenant("t1", "again")
	if err == nil || !strings.Contains(err.Error(), "SUSPENDED") {
		t.Fatalf("expected state error, got %v", err)
	}
}

func TestDeactivateTenant(t *testing.T) {
	svc := newOnboardingServiceWithClock(compClock)
	svc.CreateTenant("t1", "Acme", "free")
	svc.DeactivateTenant("t1")
	rec, _ := svc.GetTenant("t1")
	if rec.Status != TenantDeactivated {
		t.Fatalf("expected DEACTIVATED, got %s", rec.Status)
	}
}

func TestDeactivateAlreadyDeactivated(t *testing.T) {
	svc := newOnboardingServiceWithClock(compClock)
	svc.CreateTenant("t1", "Acme", "free")
	svc.DeactivateTenant("t1")
	err := svc.DeactivateTenant("t1")
	if err == nil {
		t.Fatal("expected error for double deactivation")
	}
}

func TestListTenants(t *testing.T) {
	svc := newOnboardingServiceWithClock(compClock)
	svc.CreateTenant("t1", "A", "free")
	svc.CreateTenant("t2", "B", "starter")
	list := svc.ListTenants()
	if len(list) != 2 {
		t.Fatalf("expected 2 tenants, got %d", len(list))
	}
}

func TestTenantContentHashPopulated(t *testing.T) {
	svc := newOnboardingServiceWithClock(compClock)
	rec, _ := svc.CreateTenant("t1", "A", "free")
	if rec.ContentHash == "" {
		t.Fatal("content hash should be populated")
	}
}

func TestMeteringRecordAndGetUsage(t *testing.T) {
	m := newMeteringServiceWithClock(compClock)
	m.RecordEvent(BillingEvent{TenantID: "t1", EventType: "ALLOW", Quantity: 5, Timestamp: compFixedTime})
	m.RecordEvent(BillingEvent{TenantID: "t1", EventType: "DENY", Quantity: 2, Timestamp: compFixedTime})
	usage := m.GetUsage("t1", compFixedTime.Add(-time.Hour), compFixedTime.Add(time.Hour))
	if usage.AllowCount != 5 || usage.DenyCount != 2 || usage.DecisionCount != 7 {
		t.Fatalf("usage counts wrong: allow=%d deny=%d total=%d", usage.AllowCount, usage.DenyCount, usage.DecisionCount)
	}
}

func TestMeteringFiltersByPeriod(t *testing.T) {
	m := newMeteringServiceWithClock(compClock)
	m.RecordEvent(BillingEvent{TenantID: "t1", EventType: "DECISION", Quantity: 1, Timestamp: compFixedTime.Add(-2 * time.Hour)})
	m.RecordEvent(BillingEvent{TenantID: "t1", EventType: "DECISION", Quantity: 1, Timestamp: compFixedTime})
	usage := m.GetUsage("t1", compFixedTime.Add(-time.Hour), compFixedTime.Add(time.Hour))
	if usage.DecisionCount != 1 {
		t.Fatalf("expected 1 (in window), got %d", usage.DecisionCount)
	}
}

func TestMeteringEvidencePackConversion(t *testing.T) {
	m := newMeteringServiceWithClock(compClock)
	m.RecordEvent(BillingEvent{TenantID: "t1", EventType: "EVIDENCE_PACK", Quantity: 1024, Timestamp: compFixedTime})
	usage := m.GetUsage("t1", compFixedTime.Add(-time.Hour), compFixedTime.Add(time.Hour))
	if usage.EvidencePacksGB != 1.0 {
		t.Fatalf("expected 1.0 GB, got %f", usage.EvidencePacksGB)
	}
}

func TestIsolationAuditPasses(t *testing.T) {
	a := newIsolationAuditorWithClock(compClock)
	result := a.Audit("t1", map[string]string{"res-a": "t1", "res-b": "t1"})
	if !result.Passed || result.CrossTenantLeaks != 0 || result.ResourcesAudited != 2 {
		t.Fatalf("audit should pass: passed=%v leaks=%d audited=%d", result.Passed, result.CrossTenantLeaks, result.ResourcesAudited)
	}
}

func TestIsolationAuditDetectsLeaks(t *testing.T) {
	a := newIsolationAuditorWithClock(compClock)
	result := a.Audit("t1", map[string]string{"res-a": "t1", "res-b": "t2"})
	if result.Passed || result.CrossTenantLeaks != 1 {
		t.Fatalf("audit should detect 1 leak: passed=%v leaks=%d", result.Passed, result.CrossTenantLeaks)
	}
}

func TestIsolationAuditContentHash(t *testing.T) {
	a := newIsolationAuditorWithClock(compClock)
	result := a.Audit("t1", map[string]string{"res-a": "t1"})
	if result.ContentHash == "" {
		t.Fatal("audit content hash should be populated")
	}
}
