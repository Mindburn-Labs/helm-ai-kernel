package saas

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

var saasTime = time.Date(2026, 4, 12, 0, 0, 0, 0, time.UTC)

func saasClock() time.Time { return saasTime }

func TestDeep_Onboard100Tenants(t *testing.T) {
	svc := newOnboardingServiceWithClock(saasClock)
	for i := 0; i < 100; i++ {
		_, err := svc.CreateTenant(fmt.Sprintf("t-%d", i), fmt.Sprintf("Org %d", i), "starter")
		if err != nil {
			t.Fatalf("tenant %d: %v", i, err)
		}
	}
	if len(svc.ListTenants()) != 100 {
		t.Fatalf("expected 100 tenants, got %d", len(svc.ListTenants()))
	}
}

func TestDeep_Onboard100TenantsUniqueSigningKeys(t *testing.T) {
	svc := newOnboardingServiceWithClock(saasClock)
	keys := make(map[string]bool, 100)
	for i := 0; i < 100; i++ {
		rec, _ := svc.CreateTenant(fmt.Sprintf("t-%d", i), fmt.Sprintf("Org %d", i), "free")
		if keys[rec.SigningKeyID] {
			t.Fatalf("duplicate signing key: %s", rec.SigningKeyID)
		}
		keys[rec.SigningKeyID] = true
	}
}

func TestDeep_FullLifecycle(t *testing.T) {
	svc := newOnboardingServiceWithClock(saasClock)
	svc.CreateTenant("t1", "Org1", "enterprise")

	// Active -> Suspended
	if err := svc.SuspendTenant("t1", "billing"); err != nil {
		t.Fatalf("suspend: %v", err)
	}
	rec, _ := svc.GetTenant("t1")
	if rec.Status != TenantSuspended {
		t.Fatalf("expected SUSPENDED, got %s", rec.Status)
	}

	// Suspended -> Active
	if err := svc.ActivateTenant("t1"); err != nil {
		t.Fatalf("activate: %v", err)
	}
	rec, _ = svc.GetTenant("t1")
	if rec.Status != TenantActive {
		t.Fatalf("expected ACTIVE, got %s", rec.Status)
	}

	// Active -> Deactivated (terminal)
	if err := svc.DeactivateTenant("t1"); err != nil {
		t.Fatalf("deactivate: %v", err)
	}
	rec, _ = svc.GetTenant("t1")
	if rec.Status != TenantDeactivated {
		t.Fatalf("expected DEACTIVATED, got %s", rec.Status)
	}
}

func TestDeep_SuspendNonActiveRejects(t *testing.T) {
	svc := newOnboardingServiceWithClock(saasClock)
	svc.CreateTenant("t1", "O", "free")
	svc.SuspendTenant("t1", "x")
	err := svc.SuspendTenant("t1", "again")
	if err == nil {
		t.Fatal("should not suspend already-suspended tenant")
	}
}

func TestDeep_ActivateNonSuspendedRejects(t *testing.T) {
	svc := newOnboardingServiceWithClock(saasClock)
	svc.CreateTenant("t1", "O", "free")
	err := svc.ActivateTenant("t1")
	if err == nil {
		t.Fatal("should not activate already-active tenant")
	}
}

func TestDeep_DeactivateAlreadyDeactivatedRejects(t *testing.T) {
	svc := newOnboardingServiceWithClock(saasClock)
	svc.CreateTenant("t1", "O", "free")
	svc.DeactivateTenant("t1")
	err := svc.DeactivateTenant("t1")
	if err == nil {
		t.Fatal("should not deactivate already-deactivated tenant")
	}
}

func TestDeep_CreateDuplicateTenantRejects(t *testing.T) {
	svc := newOnboardingServiceWithClock(saasClock)
	svc.CreateTenant("t1", "O", "free")
	_, err := svc.CreateTenant("t1", "O2", "free")
	if err == nil {
		t.Fatal("should reject duplicate tenant")
	}
}

func TestDeep_CreateTenantEmptyFields(t *testing.T) {
	svc := newOnboardingServiceWithClock(saasClock)
	cases := []struct{ id, org, plan string }{
		{"", "O", "free"},
		{"t1", "", "free"},
		{"t1", "O", ""},
	}
	for i, c := range cases {
		_, err := svc.CreateTenant(c.id, c.org, c.plan)
		if err == nil {
			t.Fatalf("case %d: should reject empty field", i)
		}
	}
}

func TestDeep_TenantContentHashChangesOnStateTransition(t *testing.T) {
	svc := newOnboardingServiceWithClock(saasClock)
	rec, _ := svc.CreateTenant("t1", "O", "free")
	hash1 := rec.ContentHash
	svc.SuspendTenant("t1", "x")
	rec, _ = svc.GetTenant("t1")
	if rec.ContentHash == hash1 {
		t.Fatal("content hash should change after state transition")
	}
}

func TestDeep_Metering10000Events(t *testing.T) {
	m := newMeteringServiceWithClock(saasClock)
	base := saasTime
	for i := 0; i < 10000; i++ {
		m.RecordEvent(BillingEvent{
			EventID:   fmt.Sprintf("e-%d", i),
			TenantID:  "t1",
			EventType: "DECISION",
			Quantity:  1,
			Timestamp: base.Add(time.Duration(i) * time.Second),
		})
	}
	usage := m.GetUsage("t1", base, base.Add(10001*time.Second))
	if usage.DecisionCount != 10000 {
		t.Fatalf("expected 10000 decisions, got %d", usage.DecisionCount)
	}
}

func TestDeep_MeteringEventTypes(t *testing.T) {
	m := newMeteringServiceWithClock(saasClock)
	ts := saasTime
	events := []BillingEvent{
		{EventID: "1", TenantID: "t1", EventType: "ALLOW", Quantity: 5, Timestamp: ts},
		{EventID: "2", TenantID: "t1", EventType: "DENY", Quantity: 3, Timestamp: ts},
		{EventID: "3", TenantID: "t1", EventType: "RECEIPT", Quantity: 2, Timestamp: ts},
		{EventID: "4", TenantID: "t1", EventType: "EVIDENCE_PACK", Quantity: 1024, Timestamp: ts},
		{EventID: "5", TenantID: "t1", EventType: "ZK_PROOF", Quantity: 100, Timestamp: ts},
	}
	for _, e := range events {
		m.RecordEvent(e)
	}
	usage := m.GetUsage("t1", ts.Add(-time.Second), ts.Add(time.Second))
	if usage.AllowCount != 5 || usage.DenyCount != 3 || usage.ReceiptCount != 2 {
		t.Fatalf("usage counts wrong: allow=%d deny=%d receipt=%d", usage.AllowCount, usage.DenyCount, usage.ReceiptCount)
	}
	if usage.EvidencePacksGB != 1.0 {
		t.Fatalf("evidence packs GB: got %f, want 1.0", usage.EvidencePacksGB)
	}
	if usage.ComputeMillis != 100 {
		t.Fatalf("compute millis: got %d, want 100", usage.ComputeMillis)
	}
}

func TestDeep_MeteringOutOfRangeExcluded(t *testing.T) {
	m := newMeteringServiceWithClock(saasClock)
	m.RecordEvent(BillingEvent{TenantID: "t1", EventType: "DECISION", Quantity: 1, Timestamp: saasTime.Add(-time.Hour)})
	usage := m.GetUsage("t1", saasTime, saasTime.Add(time.Hour))
	if usage.DecisionCount != 0 {
		t.Fatal("out-of-range event should not be counted")
	}
}

func TestDeep_IsolationAuditPasses(t *testing.T) {
	auditor := newIsolationAuditorWithClock(saasClock)
	resources := map[string]string{
		"res-1": "t1", "res-2": "t1", "res-3": "t1",
	}
	result := auditor.Audit("t1", resources)
	if !result.Passed || result.CrossTenantLeaks != 0 {
		t.Fatal("all resources owned by t1 — should pass")
	}
	if result.ResourcesAudited != 3 {
		t.Fatal("should audit 3 resources")
	}
}

func TestDeep_IsolationAuditDetectsLeaks(t *testing.T) {
	auditor := newIsolationAuditorWithClock(saasClock)
	resources := map[string]string{
		"res-1": "t1", "res-2": "t2", "res-3": "t3",
	}
	result := auditor.Audit("t1", resources)
	if result.Passed {
		t.Fatal("should detect cross-tenant leaks")
	}
	if result.CrossTenantLeaks != 2 {
		t.Fatalf("expected 2 leaks, got %d", result.CrossTenantLeaks)
	}
}

func TestDeep_IsolationAuditContentHash(t *testing.T) {
	auditor := newIsolationAuditorWithClock(saasClock)
	result := auditor.Audit("t1", map[string]string{"r": "t1"})
	if result.ContentHash == "" {
		t.Fatal("content hash should be set")
	}
}

func TestDeep_ConcurrentTenantOperations50Goroutines(t *testing.T) {
	svc := newOnboardingServiceWithClock(saasClock)
	var wg sync.WaitGroup

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			id := fmt.Sprintf("t-%d", idx)
			_, err := svc.CreateTenant(id, fmt.Sprintf("Org %d", idx), "starter")
			if err != nil {
				t.Errorf("create %d: %v", idx, err)
				return
			}
			if err := svc.SuspendTenant(id, "test"); err != nil {
				t.Errorf("suspend %d: %v", idx, err)
				return
			}
			if err := svc.ActivateTenant(id); err != nil {
				t.Errorf("activate %d: %v", idx, err)
			}
		}(i)
	}
	wg.Wait()

	if len(svc.ListTenants()) != 50 {
		t.Fatalf("expected 50 tenants, got %d", len(svc.ListTenants()))
	}
}

func TestDeep_ConcurrentMetering(t *testing.T) {
	m := newMeteringServiceWithClock(saasClock)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				m.RecordEvent(BillingEvent{
					TenantID:  fmt.Sprintf("t-%d", idx),
					EventType: "DECISION",
					Quantity:  1,
					Timestamp: saasTime,
				})
			}
		}(i)
	}
	wg.Wait()

	allUsage := m.GetAllUsage(saasTime.Add(-time.Second), saasTime.Add(time.Second))
	total := int64(0)
	for _, u := range allUsage {
		total += u.DecisionCount
	}
	if total != 5000 {
		t.Fatalf("expected 5000 total decisions, got %d", total)
	}
}

func TestDeep_GetTenantNotFound(t *testing.T) {
	svc := newOnboardingServiceWithClock(saasClock)
	_, found := svc.GetTenant("ghost")
	if found {
		t.Fatal("should not find non-existent tenant")
	}
}

func TestDeep_SuspendNotFoundTenant(t *testing.T) {
	svc := newOnboardingServiceWithClock(saasClock)
	if err := svc.SuspendTenant("ghost", "x"); err == nil {
		t.Fatal("should fail on non-existent tenant")
	}
}

func TestDeep_ActivateNotFoundTenant(t *testing.T) {
	svc := newOnboardingServiceWithClock(saasClock)
	if err := svc.ActivateTenant("ghost"); err == nil {
		t.Fatal("should fail on non-existent tenant")
	}
}

func TestDeep_DeactivateNotFoundTenant(t *testing.T) {
	svc := newOnboardingServiceWithClock(saasClock)
	if err := svc.DeactivateTenant("ghost"); err == nil {
		t.Fatal("should fail on non-existent tenant")
	}
}

func TestDeep_MeteringGetUsageNoTenant(t *testing.T) {
	m := newMeteringServiceWithClock(saasClock)
	usage := m.GetUsage("nonexistent", saasTime, saasTime.Add(time.Hour))
	if usage.DecisionCount != 0 {
		t.Fatal("no events for unknown tenant should be zero")
	}
}

func TestDeep_GetAllUsageFiltersInactive(t *testing.T) {
	m := newMeteringServiceWithClock(saasClock)
	m.RecordEvent(BillingEvent{TenantID: "active", EventType: "DECISION", Quantity: 1, Timestamp: saasTime})
	all := m.GetAllUsage(saasTime.Add(-time.Second), saasTime.Add(time.Second))
	if _, ok := all["inactive"]; ok {
		t.Fatal("inactive tenants should not appear in GetAllUsage")
	}
	if _, ok := all["active"]; !ok {
		t.Fatal("active tenant should appear in GetAllUsage")
	}
}

func TestDeep_IsolationAuditEmptyResources(t *testing.T) {
	auditor := newIsolationAuditorWithClock(saasClock)
	result := auditor.Audit("t1", map[string]string{})
	if !result.Passed {
		t.Fatal("empty resources should pass isolation audit")
	}
	if result.ResourcesAudited != 0 {
		t.Fatal("should audit 0 resources")
	}
}

func TestDeep_SigningKeyDeterministic(t *testing.T) {
	a := generateSigningKeyID("t1")
	b := generateSigningKeyID("t1")
	if a != b {
		t.Fatal("same tenant ID should produce same signing key")
	}
	c := generateSigningKeyID("t2")
	if a == c {
		t.Fatal("different tenant IDs should produce different signing keys")
	}
}
