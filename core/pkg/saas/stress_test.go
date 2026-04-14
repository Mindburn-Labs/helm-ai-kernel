package saas

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

var stressSaasClock = func() time.Time { return time.Date(2026, 4, 12, 0, 0, 0, 0, time.UTC) }

// --- 200 Tenants ---

func TestStress_Onboarding_200Tenants(t *testing.T) {
	svc := newOnboardingServiceWithClock(stressSaasClock)
	for i := 0; i < 200; i++ {
		_, err := svc.CreateTenant(fmt.Sprintf("t-%d", i), fmt.Sprintf("Org %d", i), "starter")
		if err != nil {
			t.Fatalf("tenant %d: %v", i, err)
		}
	}
	if len(svc.ListTenants()) != 200 {
		t.Fatalf("expected 200 tenants, got %d", len(svc.ListTenants()))
	}
}

func TestStress_Onboarding_DuplicateTenantRejected(t *testing.T) {
	svc := newOnboardingServiceWithClock(stressSaasClock)
	svc.CreateTenant("dup", "Org", "free")
	_, err := svc.CreateTenant("dup", "Org", "free")
	if err == nil {
		t.Fatal("expected error for duplicate tenant")
	}
}

func TestStress_Onboarding_EmptyFieldsRejected(t *testing.T) {
	svc := newOnboardingServiceWithClock(stressSaasClock)
	if _, err := svc.CreateTenant("", "Org", "free"); err == nil {
		t.Fatal("expected error for empty tenant_id")
	}
	if _, err := svc.CreateTenant("t1", "", "free"); err == nil {
		t.Fatal("expected error for empty org_name")
	}
	if _, err := svc.CreateTenant("t2", "Org", ""); err == nil {
		t.Fatal("expected error for empty plan")
	}
}

// --- Full Lifecycle for 50 ---

func TestStress_Lifecycle_50Tenants(t *testing.T) {
	svc := newOnboardingServiceWithClock(stressSaasClock)
	for i := 0; i < 50; i++ {
		tid := fmt.Sprintf("lc-%d", i)
		svc.CreateTenant(tid, fmt.Sprintf("Org %d", i), "enterprise")
		if err := svc.SuspendTenant(tid, "test"); err != nil {
			t.Fatalf("suspend %d: %v", i, err)
		}
		if err := svc.ActivateTenant(tid); err != nil {
			t.Fatalf("activate %d: %v", i, err)
		}
		if err := svc.DeactivateTenant(tid); err != nil {
			t.Fatalf("deactivate %d: %v", i, err)
		}
	}
}

func TestStress_Lifecycle_SuspendNonActive(t *testing.T) {
	svc := newOnboardingServiceWithClock(stressSaasClock)
	svc.CreateTenant("t1", "Org", "free")
	svc.SuspendTenant("t1", "test")
	if err := svc.SuspendTenant("t1", "again"); err == nil {
		t.Fatal("expected error suspending already-suspended tenant")
	}
}

func TestStress_Lifecycle_ActivateNonSuspended(t *testing.T) {
	svc := newOnboardingServiceWithClock(stressSaasClock)
	svc.CreateTenant("t1", "Org", "free")
	if err := svc.ActivateTenant("t1"); err == nil {
		t.Fatal("expected error activating already-active tenant")
	}
}

func TestStress_Lifecycle_DeactivateAlreadyDeactivated(t *testing.T) {
	svc := newOnboardingServiceWithClock(stressSaasClock)
	svc.CreateTenant("t1", "Org", "free")
	svc.DeactivateTenant("t1")
	if err := svc.DeactivateTenant("t1"); err == nil {
		t.Fatal("expected error deactivating already-deactivated tenant")
	}
}

func TestStress_Lifecycle_SuspendNotFound(t *testing.T) {
	svc := newOnboardingServiceWithClock(stressSaasClock)
	if err := svc.SuspendTenant("ghost", "test"); err == nil {
		t.Fatal("expected error for nonexistent tenant")
	}
}

func TestStress_Lifecycle_GetTenant(t *testing.T) {
	svc := newOnboardingServiceWithClock(stressSaasClock)
	svc.CreateTenant("t1", "Org", "free")
	rec, ok := svc.GetTenant("t1")
	if !ok || rec.TenantID != "t1" {
		t.Fatal("expected to find tenant")
	}
}

func TestStress_Lifecycle_GetNotFound(t *testing.T) {
	svc := newOnboardingServiceWithClock(stressSaasClock)
	_, ok := svc.GetTenant("ghost")
	if ok {
		t.Fatal("expected not found")
	}
}

func TestStress_Lifecycle_ContentHashChanges(t *testing.T) {
	svc := newOnboardingServiceWithClock(stressSaasClock)
	rec, _ := svc.CreateTenant("h1", "Org", "free")
	hash1 := rec.ContentHash
	svc.SuspendTenant("h1", "test")
	rec2, _ := svc.GetTenant("h1")
	if rec2.ContentHash == hash1 {
		t.Fatal("content hash should change on status change")
	}
}

func TestStress_Lifecycle_SigningKeyDeterministic(t *testing.T) {
	k1 := generateSigningKeyID("tenant-abc")
	k2 := generateSigningKeyID("tenant-abc")
	if k1 != k2 {
		t.Fatal("signing key should be deterministic")
	}
}

// --- Metering 10000 Events ---

func TestStress_Metering_10000Events(t *testing.T) {
	ms := newMeteringServiceWithClock(stressSaasClock)
	base := stressSaasClock()
	for i := 0; i < 10000; i++ {
		ms.RecordEvent(BillingEvent{
			EventID:   fmt.Sprintf("ev-%d", i),
			TenantID:  "t1",
			EventType: "DECISION",
			Quantity:  1,
			Timestamp: base.Add(time.Duration(i) * time.Second),
		})
	}
	usage := ms.GetUsage("t1", base, base.Add(20000*time.Second))
	if usage.DecisionCount != 10000 {
		t.Fatalf("expected 10000 decisions, got %d", usage.DecisionCount)
	}
}

func TestStress_Metering_AllEventTypes(t *testing.T) {
	ms := newMeteringServiceWithClock(stressSaasClock)
	base := stressSaasClock()
	types := []string{"ALLOW", "DENY", "RECEIPT", "EVIDENCE_PACK", "ZK_PROOF"}
	for i, et := range types {
		ms.RecordEvent(BillingEvent{
			EventID: fmt.Sprintf("ev-%d", i), TenantID: "t1",
			EventType: et, Quantity: 10, Timestamp: base,
		})
	}
	usage := ms.GetUsage("t1", base.Add(-time.Hour), base.Add(time.Hour))
	if usage.AllowCount != 10 {
		t.Fatalf("expected 10 allows, got %d", usage.AllowCount)
	}
	if usage.DenyCount != 10 {
		t.Fatalf("expected 10 denies, got %d", usage.DenyCount)
	}
}

func TestStress_Metering_MultipleTenants(t *testing.T) {
	ms := newMeteringServiceWithClock(stressSaasClock)
	base := stressSaasClock()
	for i := 0; i < 50; i++ {
		ms.RecordEvent(BillingEvent{
			EventID: fmt.Sprintf("ev-%d", i), TenantID: fmt.Sprintf("t-%d", i%5),
			EventType: "DECISION", Quantity: 1, Timestamp: base,
		})
	}
	all := ms.GetAllUsage(base.Add(-time.Hour), base.Add(time.Hour))
	if len(all) != 5 {
		t.Fatalf("expected 5 tenants, got %d", len(all))
	}
}

func TestStress_Metering_EmptyUsage(t *testing.T) {
	ms := newMeteringServiceWithClock(stressSaasClock)
	base := stressSaasClock()
	usage := ms.GetUsage("ghost", base, base.Add(time.Hour))
	if usage.DecisionCount != 0 {
		t.Fatal("expected zero decisions for unknown tenant")
	}
}

func TestStress_Metering_TimeWindowFilter(t *testing.T) {
	ms := newMeteringServiceWithClock(stressSaasClock)
	base := stressSaasClock()
	ms.RecordEvent(BillingEvent{EventID: "before", TenantID: "t1", EventType: "DECISION", Quantity: 1, Timestamp: base.Add(-2 * time.Hour)})
	ms.RecordEvent(BillingEvent{EventID: "in", TenantID: "t1", EventType: "DECISION", Quantity: 1, Timestamp: base})
	ms.RecordEvent(BillingEvent{EventID: "after", TenantID: "t1", EventType: "DECISION", Quantity: 1, Timestamp: base.Add(2 * time.Hour)})
	usage := ms.GetUsage("t1", base.Add(-time.Hour), base.Add(time.Hour))
	if usage.DecisionCount != 1 {
		t.Fatalf("expected 1 in-window event, got %d", usage.DecisionCount)
	}
}

// --- Isolation Audit 500 Resources ---

func TestStress_Isolation_500Resources_AllOwned(t *testing.T) {
	auditor := newIsolationAuditorWithClock(stressSaasClock)
	resources := make(map[string]string, 500)
	for i := 0; i < 500; i++ {
		resources[fmt.Sprintf("res-%d", i)] = "tenant-a"
	}
	result := auditor.Audit("tenant-a", resources)
	if !result.Passed {
		t.Fatal("expected audit to pass when all resources owned")
	}
	if result.ResourcesAudited != 500 {
		t.Fatalf("expected 500 resources audited, got %d", result.ResourcesAudited)
	}
}

func TestStress_Isolation_500Resources_SomeLeaks(t *testing.T) {
	auditor := newIsolationAuditorWithClock(stressSaasClock)
	resources := make(map[string]string, 500)
	for i := 0; i < 500; i++ {
		owner := "tenant-a"
		if i%100 == 0 {
			owner = "tenant-b"
		}
		resources[fmt.Sprintf("res-%d", i)] = owner
	}
	result := auditor.Audit("tenant-a", resources)
	if result.Passed {
		t.Fatal("expected audit to fail with cross-tenant leaks")
	}
	if result.CrossTenantLeaks != 5 {
		t.Fatalf("expected 5 leaks, got %d", result.CrossTenantLeaks)
	}
}

func TestStress_Isolation_EmptyResources(t *testing.T) {
	auditor := newIsolationAuditorWithClock(stressSaasClock)
	result := auditor.Audit("tenant-a", map[string]string{})
	if !result.Passed {
		t.Fatal("empty resources should pass")
	}
}

func TestStress_Isolation_ContentHashSet(t *testing.T) {
	auditor := newIsolationAuditorWithClock(stressSaasClock)
	result := auditor.Audit("t1", map[string]string{"r1": "t1"})
	if result.ContentHash == "" {
		t.Fatal("content hash should be set")
	}
}

func TestStress_Isolation_AuditIDDeterministic(t *testing.T) {
	ts := stressSaasClock()
	id1 := generateAuditID("t1", ts)
	id2 := generateAuditID("t1", ts)
	if id1 != id2 {
		t.Fatal("audit ID should be deterministic for same input")
	}
}

// --- Concurrent Operations 100 Goroutines ---

func TestStress_Concurrent_Onboarding_100Goroutines(t *testing.T) {
	svc := newOnboardingServiceWithClock(stressSaasClock)
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			svc.CreateTenant(fmt.Sprintf("ct-%d", id), fmt.Sprintf("Org-%d", id), "free")
		}(i)
	}
	wg.Wait()
	if len(svc.ListTenants()) != 100 {
		t.Fatalf("expected 100 tenants, got %d", len(svc.ListTenants()))
	}
}

func TestStress_Concurrent_Metering_100Goroutines(t *testing.T) {
	ms := newMeteringServiceWithClock(stressSaasClock)
	base := stressSaasClock()
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				ms.RecordEvent(BillingEvent{
					EventID: fmt.Sprintf("ev-%d-%d", id, j), TenantID: "t1",
					EventType: "DECISION", Quantity: 1, Timestamp: base,
				})
			}
		}(i)
	}
	wg.Wait()
	usage := ms.GetUsage("t1", base.Add(-time.Hour), base.Add(time.Hour))
	if usage.DecisionCount != 10000 {
		t.Fatalf("expected 10000 decisions, got %d", usage.DecisionCount)
	}
}

func TestStress_Concurrent_IsolationAudit(t *testing.T) {
	auditor := newIsolationAuditorWithClock(stressSaasClock)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			resources := map[string]string{fmt.Sprintf("r-%d", id): fmt.Sprintf("t-%d", id)}
			auditor.Audit(fmt.Sprintf("t-%d", id), resources)
		}(i)
	}
	wg.Wait()
}

func TestStress_Concurrent_LifecycleOps(t *testing.T) {
	svc := newOnboardingServiceWithClock(stressSaasClock)
	for i := 0; i < 50; i++ {
		svc.CreateTenant(fmt.Sprintf("cl-%d", i), fmt.Sprintf("Org-%d", i), "enterprise")
	}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			tid := fmt.Sprintf("cl-%d", id)
			svc.SuspendTenant(tid, "test")
			svc.ActivateTenant(tid)
		}(i)
	}
	wg.Wait()
}

func TestStress_Concurrent_ListTenants(t *testing.T) {
	svc := newOnboardingServiceWithClock(stressSaasClock)
	for i := 0; i < 20; i++ {
		svc.CreateTenant(fmt.Sprintf("lt-%d", i), "Org", "free")
	}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			svc.ListTenants()
		}()
	}
	wg.Wait()
}

func TestStress_Metering_EvidencePackGB(t *testing.T) {
	ms := newMeteringServiceWithClock(stressSaasClock)
	base := stressSaasClock()
	ms.RecordEvent(BillingEvent{EventID: "ep1", TenantID: "t1", EventType: "EVIDENCE_PACK", Quantity: 1024, Timestamp: base})
	usage := ms.GetUsage("t1", base.Add(-time.Hour), base.Add(time.Hour))
	if usage.EvidencePacksGB != 1.0 {
		t.Fatalf("expected 1.0 GB, got %f", usage.EvidencePacksGB)
	}
}

func TestStress_Metering_ZKProofCompute(t *testing.T) {
	ms := newMeteringServiceWithClock(stressSaasClock)
	base := stressSaasClock()
	ms.RecordEvent(BillingEvent{EventID: "zk1", TenantID: "t1", EventType: "ZK_PROOF", Quantity: 5000, Timestamp: base})
	usage := ms.GetUsage("t1", base.Add(-time.Hour), base.Add(time.Hour))
	if usage.ComputeMillis != 5000 {
		t.Fatalf("expected 5000 millis, got %d", usage.ComputeMillis)
	}
}

func TestStress_Onboarding_StatusAfterCreate(t *testing.T) {
	svc := newOnboardingServiceWithClock(stressSaasClock)
	rec, _ := svc.CreateTenant("sc1", "Org", "free")
	if rec.Status != TenantActive {
		t.Fatalf("expected ACTIVE after create, got %s", rec.Status)
	}
}

func TestStress_Onboarding_PlanPreserved(t *testing.T) {
	svc := newOnboardingServiceWithClock(stressSaasClock)
	rec, _ := svc.CreateTenant("pp1", "Org", "enterprise")
	if rec.Plan != "enterprise" {
		t.Fatalf("expected enterprise plan, got %s", rec.Plan)
	}
}

func TestStress_Lifecycle_DeactivateFromSuspended(t *testing.T) {
	svc := newOnboardingServiceWithClock(stressSaasClock)
	svc.CreateTenant("ds1", "Org", "free")
	svc.SuspendTenant("ds1", "test")
	if err := svc.DeactivateTenant("ds1"); err != nil {
		t.Fatalf("should be able to deactivate from suspended: %v", err)
	}
}

func TestStress_Onboarding_ActivateNotFound(t *testing.T) {
	svc := newOnboardingServiceWithClock(stressSaasClock)
	if err := svc.ActivateTenant("ghost"); err == nil {
		t.Fatal("expected error for nonexistent tenant")
	}
}

func TestStress_Onboarding_DeactivateNotFound(t *testing.T) {
	svc := newOnboardingServiceWithClock(stressSaasClock)
	if err := svc.DeactivateTenant("ghost"); err == nil {
		t.Fatal("expected error for nonexistent tenant")
	}
}

func TestStress_Metering_GetAllUsageEmpty(t *testing.T) {
	ms := newMeteringServiceWithClock(stressSaasClock)
	base := stressSaasClock()
	all := ms.GetAllUsage(base, base.Add(time.Hour))
	if len(all) != 0 {
		t.Fatalf("expected empty usage, got %d", len(all))
	}
}

func TestStress_Isolation_AllLeaks(t *testing.T) {
	auditor := newIsolationAuditorWithClock(stressSaasClock)
	resources := map[string]string{"r1": "other", "r2": "other", "r3": "other"}
	result := auditor.Audit("tenant-a", resources)
	if result.Passed {
		t.Fatal("expected audit to fail with all leaks")
	}
	if result.CrossTenantLeaks != 3 {
		t.Fatalf("expected 3 leaks, got %d", result.CrossTenantLeaks)
	}
}

func TestStress_Concurrent_GetAndCreate(t *testing.T) {
	svc := newOnboardingServiceWithClock(stressSaasClock)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			svc.CreateTenant(fmt.Sprintf("gc-%d", id), "Org", "free")
			svc.GetTenant(fmt.Sprintf("gc-%d", id))
		}(i)
	}
	wg.Wait()
}

func TestStress_Onboarding_SigningKeyUnique(t *testing.T) {
	k1 := generateSigningKeyID("tenant-one")
	k2 := generateSigningKeyID("tenant-two")
	if k1 == k2 {
		t.Fatal("different tenants should get different signing keys")
	}
}

func TestStress_Metering_DecisionEventType(t *testing.T) {
	ms := newMeteringServiceWithClock(stressSaasClock)
	base := stressSaasClock()
	ms.RecordEvent(BillingEvent{EventID: "d1", TenantID: "t1", EventType: "DECISION", Quantity: 5, Timestamp: base})
	usage := ms.GetUsage("t1", base.Add(-time.Hour), base.Add(time.Hour))
	if usage.DecisionCount != 5 {
		t.Fatalf("expected 5 decisions, got %d", usage.DecisionCount)
	}
	if usage.AllowCount != 0 || usage.DenyCount != 0 {
		t.Fatal("DECISION type should not increment allow/deny counts")
	}
}

func TestStress_Onboarding_ContentHashNonEmpty(t *testing.T) {
	svc := newOnboardingServiceWithClock(stressSaasClock)
	rec, _ := svc.CreateTenant("ch1", "Org", "free")
	if rec.ContentHash == "" {
		t.Fatal("expected non-empty content hash after create")
	}
}
