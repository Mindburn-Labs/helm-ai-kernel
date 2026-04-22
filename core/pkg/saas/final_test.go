package saas

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestFinal_TenantStatusConstants(t *testing.T) {
	statuses := []TenantStatus{TenantActive, TenantSuspended, TenantDeactivated}
	if len(statuses) != 3 {
		t.Fatal("expected 3 statuses")
	}
}

func TestFinal_TenantRecordJSONRoundTrip(t *testing.T) {
	tr := TenantRecord{TenantID: "t1", OrgName: "Acme", Status: TenantActive, Plan: "enterprise"}
	data, _ := json.Marshal(tr)
	var got TenantRecord
	json.Unmarshal(data, &got)
	if got.TenantID != "t1" || got.Plan != "enterprise" {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_UsageRecordJSONRoundTrip(t *testing.T) {
	ur := UsageRecord{TenantID: "t1", DecisionCount: 100, AllowCount: 80, DenyCount: 20}
	data, _ := json.Marshal(ur)
	var got UsageRecord
	json.Unmarshal(data, &got)
	if got.DecisionCount != 100 || got.AllowCount != 80 {
		t.Fatal("usage round-trip")
	}
}

func TestFinal_BillingEventJSONRoundTrip(t *testing.T) {
	be := BillingEvent{EventID: "e1", TenantID: "t1", EventType: "DECISION", Quantity: 5}
	data, _ := json.Marshal(be)
	var got BillingEvent
	json.Unmarshal(data, &got)
	if got.EventType != "DECISION" || got.Quantity != 5 {
		t.Fatal("billing event round-trip")
	}
}

func TestFinal_IsolationAuditResultJSONRoundTrip(t *testing.T) {
	ar := IsolationAuditResult{AuditID: "a1", Passed: true, ResourcesAudited: 10}
	data, _ := json.Marshal(ar)
	var got IsolationAuditResult
	json.Unmarshal(data, &got)
	if !got.Passed || got.ResourcesAudited != 10 {
		t.Fatal("audit round-trip")
	}
}

func TestFinal_NewOnboardingService(t *testing.T) {
	svc := NewOnboardingService()
	if svc == nil {
		t.Fatal("nil service")
	}
}

func TestFinal_CreateTenantSuccess(t *testing.T) {
	svc := NewOnboardingService()
	rec, err := svc.CreateTenant("t1", "Acme", "starter")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != TenantActive {
		t.Fatal("should be active")
	}
}

func TestFinal_CreateTenantEmptyID(t *testing.T) {
	svc := NewOnboardingService()
	_, err := svc.CreateTenant("", "Acme", "starter")
	if err == nil {
		t.Fatal("should fail on empty ID")
	}
}

func TestFinal_CreateTenantEmptyOrg(t *testing.T) {
	svc := NewOnboardingService()
	_, err := svc.CreateTenant("t1", "", "starter")
	if err == nil {
		t.Fatal("should fail on empty org")
	}
}

func TestFinal_CreateTenantEmptyPlan(t *testing.T) {
	svc := NewOnboardingService()
	_, err := svc.CreateTenant("t1", "Acme", "")
	if err == nil {
		t.Fatal("should fail on empty plan")
	}
}

func TestFinal_CreateTenantDuplicate(t *testing.T) {
	svc := NewOnboardingService()
	svc.CreateTenant("t1", "Acme", "starter")
	_, err := svc.CreateTenant("t1", "Acme2", "starter")
	if err == nil {
		t.Fatal("should fail on duplicate")
	}
}

func TestFinal_SuspendTenantSuccess(t *testing.T) {
	svc := NewOnboardingService()
	svc.CreateTenant("t1", "Acme", "starter")
	err := svc.SuspendTenant("t1", "payment overdue")
	if err != nil {
		t.Fatal(err)
	}
}

func TestFinal_SuspendNonexistent(t *testing.T) {
	svc := NewOnboardingService()
	err := svc.SuspendTenant("nope", "reason")
	if err == nil {
		t.Fatal("should fail")
	}
}

func TestFinal_ActivateTenantSuccess(t *testing.T) {
	svc := NewOnboardingService()
	svc.CreateTenant("t1", "Acme", "starter")
	svc.SuspendTenant("t1", "reason")
	err := svc.ActivateTenant("t1")
	if err != nil {
		t.Fatal(err)
	}
}

func TestFinal_ActivateNonSuspended(t *testing.T) {
	svc := NewOnboardingService()
	svc.CreateTenant("t1", "Acme", "starter")
	err := svc.ActivateTenant("t1")
	if err == nil {
		t.Fatal("should fail on active tenant")
	}
}

func TestFinal_DeactivateTenantSuccess(t *testing.T) {
	svc := NewOnboardingService()
	svc.CreateTenant("t1", "Acme", "starter")
	err := svc.DeactivateTenant("t1")
	if err != nil {
		t.Fatal(err)
	}
}

func TestFinal_DeactivateAlreadyDeactivated(t *testing.T) {
	svc := NewOnboardingService()
	svc.CreateTenant("t1", "Acme", "starter")
	svc.DeactivateTenant("t1")
	err := svc.DeactivateTenant("t1")
	if err == nil {
		t.Fatal("should fail on already deactivated")
	}
}

func TestFinal_GetTenantExists(t *testing.T) {
	svc := NewOnboardingService()
	svc.CreateTenant("t1", "Acme", "starter")
	rec, ok := svc.GetTenant("t1")
	if !ok || rec.OrgName != "Acme" {
		t.Fatal("tenant not found")
	}
}

func TestFinal_GetTenantMissing(t *testing.T) {
	svc := NewOnboardingService()
	_, ok := svc.GetTenant("nope")
	if ok {
		t.Fatal("should not find")
	}
}

func TestFinal_ListTenants(t *testing.T) {
	svc := NewOnboardingService()
	svc.CreateTenant("t1", "A", "free")
	svc.CreateTenant("t2", "B", "free")
	list := svc.ListTenants()
	if len(list) != 2 {
		t.Fatalf("expected 2, got %d", len(list))
	}
}

func TestFinal_ContentHashOnCreate(t *testing.T) {
	svc := NewOnboardingService()
	rec, _ := svc.CreateTenant("t1", "Acme", "starter")
	if rec.ContentHash == "" {
		t.Fatal("content hash should be set")
	}
}

func TestFinal_SigningKeyIDGenerated(t *testing.T) {
	svc := NewOnboardingService()
	rec, _ := svc.CreateTenant("t1", "Acme", "starter")
	if !strings.HasPrefix(rec.SigningKeyID, "sk-") {
		t.Fatalf("unexpected key ID: %s", rec.SigningKeyID)
	}
}

func TestFinal_SigningKeyIDDeterministic(t *testing.T) {
	k1 := generateSigningKeyID("t1")
	k2 := generateSigningKeyID("t1")
	if k1 != k2 {
		t.Fatal("key ID not deterministic")
	}
}

func TestFinal_NewMeteringService(t *testing.T) {
	svc := NewMeteringService()
	if svc == nil {
		t.Fatal("nil service")
	}
}

func TestFinal_RecordAndGetUsage(t *testing.T) {
	svc := NewMeteringService()
	now := time.Now().UTC()
	svc.RecordEvent(BillingEvent{TenantID: "t1", EventType: "DECISION", Quantity: 10, Timestamp: now})
	usage := svc.GetUsage("t1", now.Add(-time.Hour), now.Add(time.Hour))
	if usage.DecisionCount != 10 {
		t.Fatal("usage mismatch")
	}
}

func TestFinal_GetUsageNoEvents(t *testing.T) {
	svc := NewMeteringService()
	now := time.Now().UTC()
	usage := svc.GetUsage("t1", now.Add(-time.Hour), now.Add(time.Hour))
	if usage.DecisionCount != 0 {
		t.Fatal("should be 0")
	}
}

func TestFinal_GetAllUsage(t *testing.T) {
	svc := NewMeteringService()
	now := time.Now().UTC()
	svc.RecordEvent(BillingEvent{TenantID: "t1", EventType: "DECISION", Quantity: 5, Timestamp: now})
	svc.RecordEvent(BillingEvent{TenantID: "t2", EventType: "RECEIPT", Quantity: 3, Timestamp: now})
	all := svc.GetAllUsage(now.Add(-time.Hour), now.Add(time.Hour))
	if len(all) != 2 {
		t.Fatalf("expected 2, got %d", len(all))
	}
}

func TestFinal_AggregateAllow(t *testing.T) {
	u := &UsageRecord{}
	aggregateEvent(u, BillingEvent{EventType: "ALLOW", Quantity: 3})
	if u.AllowCount != 3 || u.DecisionCount != 3 {
		t.Fatal("allow aggregation")
	}
}

func TestFinal_AggregateDeny(t *testing.T) {
	u := &UsageRecord{}
	aggregateEvent(u, BillingEvent{EventType: "DENY", Quantity: 2})
	if u.DenyCount != 2 || u.DecisionCount != 2 {
		t.Fatal("deny aggregation")
	}
}

func TestFinal_AggregateEvidencePack(t *testing.T) {
	u := &UsageRecord{}
	aggregateEvent(u, BillingEvent{EventType: "EVIDENCE_PACK", Quantity: 1024})
	if u.EvidencePacksGB != 1.0 {
		t.Fatalf("expected 1.0 GB, got %f", u.EvidencePacksGB)
	}
}

func TestFinal_NewIsolationAuditor(t *testing.T) {
	a := NewIsolationAuditor()
	if a == nil {
		t.Fatal("nil auditor")
	}
}

func TestFinal_AuditPassesClean(t *testing.T) {
	a := NewIsolationAuditor()
	result := a.Audit("t1", map[string]string{"r1": "t1", "r2": "t1"})
	if !result.Passed || result.CrossTenantLeaks != 0 {
		t.Fatal("should pass")
	}
}

func TestFinal_AuditDetectsLeak(t *testing.T) {
	a := NewIsolationAuditor()
	result := a.Audit("t1", map[string]string{"r1": "t1", "r2": "t2"})
	if result.Passed || result.CrossTenantLeaks != 1 {
		t.Fatal("should detect leak")
	}
}

func TestFinal_AuditContentHashSet(t *testing.T) {
	a := NewIsolationAuditor()
	result := a.Audit("t1", map[string]string{"r1": "t1"})
	if result.ContentHash == "" {
		t.Fatal("content hash should be set")
	}
}

func TestFinal_AuditIDDeterministic(t *testing.T) {
	fixed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	id1 := generateAuditID("t1", fixed)
	id2 := generateAuditID("t1", fixed)
	if id1 != id2 {
		t.Fatal("audit ID not deterministic")
	}
}
