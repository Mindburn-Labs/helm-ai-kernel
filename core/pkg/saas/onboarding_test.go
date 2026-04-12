package saas

import (
	"testing"
	"time"
)

func fixedClock(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

func TestOnboardingService_Create(t *testing.T) {
	now := time.Date(2026, 4, 12, 10, 0, 0, 0, time.UTC)
	svc := newOnboardingServiceWithClock(fixedClock(now))

	record, err := svc.CreateTenant("t-001", "Acme Corp", "enterprise")
	if err != nil {
		t.Fatalf("CreateTenant failed: %v", err)
	}

	if record.TenantID != "t-001" {
		t.Errorf("TenantID = %s, want t-001", record.TenantID)
	}
	if record.OrgName != "Acme Corp" {
		t.Errorf("OrgName = %s, want Acme Corp", record.OrgName)
	}
	if record.Status != TenantActive {
		t.Errorf("Status = %s, want ACTIVE", record.Status)
	}
	if record.Plan != "enterprise" {
		t.Errorf("Plan = %s, want enterprise", record.Plan)
	}
	if record.SigningKeyID == "" {
		t.Error("SigningKeyID should be generated")
	}
	if !record.CreatedAt.Equal(now) {
		t.Errorf("CreatedAt = %v, want %v", record.CreatedAt, now)
	}
	if record.ContentHash == "" {
		t.Error("ContentHash should be computed")
	}

	// Verify tenant is retrievable.
	got, ok := svc.GetTenant("t-001")
	if !ok {
		t.Fatal("GetTenant returned not found")
	}
	if got.TenantID != "t-001" {
		t.Errorf("GetTenant TenantID = %s, want t-001", got.TenantID)
	}
}

func TestOnboardingService_DuplicateID(t *testing.T) {
	svc := NewOnboardingService()

	_, err := svc.CreateTenant("t-001", "Acme Corp", "free")
	if err != nil {
		t.Fatalf("first CreateTenant failed: %v", err)
	}

	_, err = svc.CreateTenant("t-001", "Beta Corp", "starter")
	if err == nil {
		t.Fatal("duplicate CreateTenant should fail")
	}
}

func TestOnboardingService_CreateValidation(t *testing.T) {
	svc := NewOnboardingService()

	if _, err := svc.CreateTenant("", "Acme", "free"); err == nil {
		t.Error("empty tenantID should fail")
	}
	if _, err := svc.CreateTenant("t-001", "", "free"); err == nil {
		t.Error("empty orgName should fail")
	}
	if _, err := svc.CreateTenant("t-001", "Acme", ""); err == nil {
		t.Error("empty plan should fail")
	}
}

func TestOnboardingService_Suspend(t *testing.T) {
	now := time.Date(2026, 4, 12, 10, 0, 0, 0, time.UTC)
	svc := newOnboardingServiceWithClock(fixedClock(now))

	svc.CreateTenant("t-001", "Acme Corp", "enterprise")

	if err := svc.SuspendTenant("t-001", "billing overdue"); err != nil {
		t.Fatalf("SuspendTenant failed: %v", err)
	}

	record, _ := svc.GetTenant("t-001")
	if record.Status != TenantSuspended {
		t.Errorf("Status = %s, want SUSPENDED", record.Status)
	}
	if record.SuspendedAt.IsZero() {
		t.Error("SuspendedAt should be set")
	}

	// Suspending a non-active tenant should fail.
	if err := svc.SuspendTenant("t-001", "again"); err == nil {
		t.Error("suspending already-suspended tenant should fail")
	}

	// Suspending nonexistent tenant should fail.
	if err := svc.SuspendTenant("nonexistent", "reason"); err == nil {
		t.Error("suspending nonexistent tenant should fail")
	}
}

func TestOnboardingService_Lifecycle(t *testing.T) {
	now := time.Date(2026, 4, 12, 10, 0, 0, 0, time.UTC)
	svc := newOnboardingServiceWithClock(fixedClock(now))

	// Create: ACTIVE
	record, err := svc.CreateTenant("t-001", "Acme Corp", "starter")
	if err != nil {
		t.Fatalf("CreateTenant failed: %v", err)
	}
	if record.Status != TenantActive {
		t.Fatalf("initial status = %s, want ACTIVE", record.Status)
	}

	// ACTIVE -> SUSPENDED
	if err := svc.SuspendTenant("t-001", "overdue"); err != nil {
		t.Fatalf("SuspendTenant failed: %v", err)
	}
	record, _ = svc.GetTenant("t-001")
	if record.Status != TenantSuspended {
		t.Fatalf("status after suspend = %s, want SUSPENDED", record.Status)
	}

	// SUSPENDED -> ACTIVE
	if err := svc.ActivateTenant("t-001"); err != nil {
		t.Fatalf("ActivateTenant failed: %v", err)
	}
	record, _ = svc.GetTenant("t-001")
	if record.Status != TenantActive {
		t.Fatalf("status after reactivate = %s, want ACTIVE", record.Status)
	}
	if !record.SuspendedAt.IsZero() {
		t.Error("SuspendedAt should be cleared after reactivation")
	}

	// Activating an already-active tenant should fail.
	if err := svc.ActivateTenant("t-001"); err == nil {
		t.Error("activating already-active tenant should fail")
	}

	// ACTIVE -> DEACTIVATED
	if err := svc.DeactivateTenant("t-001"); err != nil {
		t.Fatalf("DeactivateTenant failed: %v", err)
	}
	record, _ = svc.GetTenant("t-001")
	if record.Status != TenantDeactivated {
		t.Fatalf("status after deactivate = %s, want DEACTIVATED", record.Status)
	}

	// DEACTIVATED is terminal.
	if err := svc.DeactivateTenant("t-001"); err == nil {
		t.Error("deactivating already-deactivated tenant should fail")
	}
	if err := svc.SuspendTenant("t-001", "reason"); err == nil {
		t.Error("suspending deactivated tenant should fail")
	}

	// Nonexistent tenant operations should fail.
	if err := svc.ActivateTenant("nonexistent"); err == nil {
		t.Error("activating nonexistent tenant should fail")
	}
	if err := svc.DeactivateTenant("nonexistent"); err == nil {
		t.Error("deactivating nonexistent tenant should fail")
	}
}

func TestOnboardingService_ListTenants(t *testing.T) {
	svc := NewOnboardingService()

	// Empty list.
	if list := svc.ListTenants(); len(list) != 0 {
		t.Errorf("ListTenants on empty = %d, want 0", len(list))
	}

	svc.CreateTenant("t-001", "Acme", "free")
	svc.CreateTenant("t-002", "Beta", "starter")
	svc.CreateTenant("t-003", "Gamma", "enterprise")

	list := svc.ListTenants()
	if len(list) != 3 {
		t.Errorf("ListTenants = %d, want 3", len(list))
	}
}

func TestOnboardingService_ContentHashChanges(t *testing.T) {
	now := time.Date(2026, 4, 12, 10, 0, 0, 0, time.UTC)
	svc := newOnboardingServiceWithClock(fixedClock(now))

	record, _ := svc.CreateTenant("t-001", "Acme Corp", "enterprise")
	hashAfterCreate := record.ContentHash

	svc.SuspendTenant("t-001", "reason")
	record, _ = svc.GetTenant("t-001")
	hashAfterSuspend := record.ContentHash

	if hashAfterCreate == hashAfterSuspend {
		t.Error("content hash should change after status transition")
	}
}
