package tenants

import (
	"context"
	"testing"
	"time"
)

func TestTenantStore_CRUD(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryTenantStore()

	tenant := &Tenant{
		TenantID:  "t-001",
		Name:      "Acme Corp",
		Edition:   "enterprise",
		Status:    StatusActive,
		OwnerID:   "user-owner-1",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}

	// Create
	if err := store.Create(ctx, tenant); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Duplicate create should fail
	if err := store.Create(ctx, tenant); err == nil {
		t.Fatal("duplicate Create should fail")
	}

	// Get
	got, err := store.Get(ctx, "t-001")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if got.Name != "Acme Corp" {
		t.Errorf("Name = %s, want Acme Corp", got.Name)
	}

	// Get nonexistent
	if _, err := store.Get(ctx, "nonexistent"); err == nil {
		t.Fatal("Get nonexistent should fail")
	}

	// Update
	tenant.Name = "Acme Industries"
	if err := store.Update(ctx, tenant); err != nil {
		t.Fatalf("Update failed: %v", err)
	}
	got, _ = store.Get(ctx, "t-001")
	if got.Name != "Acme Industries" {
		t.Errorf("Name after update = %s, want Acme Industries", got.Name)
	}

	// Update nonexistent
	if err := store.Update(ctx, &Tenant{TenantID: "nonexistent"}); err == nil {
		t.Fatal("Update nonexistent should fail")
	}

	// List
	store.Create(ctx, &Tenant{TenantID: "t-002", Name: "Beta Corp", Status: StatusActive, OwnerID: "user-2", CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()})
	list, err := store.List(ctx)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(list) != 2 {
		t.Errorf("List length = %d, want 2", len(list))
	}
}

func TestTenantStore_Limits(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryTenantStore()

	limits := &TenantLimits{
		TenantID:          "t-001",
		MaxWorkspaces:     10,
		MaxEmployees:      50,
		MaxConnectors:     5,
		MaxDailyActions:   10000,
		MaxBudgetCentsDay: 5000,
		MaxStorageBytes:   1 << 30,
	}

	if err := store.SetLimits(ctx, limits); err != nil {
		t.Fatalf("SetLimits failed: %v", err)
	}

	got, err := store.GetLimits(ctx, "t-001")
	if err != nil {
		t.Fatalf("GetLimits failed: %v", err)
	}
	if got.MaxWorkspaces != 10 {
		t.Errorf("MaxWorkspaces = %d, want 10", got.MaxWorkspaces)
	}

	// Nonexistent limits
	if _, err := store.GetLimits(ctx, "nonexistent"); err == nil {
		t.Fatal("GetLimits for nonexistent tenant should fail")
	}
}

func TestIsolationEnforcer_SameTenantAllowed(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryTenantStore()

	store.Create(ctx, &Tenant{
		TenantID:     "t-001",
		Name:         "Acme Corp",
		Status:       StatusActive,
		OwnerID:      "user-owner",
		PrincipalIDs: []string{"user-member-1", "user-member-2"},
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	})

	enforcer := NewIsolationEnforcer(store)

	// Owner access
	check := enforcer.CheckAccess(ctx, "user-owner", "t-001", "workspace-1")
	if !check.Allowed {
		t.Errorf("owner should be allowed, got denied: %s", check.Reason)
	}

	// Member access
	check = enforcer.CheckAccess(ctx, "user-member-1", "t-001", "workspace-1")
	if !check.Allowed {
		t.Errorf("member should be allowed, got denied: %s", check.Reason)
	}
}

func TestIsolationEnforcer_CrossTenantDenied(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryTenantStore()

	store.Create(ctx, &Tenant{
		TenantID:     "t-001",
		Name:         "Acme Corp",
		Status:       StatusActive,
		OwnerID:      "user-owner",
		PrincipalIDs: []string{"user-member-1"},
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	})

	enforcer := NewIsolationEnforcer(store)

	// Foreign principal
	check := enforcer.CheckAccess(ctx, "foreign-user", "t-001", "workspace-1")
	if check.Allowed {
		t.Error("cross-tenant access should be denied")
	}
}

func TestIsolationEnforcer_SuspendedTenantDenied(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryTenantStore()

	store.Create(ctx, &Tenant{
		TenantID:     "t-001",
		Name:         "Suspended Corp",
		Status:       StatusSuspended,
		OwnerID:      "user-owner",
		PrincipalIDs: []string{},
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	})

	enforcer := NewIsolationEnforcer(store)

	check := enforcer.CheckAccess(ctx, "user-owner", "t-001", "workspace-1")
	if check.Allowed {
		t.Error("suspended tenant access should be denied even for owner")
	}
	if check.Reason != "tenant t-001 is suspended" {
		t.Errorf("unexpected reason: %s", check.Reason)
	}
}

func TestIsolationEnforcer_NonexistentTenantDenied(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryTenantStore()
	enforcer := NewIsolationEnforcer(store)

	check := enforcer.CheckAccess(ctx, "user-owner", "nonexistent", "workspace-1")
	if check.Allowed {
		t.Error("nonexistent tenant access should be denied (fail-closed)")
	}
}

func TestIsolationEnforcer_EnforceLimits_WithinLimits(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryTenantStore()
	store.SetLimits(ctx, &TenantLimits{
		TenantID:      "t-001",
		MaxWorkspaces: 10,
		MaxEmployees:  50,
		MaxConnectors: 5,
	})

	enforcer := NewIsolationEnforcer(store)

	ok, reason := enforcer.EnforceLimits(ctx, "t-001", 5, 25, 3)
	if !ok {
		t.Errorf("within limits should be allowed: %s", reason)
	}
}

func TestIsolationEnforcer_EnforceLimits_Exceeded(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryTenantStore()
	store.SetLimits(ctx, &TenantLimits{
		TenantID:      "t-001",
		MaxWorkspaces: 10,
		MaxEmployees:  50,
		MaxConnectors: 5,
	})

	enforcer := NewIsolationEnforcer(store)

	// Workspace limit exceeded
	ok, _ := enforcer.EnforceLimits(ctx, "t-001", 11, 25, 3)
	if ok {
		t.Error("workspace limit exceeded should be denied")
	}

	// Employee limit exceeded
	ok, _ = enforcer.EnforceLimits(ctx, "t-001", 5, 51, 3)
	if ok {
		t.Error("employee limit exceeded should be denied")
	}

	// Connector limit exceeded
	ok, _ = enforcer.EnforceLimits(ctx, "t-001", 5, 25, 6)
	if ok {
		t.Error("connector limit exceeded should be denied")
	}
}

func TestIsolationEnforcer_EnforceLimits_NoLimitsFailClosed(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryTenantStore()
	enforcer := NewIsolationEnforcer(store)

	ok, _ := enforcer.EnforceLimits(ctx, "nonexistent", 1, 1, 1)
	if ok {
		t.Error("missing limits should fail closed (deny)")
	}
}
