package rbac

import (
	"context"
	"testing"
	"time"
)

func TestBuiltinRoles(t *testing.T) {
	roles := BuiltinRoles()
	if len(roles) != 4 {
		t.Fatalf("expected 4 built-in roles, got %d", len(roles))
	}

	ids := make(map[string]bool)
	for _, r := range roles {
		if !r.IsBuiltin {
			t.Errorf("role %s should be built-in", r.RoleID)
		}
		if len(r.Permissions) == 0 {
			t.Errorf("role %s has no permissions", r.RoleID)
		}
		ids[r.RoleID] = true
	}

	for _, expected := range []string{"owner", "admin", "manager", "viewer"} {
		if !ids[expected] {
			t.Errorf("missing built-in role: %s", expected)
		}
	}
}

func TestMatchPermission_ExactMatch(t *testing.T) {
	if !MatchPermission("inbox:approve", "inbox:approve") {
		t.Error("exact match should succeed")
	}
}

func TestMatchPermission_WildcardMatch(t *testing.T) {
	if !MatchPermission("workspace:*", "workspace:read") {
		t.Error("wildcard should match workspace:read")
	}
	if !MatchPermission("workspace:*", "workspace:write") {
		t.Error("wildcard should match workspace:write")
	}
}

func TestMatchPermission_NoMatch(t *testing.T) {
	if MatchPermission("workspace:read", "workspace:write") {
		t.Error("workspace:read should not match workspace:write")
	}
	if MatchPermission("inbox:*", "workspace:read") {
		t.Error("inbox:* should not match workspace:read")
	}
}

func TestEnforcer_OwnerHasAll(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryRBACStore()

	store.CreateBinding(ctx, &RoleBinding{
		BindingID:   "b-1",
		PrincipalID: "user-owner",
		RoleID:      "owner",
		TenantID:    "t-001",
		Scope:       "tenant",
		CreatedAt:   time.Now().UTC(),
	})

	enforcer := NewEnforcer(store)

	// Owner should have all permissions.
	perms := []string{"workspace:read", "workspace:write", "employee:manage", "tenant:manage", "export:read", "policy:write"}
	for _, p := range perms {
		d := enforcer.Check(ctx, "user-owner", "t-001", p, "tenant")
		if !d.Allowed {
			t.Errorf("owner should have %s, got denied: %s", p, d.Reason)
		}
	}
}

func TestEnforcer_ViewerReadOnly(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryRBACStore()

	store.CreateBinding(ctx, &RoleBinding{
		BindingID:   "b-1",
		PrincipalID: "user-viewer",
		RoleID:      "viewer",
		TenantID:    "t-001",
		Scope:       "tenant",
		CreatedAt:   time.Now().UTC(),
	})

	enforcer := NewEnforcer(store)

	// Viewer should have read permissions.
	d := enforcer.Check(ctx, "user-viewer", "t-001", "workspace:read", "tenant")
	if !d.Allowed {
		t.Errorf("viewer should have workspace:read: %s", d.Reason)
	}

	// Viewer should NOT have write/manage permissions.
	denied := []string{"workspace:write", "employee:manage", "tenant:manage", "policy:write"}
	for _, p := range denied {
		d := enforcer.Check(ctx, "user-viewer", "t-001", p, "tenant")
		if d.Allowed {
			t.Errorf("viewer should not have %s", p)
		}
	}
}

func TestEnforcer_NoBindingDenied(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryRBACStore()
	enforcer := NewEnforcer(store)

	d := enforcer.Check(ctx, "unknown-user", "t-001", "workspace:read", "tenant")
	if d.Allowed {
		t.Error("user with no bindings should be denied")
	}
}

func TestEnforcer_ExpiredBindingDenied(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryRBACStore()

	past := time.Now().Add(-1 * time.Hour)
	store.CreateBinding(ctx, &RoleBinding{
		BindingID:   "b-expired",
		PrincipalID: "user-1",
		RoleID:      "owner",
		TenantID:    "t-001",
		Scope:       "tenant",
		CreatedAt:   time.Now().Add(-2 * time.Hour),
		ExpiresAt:   &past,
	})

	enforcer := NewEnforcer(store)

	d := enforcer.Check(ctx, "user-1", "t-001", "workspace:read", "tenant")
	if d.Allowed {
		t.Error("expired binding should be denied")
	}
}

func TestEnforcer_ScopeFiltering(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryRBACStore()

	// Bind user as manager only in workspace:ws-1
	store.CreateBinding(ctx, &RoleBinding{
		BindingID:   "b-scoped",
		PrincipalID: "user-scoped",
		RoleID:      "manager",
		TenantID:    "t-001",
		Scope:       "workspace:ws-1",
		CreatedAt:   time.Now().UTC(),
	})

	enforcer := NewEnforcer(store)

	// Should be allowed in ws-1
	d := enforcer.Check(ctx, "user-scoped", "t-001", "inbox:approve", "workspace:ws-1")
	if !d.Allowed {
		t.Errorf("should be allowed in workspace:ws-1: %s", d.Reason)
	}

	// Should be denied in ws-2
	d = enforcer.Check(ctx, "user-scoped", "t-001", "inbox:approve", "workspace:ws-2")
	if d.Allowed {
		t.Error("should be denied in workspace:ws-2")
	}
}

func TestEnforcer_TenantScopeMatchesAll(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryRBACStore()

	store.CreateBinding(ctx, &RoleBinding{
		BindingID:   "b-tenant",
		PrincipalID: "user-admin",
		RoleID:      "admin",
		TenantID:    "t-001",
		Scope:       "tenant",
		CreatedAt:   time.Now().UTC(),
	})

	enforcer := NewEnforcer(store)

	// Tenant-scoped binding should match any sub-scope.
	d := enforcer.Check(ctx, "user-admin", "t-001", "workspace:read", "workspace:ws-99")
	if !d.Allowed {
		t.Errorf("tenant-scoped binding should match workspace scope: %s", d.Reason)
	}
}

func TestRBACStore_CRUD(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryRBACStore()

	// Built-in roles should be present.
	role, err := store.GetRole(ctx, "owner")
	if err != nil {
		t.Fatalf("built-in owner role should exist: %v", err)
	}
	if !role.IsBuiltin {
		t.Error("owner role should be built-in")
	}

	// Create custom role.
	custom := &Role{
		RoleID:      "custom-auditor",
		Name:        "Auditor",
		TenantID:    "t-001",
		Permissions: []string{"export:read", "policy:read"},
		CreatedAt:   time.Now().UTC(),
	}
	if err := store.CreateRole(ctx, custom); err != nil {
		t.Fatalf("CreateRole failed: %v", err)
	}

	// Duplicate should fail.
	if err := store.CreateRole(ctx, custom); err == nil {
		t.Fatal("duplicate CreateRole should fail")
	}

	// List roles for tenant.
	roles, err := store.ListRoles(ctx, "t-001")
	if err != nil {
		t.Fatalf("ListRoles failed: %v", err)
	}
	// Should include 4 built-in + 1 custom.
	if len(roles) != 5 {
		t.Errorf("expected 5 roles, got %d", len(roles))
	}

	// Binding CRUD.
	binding := &RoleBinding{
		BindingID:   "b-test",
		PrincipalID: "user-1",
		RoleID:      "custom-auditor",
		TenantID:    "t-001",
		Scope:       "tenant",
		CreatedAt:   time.Now().UTC(),
	}
	if err := store.CreateBinding(ctx, binding); err != nil {
		t.Fatalf("CreateBinding failed: %v", err)
	}
	if err := store.CreateBinding(ctx, binding); err == nil {
		t.Fatal("duplicate binding should fail")
	}

	bindings, err := store.ListBindings(ctx, "user-1", "t-001")
	if err != nil {
		t.Fatalf("ListBindings failed: %v", err)
	}
	if len(bindings) != 1 {
		t.Errorf("expected 1 binding, got %d", len(bindings))
	}

	// Remove binding.
	if err := store.RemoveBinding(ctx, "b-test"); err != nil {
		t.Fatalf("RemoveBinding failed: %v", err)
	}
	if err := store.RemoveBinding(ctx, "b-test"); err == nil {
		t.Fatal("removing nonexistent binding should fail")
	}

	bindings, _ = store.ListBindings(ctx, "user-1", "t-001")
	if len(bindings) != 0 {
		t.Errorf("expected 0 bindings after removal, got %d", len(bindings))
	}
}
