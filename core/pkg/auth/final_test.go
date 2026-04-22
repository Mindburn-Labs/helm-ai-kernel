package auth

import (
	"context"
	"encoding/json"
	"testing"
)

func TestFinal_TenantJSONRoundTrip(t *testing.T) {
	tenant := Tenant{ID: "t1", Name: "Acme", Plan: "enterprise", Status: "ACTIVE"}
	data, _ := json.Marshal(tenant)
	var got Tenant
	json.Unmarshal(data, &got)
	if got.ID != "t1" || got.Plan != "enterprise" {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_UserJSONRoundTrip(t *testing.T) {
	u := User{ID: "u1", Email: "test@example.com", TenantID: "t1", Roles: []string{"admin"}}
	data, _ := json.Marshal(u)
	var got User
	json.Unmarshal(data, &got)
	if got.Email != "test@example.com" || len(got.Roles) != 1 {
		t.Fatal("user round-trip")
	}
}

func TestFinal_BasePrincipalGetID(t *testing.T) {
	p := &BasePrincipal{ID: "u1", TenantID: "t1"}
	if p.GetID() != "u1" {
		t.Fatal("GetID")
	}
}

func TestFinal_BasePrincipalGetTenantID(t *testing.T) {
	p := &BasePrincipal{ID: "u1", TenantID: "t1"}
	if p.GetTenantID() != "t1" {
		t.Fatal("GetTenantID")
	}
}

func TestFinal_BasePrincipalGetRoles(t *testing.T) {
	p := &BasePrincipal{Roles: []string{"admin", "viewer"}}
	if len(p.GetRoles()) != 2 {
		t.Fatal("GetRoles")
	}
}

func TestFinal_BasePrincipalHasPermissionAdmin(t *testing.T) {
	p := &BasePrincipal{Roles: []string{"admin"}}
	if !p.HasPermission("anything") {
		t.Fatal("admin should have all permissions")
	}
}

func TestFinal_BasePrincipalHasPermissionNonAdmin(t *testing.T) {
	p := &BasePrincipal{Roles: []string{"viewer"}}
	if p.HasPermission("write") {
		t.Fatal("viewer should not have write")
	}
}

func TestFinal_BasePrincipalNoRoles(t *testing.T) {
	p := &BasePrincipal{Roles: []string{}}
	if p.HasPermission("anything") {
		t.Fatal("no roles should have no permissions")
	}
}

func TestFinal_WithPrincipalAndGet(t *testing.T) {
	p := &BasePrincipal{ID: "u1", TenantID: "t1"}
	ctx := WithPrincipal(context.Background(), p)
	got, err := GetPrincipal(ctx)
	if err != nil || got.GetID() != "u1" {
		t.Fatal("principal not in context")
	}
}

func TestFinal_GetPrincipalMissing(t *testing.T) {
	_, err := GetPrincipal(context.Background())
	if err == nil {
		t.Fatal("should error")
	}
}

func TestFinal_GetTenantIDFromContext(t *testing.T) {
	p := &BasePrincipal{ID: "u1", TenantID: "t1"}
	ctx := WithPrincipal(context.Background(), p)
	tid, err := GetTenantID(ctx)
	if err != nil || tid != "t1" {
		t.Fatal("tenant ID mismatch")
	}
}

func TestFinal_GetTenantIDMissing(t *testing.T) {
	_, err := GetTenantID(context.Background())
	if err == nil {
		t.Fatal("should error")
	}
}

func TestFinal_MustGetTenantIDSuccess(t *testing.T) {
	p := &BasePrincipal{ID: "u1", TenantID: "t1"}
	ctx := WithPrincipal(context.Background(), p)
	tid := MustGetTenantID(ctx)
	if tid != "t1" {
		t.Fatal("tenant ID mismatch")
	}
}

func TestFinal_MustGetTenantIDPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("should panic")
		}
	}()
	MustGetTenantID(context.Background())
}

func TestFinal_PrincipalInterfaceCompliance(t *testing.T) {
	var p Principal = &BasePrincipal{ID: "u1", TenantID: "t1", Roles: []string{"admin"}}
	if p.GetID() != "u1" {
		t.Fatal("interface compliance")
	}
}

func TestFinal_TenantStatusField(t *testing.T) {
	tenant := Tenant{Status: "SUSPENDED"}
	data, _ := json.Marshal(tenant)
	var got Tenant
	json.Unmarshal(data, &got)
	if got.Status != "SUSPENDED" {
		t.Fatal("status field")
	}
}

func TestFinal_UserRolesEmpty(t *testing.T) {
	u := User{Roles: []string{}}
	data, _ := json.Marshal(u)
	var got User
	json.Unmarshal(data, &got)
	if len(got.Roles) != 0 {
		t.Fatal("empty roles")
	}
}

func TestFinal_BasePrincipalMultipleRoles(t *testing.T) {
	p := &BasePrincipal{Roles: []string{"viewer", "editor", "admin"}}
	if !p.HasPermission("anything") {
		t.Fatal("should have permission with admin role")
	}
}

func TestFinal_ContextKeyUniqueness(t *testing.T) {
	p1 := &BasePrincipal{ID: "u1"}
	p2 := &BasePrincipal{ID: "u2"}
	ctx := WithPrincipal(context.Background(), p1)
	ctx = WithPrincipal(ctx, p2)
	got, _ := GetPrincipal(ctx)
	if got.GetID() != "u2" {
		t.Fatal("latest principal should win")
	}
}

func TestFinal_TenantAllFields(t *testing.T) {
	tenant := Tenant{ID: "t1", Name: "Acme", Plan: "free", Status: "ACTIVE"}
	data, _ := json.Marshal(tenant)
	if len(data) == 0 {
		t.Fatal("should serialize")
	}
}

func TestFinal_UserAllFields(t *testing.T) {
	u := User{ID: "u1", Email: "a@b.com", TenantID: "t1", Roles: []string{"admin"}}
	data, _ := json.Marshal(u)
	if len(data) == 0 {
		t.Fatal("should serialize")
	}
}

func TestFinal_GetPrincipalRoundTrip(t *testing.T) {
	p := &BasePrincipal{ID: "u1", TenantID: "t1", Roles: []string{"viewer"}}
	ctx := WithPrincipal(context.Background(), p)
	got, _ := GetPrincipal(ctx)
	if got.GetTenantID() != "t1" {
		t.Fatal("tenant mismatch after round-trip")
	}
}

func TestFinal_BasePrincipalEmptyID(t *testing.T) {
	p := &BasePrincipal{}
	if p.GetID() != "" {
		t.Fatal("empty should return empty")
	}
}

func TestFinal_BasePrincipalEmptyTenant(t *testing.T) {
	p := &BasePrincipal{}
	if p.GetTenantID() != "" {
		t.Fatal("empty should return empty")
	}
}

func TestFinal_BasePrincipalEmptyRoles(t *testing.T) {
	p := &BasePrincipal{}
	if p.GetRoles() != nil {
		t.Fatal("nil roles should return nil")
	}
}

func TestFinal_HasPermissionWithMultipleNonAdmin(t *testing.T) {
	p := &BasePrincipal{Roles: []string{"viewer", "editor"}}
	if p.HasPermission("admin_action") {
		t.Fatal("non-admin roles should not have admin permissions")
	}
}

func TestFinal_TenantPlanField(t *testing.T) {
	for _, plan := range []string{"free", "starter", "enterprise"} {
		tenant := Tenant{Plan: plan}
		data, _ := json.Marshal(tenant)
		var got Tenant
		json.Unmarshal(data, &got)
		if got.Plan != plan {
			t.Fatalf("plan %s lost", plan)
		}
	}
}

func TestFinal_UserEmailField(t *testing.T) {
	u := User{Email: "test@example.com"}
	data, _ := json.Marshal(u)
	var got User
	json.Unmarshal(data, &got)
	if got.Email != "test@example.com" {
		t.Fatal("email lost")
	}
}
