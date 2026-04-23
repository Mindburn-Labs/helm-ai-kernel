//go:build conformance

package identity

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// ── SCIM Lifecycle Tests ──────────────────────────────────────

func TestSCIM_CreateUser(t *testing.T) {
	t.Parallel()
	srv := NewSCIMServer()
	mux := http.NewServeMux()
	srv.RegisterRoutes(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	body := `{"userName":"alice@example.com","name":{"givenName":"Alice","familyName":"Smith"}}`
	resp, err := http.Post(ts.URL+"/scim/v2/Users", "application/scim+json", bytes.NewBufferString(body))
	if err != nil {
		t.Fatalf("POST failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}

	var user SCIMUser
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	if user.ID == "" {
		t.Error("expected user ID")
	}
	if user.UserName != "alice@example.com" {
		t.Errorf("expected userName=alice@example.com, got %s", user.UserName)
	}
	if !user.Active {
		t.Error("expected user to be active")
	}
	if user.Schemas[0] != "urn:ietf:params:scim:schemas:core:2.0:User" {
		t.Errorf("unexpected schema: %v", user.Schemas)
	}

	t.Logf("created user: id=%s userName=%s", user.ID, user.UserName)
}

func TestSCIM_ListUsers(t *testing.T) {
	t.Parallel()
	srv := NewSCIMServer()
	mux := http.NewServeMux()
	srv.RegisterRoutes(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Create 2 users
	for _, name := range []string{"alice@example.com", "bob@example.com"} {
		body := `{"userName":"` + name + `"}`
		resp, _ := http.Post(ts.URL+"/scim/v2/Users", "application/scim+json", bytes.NewBufferString(body))
		resp.Body.Close()
	}

	resp, err := http.Get(ts.URL + "/scim/v2/Users")
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	defer resp.Body.Close()

	var list SCIMListResponse
	json.NewDecoder(resp.Body).Decode(&list)

	if list.TotalResults != 2 {
		t.Errorf("expected 2 users, got %d", list.TotalResults)
	}

	t.Logf("listed %d users", list.TotalResults)
}

func TestSCIM_UpdateUser(t *testing.T) {
	t.Parallel()
	srv := NewSCIMServer()
	mux := http.NewServeMux()
	srv.RegisterRoutes(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Create user
	body := `{"userName":"alice@example.com","name":{"givenName":"Alice","familyName":"Smith"}}`
	resp, _ := http.Post(ts.URL+"/scim/v2/Users", "application/scim+json", bytes.NewBufferString(body))
	var user SCIMUser
	json.NewDecoder(resp.Body).Decode(&user)
	resp.Body.Close()

	// Update — change family name
	updateBody := `{"userName":"alice@example.com","name":{"givenName":"Alice","familyName":"Johnson"},"active":true}`
	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/scim/v2/Users/"+user.ID, bytes.NewBufferString(updateBody))
	req.Header.Set("Content-Type", "application/scim+json")
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT failed: %v", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp2.StatusCode)
	}

	var updated SCIMUser
	json.NewDecoder(resp2.Body).Decode(&updated)

	if updated.Name.FamilyName != "Johnson" {
		t.Errorf("expected FamilyName=Johnson, got %s", updated.Name.FamilyName)
	}
	if updated.ID != user.ID {
		t.Error("ID should be preserved")
	}

	t.Logf("updated user: familyName=%s", updated.Name.FamilyName)
}

func TestSCIM_DeleteUser_SoftDelete(t *testing.T) {
	t.Parallel()
	srv := NewSCIMServer()
	mux := http.NewServeMux()
	srv.RegisterRoutes(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Create user
	body := `{"userName":"alice@example.com"}`
	resp, _ := http.Post(ts.URL+"/scim/v2/Users", "application/scim+json", bytes.NewBufferString(body))
	var user SCIMUser
	json.NewDecoder(resp.Body).Decode(&user)
	resp.Body.Close()

	// Delete
	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/scim/v2/Users/"+user.ID, nil)
	resp2, _ := http.DefaultClient.Do(req)
	if resp2.StatusCode != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", resp2.StatusCode)
	}
	resp2.Body.Close()

	// Verify soft delete — GET still finds the user but inactive
	resp3, _ := http.Get(ts.URL + "/scim/v2/Users/" + user.ID)
	var deleted SCIMUser
	json.NewDecoder(resp3.Body).Decode(&deleted)
	resp3.Body.Close()

	if deleted.Active {
		t.Error("deleted user should be inactive")
	}

	// List should exclude deactivated users
	resp4, _ := http.Get(ts.URL + "/scim/v2/Users")
	var list SCIMListResponse
	json.NewDecoder(resp4.Body).Decode(&list)
	resp4.Body.Close()

	if list.TotalResults != 0 {
		t.Errorf("expected 0 active users after delete, got %d", list.TotalResults)
	}

	t.Log("soft delete verified: user deactivated, excluded from list")
}

func TestSCIM_CrossTenantIsolation(t *testing.T) {
	t.Parallel()
	srv := NewSCIMServer()
	mux := http.NewServeMux()
	srv.RegisterRoutes(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Create same userName in different tenants
	body1 := `{"userName":"alice@example.com","urn:helm:params:scim:tenantId":"tenant-a"}`
	resp1, _ := http.Post(ts.URL+"/scim/v2/Users", "application/scim+json", bytes.NewBufferString(body1))
	resp1.Body.Close()

	body2 := `{"userName":"alice@example.com","urn:helm:params:scim:tenantId":"tenant-b"}`
	resp2, _ := http.Post(ts.URL+"/scim/v2/Users", "application/scim+json", bytes.NewBufferString(body2))
	resp2.Body.Close()

	if resp1.StatusCode != http.StatusCreated {
		t.Errorf("first create should succeed: %d", resp1.StatusCode)
	}
	if resp2.StatusCode != http.StatusCreated {
		t.Errorf("second create in different tenant should succeed: %d", resp2.StatusCode)
	}

	t.Log("cross-tenant isolation verified: same userName allowed in different tenants")
}

func TestSCIM_Groups(t *testing.T) {
	t.Parallel()
	srv := NewSCIMServer()
	mux := http.NewServeMux()
	srv.RegisterRoutes(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	body := `{"displayName":"Engineering"}`
	resp, _ := http.Post(ts.URL+"/scim/v2/Groups", "application/scim+json", bytes.NewBufferString(body))
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}

	var group SCIMGroup
	json.NewDecoder(resp.Body).Decode(&group)

	if group.DisplayName != "Engineering" {
		t.Errorf("expected displayName=Engineering, got %s", group.DisplayName)
	}

	t.Logf("created group: id=%s displayName=%s", group.ID, group.DisplayName)
}

// ── Conditional Access Tests ──────────────────────────────────

func TestConditionalAccess_AllowByDefault(t *testing.T) {
	t.Parallel()
	engine := NewConditionalAccessEngine()

	decision := engine.Evaluate(AccessContext{
		PrincipalID: "user-1",
		SourceIP:    "192.168.1.10",
	})

	if decision != AccessAllow {
		t.Errorf("expected ALLOW, got %s", decision)
	}
}

func TestConditionalAccess_DenyByIP(t *testing.T) {
	t.Parallel()
	engine := NewConditionalAccessEngine()
	engine.AddPolicy(&ConditionalPolicy{
		ID:       "deny-external",
		Name:     "Deny External IPs",
		Priority: 1,
		Active:   true,
		Conditions: PolicyConditions{
			AllowedIPRanges: []string{"10.0.0.0/8", "172.16.0.0/12"},
		},
		Decision: AccessDeny,
	})

	// External IP → should match the policy (not in allowed range) → DENY
	decision := engine.Evaluate(AccessContext{
		PrincipalID: "user-1",
		SourceIP:    "203.0.113.50",
		RequestTime: time.Now(),
	})

	if decision != AccessDeny {
		t.Errorf("expected DENY for external IP, got %s", decision)
	}
}

func TestConditionalAccess_RequireMFA_HighRisk(t *testing.T) {
	t.Parallel()
	engine := NewConditionalAccessEngine()
	engine.AddPolicy(&ConditionalPolicy{
		ID:       "mfa-risky",
		Name:     "Require MFA for High Risk",
		Priority: 1,
		Active:   true,
		Conditions: PolicyConditions{
			MaxRiskScore: 0.7,
		},
		Decision: AccessRequireMFA,
	})

	// High risk score → REQUIRE_MFA
	decision := engine.Evaluate(AccessContext{
		PrincipalID: "user-1",
		RiskScore:   0.9,
		RequestTime: time.Now(),
	})

	if decision != AccessRequireMFA {
		t.Errorf("expected REQUIRE_MFA for high risk, got %s", decision)
	}
}

func TestConditionalAccess_DenyByLocation(t *testing.T) {
	t.Parallel()
	engine := NewConditionalAccessEngine()
	engine.AddPolicy(&ConditionalPolicy{
		ID:       "deny-country",
		Name:     "Deny Embargoed Locations",
		Priority: 1,
		Active:   true,
		Conditions: PolicyConditions{
			DeniedLocations: []string{"KP", "IR", "SY"},
		},
		Decision: AccessDeny,
	})

	decision := engine.Evaluate(AccessContext{
		PrincipalID: "user-1",
		Location:    "KP",
		RequestTime: time.Now(),
	})

	if decision != AccessDeny {
		t.Errorf("expected DENY for embargoed location, got %s", decision)
	}
}

func TestConditionalAccess_TenantScoping(t *testing.T) {
	t.Parallel()
	engine := NewConditionalAccessEngine()
	engine.AddPolicy(&ConditionalPolicy{
		ID:       "tenant-a-restrict",
		Name:     "Restrict Tenant A",
		Priority: 1,
		Active:   true,
		TenantID: "tenant-a",
		Conditions: PolicyConditions{
			AllowedDeviceTypes: []string{"managed"},
		},
		Decision: AccessDeny,
	})

	// Tenant A with unmanaged device → DENY
	decision := engine.Evaluate(AccessContext{
		PrincipalID: "user-1",
		TenantID:    "tenant-a",
		DeviceType:  "unmanaged",
		RequestTime: time.Now(),
	})
	if decision != AccessDeny {
		t.Errorf("expected DENY for unmanaged device in tenant-a, got %s", decision)
	}

	// Tenant B with unmanaged device → ALLOW (policy scoped to tenant-a)
	decision2 := engine.Evaluate(AccessContext{
		PrincipalID: "user-1",
		TenantID:    "tenant-b",
		DeviceType:  "unmanaged",
		RequestTime: time.Now(),
	})
	if decision2 != AccessAllow {
		t.Errorf("expected ALLOW for tenant-b, got %s", decision2)
	}
}
