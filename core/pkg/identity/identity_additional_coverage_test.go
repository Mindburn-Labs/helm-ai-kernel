package identity

import (
	"testing"
	"time"
)

// ── FileStore Persistence ───────────────────────────────────

// ── Delegation with MFA ─────────────────────────────────────

func TestDelegation_MFASessionPassesValidation(t *testing.T) {
	now := time.Now()
	s := validSession(now) // CreatedWithMFA = true
	err := ValidateSession(s, "", now, nil)
	if err != nil {
		t.Fatalf("MFA session should pass: %v", err)
	}
}

func TestDelegation_NonMFASessionStillValid(t *testing.T) {
	now := time.Now()
	s := NewDelegationSession("s1", "d", "g", "n1", "sha256:abc", "t", 0, now.Add(time.Hour), false, staticClock(now))
	err := ValidateSession(s, "", now, nil)
	if err != nil {
		t.Fatalf("non-MFA session should still pass validation: %v", err)
	}
}

func TestDelegation_VerifierBindingWithMFA(t *testing.T) {
	now := time.Now()
	s := NewDelegationSession("s1", "d", "g", "n1", "sha256:abc", "t", 0, now.Add(time.Hour), true, staticClock(now))
	s.BindVerifier("mfa-secret")
	err := ValidateSession(s, "mfa-secret", now, nil)
	if err != nil {
		t.Fatalf("MFA + correct verifier should pass: %v", err)
	}
}

// ── Principal Types ─────────────────────────────────────────

func TestPrincipalType_UserConstant(t *testing.T) {
	if PrincipalUser != "USER" {
		t.Fatalf("expected USER, got %s", PrincipalUser)
	}
}

func TestPrincipalType_ServiceConstant(t *testing.T) {
	if PrincipalService != "SERVICE" {
		t.Fatalf("expected SERVICE, got %s", PrincipalService)
	}
}

// ── Agent Identity Wrapping ─────────────────────────────────

func TestAgentIdentity_ScopesStored(t *testing.T) {
	a := &AgentIdentity{AgentID: "a1", DelegatorID: "u1", Scopes: []string{"read", "write"}}
	if len(a.Scopes) != 2 || a.Scopes[0] != "read" {
		t.Fatalf("scopes not stored correctly: %v", a.Scopes)
	}
}

func TestAgentIdentity_DelegatorIDStored(t *testing.T) {
	a := &AgentIdentity{AgentID: "a", DelegatorID: "user-42"}
	if a.DelegatorID != "user-42" {
		t.Fatalf("expected user-42, got %s", a.DelegatorID)
	}
}

// ── Device Identity ─────────────────────────────────────────

// ── Concurrent Store Access ─────────────────────────────────

// ── InMemoryKeySet ──────────────────────────────────────────
