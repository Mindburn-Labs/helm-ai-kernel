package identity

import (
	"testing"
	"time"
)

func fixedClock(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

func TestNewDelegationSession_DenyAllByDefault(t *testing.T) {
	now := time.Date(2026, 3, 11, 12, 0, 0, 0, time.UTC)
	expires := now.Add(1 * time.Hour)

	s := NewDelegationSession(
		"sess-001", "user-alice", "agent-bot1",
		"nonce-abc", "sha256:policy1", "trust-root-1",
		100, expires, true, fixedClock(now),
	)

	if len(s.AllowedTools) != 0 {
		t.Errorf("expected deny-all (empty AllowedTools), got %v", s.AllowedTools)
	}
	if len(s.Capabilities) != 0 {
		t.Errorf("expected deny-all (empty Capabilities), got %v", s.Capabilities)
	}
	if s.IsToolAllowed("any_tool") {
		t.Error("deny-all session should not allow any tool")
	}
	if s.IsActionAllowed("any", "any") {
		t.Error("deny-all session should not allow any action")
	}
}

func TestDelegationSession_AddCapability(t *testing.T) {
	now := time.Date(2026, 3, 11, 12, 0, 0, 0, time.UTC)
	s := NewDelegationSession(
		"sess-002", "user-alice", "agent-bot1",
		"nonce-def", "sha256:policy1", "trust-root-1",
		100, now.Add(time.Hour), true, fixedClock(now),
	)

	// Valid capability
	err := s.AddCapability(CapabilityGrant{
		Resource: "github_pr_create",
		Actions:  []string{"EXECUTE_TOOL"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Empty resource → error
	err = s.AddCapability(CapabilityGrant{
		Resource: "",
		Actions:  []string{"EXECUTE_TOOL"},
	})
	if err == nil {
		t.Fatal("expected error for empty resource")
	}
	de, ok := err.(*DelegationError)
	if !ok || de.Code != "DELEGATION_INVALID" {
		t.Errorf("expected DELEGATION_INVALID, got %v", err)
	}

	// Empty actions → error
	err = s.AddCapability(CapabilityGrant{
		Resource: "some_tool",
		Actions:  []string{},
	})
	if err == nil {
		t.Fatal("expected error for empty actions")
	}
}

func TestDelegationSession_ToolScoping(t *testing.T) {
	now := time.Date(2026, 3, 11, 12, 0, 0, 0, time.UTC)
	s := NewDelegationSession(
		"sess-003", "user-alice", "agent-bot1",
		"nonce-ghi", "sha256:policy1", "trust-root-1",
		100, now.Add(time.Hour), true, fixedClock(now),
	)

	s.AddAllowedTool("github_pr_create")
	s.AddAllowedTool("slack_send_message")

	if !s.IsToolAllowed("github_pr_create") {
		t.Error("expected github_pr_create to be allowed")
	}
	if !s.IsToolAllowed("slack_send_message") {
		t.Error("expected slack_send_message to be allowed")
	}
	if s.IsToolAllowed("psql_drop_table") {
		t.Error("psql_drop_table should not be allowed")
	}
}

func TestDelegationSession_ActionScoping(t *testing.T) {
	now := time.Date(2026, 3, 11, 12, 0, 0, 0, time.UTC)
	s := NewDelegationSession(
		"sess-004", "user-alice", "agent-bot1",
		"nonce-jkl", "sha256:policy1", "trust-root-1",
		100, now.Add(time.Hour), true, fixedClock(now),
	)

	_ = s.AddCapability(CapabilityGrant{
		Resource: "github_pr_create",
		Actions:  []string{"EXECUTE_TOOL", "READ"},
	})

	if !s.IsActionAllowed("github_pr_create", "EXECUTE_TOOL") {
		t.Error("EXECUTE_TOOL on github_pr_create should be allowed")
	}
	if !s.IsActionAllowed("github_pr_create", "READ") {
		t.Error("READ on github_pr_create should be allowed")
	}
	if s.IsActionAllowed("github_pr_create", "DELETE") {
		t.Error("DELETE on github_pr_create should not be allowed")
	}
	if s.IsActionAllowed("other_tool", "EXECUTE_TOOL") {
		t.Error("actions on ungranted resources should not be allowed")
	}
}

func TestValidateSession_Expiry(t *testing.T) {
	now := time.Date(2026, 3, 11, 12, 0, 0, 0, time.UTC)
	s := NewDelegationSession(
		"sess-005", "user-alice", "agent-bot1",
		"nonce-mno", "sha256:policy1", "trust-root-1",
		100, now.Add(-1*time.Hour), true, fixedClock(now),
	)

	err := ValidateSession(s, "", now, nil)
	if err == nil {
		t.Fatal("expected expiry error")
	}
	de := err.(*DelegationError)
	if de.Code != "DELEGATION_INVALID" {
		t.Errorf("expected DELEGATION_INVALID, got %s", de.Code)
	}
}

func TestValidateSession_NonceReplay(t *testing.T) {
	now := time.Date(2026, 3, 11, 12, 0, 0, 0, time.UTC)
	s := NewDelegationSession(
		"sess-006", "user-alice", "agent-bot1",
		"nonce-pqr", "sha256:policy1", "trust-root-1",
		100, now.Add(time.Hour), true, fixedClock(now),
	)

	// Nonce already used
	checker := func(n string) bool { return n == "nonce-pqr" }

	err := ValidateSession(s, "", now, checker)
	if err == nil {
		t.Fatal("expected nonce replay error")
	}
	de := err.(*DelegationError)
	if de.Code != "DELEGATION_INVALID" {
		t.Errorf("expected DELEGATION_INVALID, got %s", de.Code)
	}
}

func TestValidateSession_VerifierMismatch(t *testing.T) {
	now := time.Date(2026, 3, 11, 12, 0, 0, 0, time.UTC)
	s := NewDelegationSession(
		"sess-007", "user-alice", "agent-bot1",
		"nonce-stu", "sha256:policy1", "trust-root-1",
		100, now.Add(time.Hour), true, fixedClock(now),
	)

	s.BindVerifier("correct-verifier")

	// Correct verifier
	err := ValidateSession(s, "correct-verifier", now, nil)
	if err != nil {
		t.Fatalf("unexpected error with correct verifier: %v", err)
	}

	// Wrong verifier
	err = ValidateSession(s, "wrong-verifier", now, nil)
	if err == nil {
		t.Fatal("expected verifier mismatch error")
	}
	de := err.(*DelegationError)
	if de.Code != "DELEGATION_INVALID" {
		t.Errorf("expected DELEGATION_INVALID, got %s", de.Code)
	}

	// Missing verifier when binding exists
	err = ValidateSession(s, "", now, nil)
	if err == nil {
		t.Fatal("expected missing verifier error")
	}
}

func TestValidateSession_MissingPolicyHash(t *testing.T) {
	now := time.Date(2026, 3, 11, 12, 0, 0, 0, time.UTC)
	s := NewDelegationSession(
		"sess-008", "user-alice", "agent-bot1",
		"nonce-vwx", "", "trust-root-1", // empty policy hash
		100, now.Add(time.Hour), true, fixedClock(now),
	)

	err := ValidateSession(s, "", now, nil)
	if err == nil {
		t.Fatal("expected missing policy hash error")
	}
}

func TestValidateSession_NilSession(t *testing.T) {
	err := ValidateSession(nil, "", time.Now(), nil)
	if err == nil {
		t.Fatal("expected nil session error")
	}
}

func TestValidateSession_HappyPath(t *testing.T) {
	now := time.Date(2026, 3, 11, 12, 0, 0, 0, time.UTC)
	s := NewDelegationSession(
		"sess-009", "user-alice", "agent-bot1",
		"nonce-yz", "sha256:policy1", "trust-root-1",
		100, now.Add(time.Hour), true, fixedClock(now),
	)

	// No nonce replay, no verifier binding
	err := ValidateSession(s, "", now, func(n string) bool { return false })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDelegationSession_EffectiveTools(t *testing.T) {
	now := time.Date(2026, 3, 11, 12, 0, 0, 0, time.UTC)
	s := NewDelegationSession(
		"sess-010", "user-alice", "agent-bot1",
		"nonce-eff", "sha256:policy1", "trust-root-1",
		100, now.Add(time.Hour), true, fixedClock(now),
	)

	s.AddAllowedTool("tool_a")
	s.AddAllowedTool("tool_b")

	available := []string{"tool_a", "tool_c", "tool_d"}
	effective := s.EffectiveTools(available)

	if len(effective) != 1 || effective[0] != "tool_a" {
		t.Errorf("expected [tool_a], got %v", effective)
	}

	// Deny-all: empty allowed tools
	s2 := NewDelegationSession(
		"sess-011", "user-alice", "agent-bot1",
		"nonce-eff2", "sha256:policy1", "trust-root-1",
		100, now.Add(time.Hour), true, fixedClock(now),
	)
	if result := s2.EffectiveTools(available); len(result) != 0 {
		t.Errorf("deny-all session should return empty effective tools, got %v", result)
	}
}

func TestInMemoryDelegationStore(t *testing.T) {
	store := NewInMemoryDelegationStore()
	now := time.Date(2026, 3, 11, 12, 0, 0, 0, time.UTC)

	s := NewDelegationSession(
		"sess-store-1", "user-alice", "agent-bot1",
		"nonce-store", "sha256:policy1", "trust-root-1",
		100, now.Add(time.Hour), true, fixedClock(now),
	)

	// Store + Load
	if err := store.Store(s); err != nil {
		t.Fatalf("store error: %v", err)
	}
	loaded, err := store.Load("sess-store-1")
	if err != nil {
		t.Fatalf("load error: %v", err)
	}
	if loaded.SessionID != "sess-store-1" {
		t.Errorf("expected sess-store-1, got %s", loaded.SessionID)
	}

	// Not found
	loaded, err = store.Load("nonexistent")
	if err != nil || loaded != nil {
		t.Errorf("expected nil for nonexistent, got %v, %v", loaded, err)
	}

	// Revoke
	if err := store.Revoke("sess-store-1"); err != nil {
		t.Fatalf("revoke error: %v", err)
	}
	_, err = store.Load("sess-store-1")
	if err == nil {
		t.Fatal("expected error loading revoked session")
	}

	// Nonce tracking
	if store.IsNonceUsed("test-nonce") {
		t.Error("nonce should not be used yet")
	}
	store.MarkNonceUsed("test-nonce")
	if !store.IsNonceUsed("test-nonce") {
		t.Error("nonce should be marked as used")
	}
}
