package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"testing"
	"time"
)

// ── Helpers ──────────────────────────────────────────────────

func staticClock(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

func validSession(now time.Time) *DelegationSession {
	return NewDelegationSession(
		"s-valid", "delegator-1", "delegate-1",
		"nonce-1", "sha256:abc", "trust-ref-1",
		50, now.Add(time.Hour), true, staticClock(now),
	)
}

// ── DelegationSession Fields ─────────────────────────────────

func TestSessionFieldsSessionID(t *testing.T) {
	now := time.Now()
	s := NewDelegationSession("id-42", "d", "g", "n", "p", "t", 1, now.Add(time.Hour), false, staticClock(now))
	if s.SessionID != "id-42" {
		t.Fatalf("got %s, want id-42", s.SessionID)
	}
}

func TestSessionFieldsDelegatorPrincipal(t *testing.T) {
	now := time.Now()
	s := NewDelegationSession("s", "alice", "bob", "n", "p", "t", 0, now.Add(time.Hour), false, staticClock(now))
	if s.DelegatorPrincipal != "alice" {
		t.Fatalf("got %s, want alice", s.DelegatorPrincipal)
	}
}

func TestSessionFieldsDelegatePrincipal(t *testing.T) {
	now := time.Now()
	s := NewDelegationSession("s", "alice", "bob", "n", "p", "t", 0, now.Add(time.Hour), false, staticClock(now))
	if s.DelegatePrincipal != "bob" {
		t.Fatalf("got %s, want bob", s.DelegatePrincipal)
	}
}

func TestSessionFieldsNonce(t *testing.T) {
	now := time.Now()
	s := NewDelegationSession("s", "a", "b", "unique-nonce", "p", "t", 0, now.Add(time.Hour), false, staticClock(now))
	if s.SessionNonce != "unique-nonce" {
		t.Fatalf("got %s, want unique-nonce", s.SessionNonce)
	}
}

func TestSessionFieldsPolicyHash(t *testing.T) {
	now := time.Now()
	s := NewDelegationSession("s", "a", "b", "n", "sha256:xyz", "t", 0, now.Add(time.Hour), false, staticClock(now))
	if s.DelegationPolicyHash != "sha256:xyz" {
		t.Fatalf("got %s", s.DelegationPolicyHash)
	}
}

func TestSessionFieldsPrincipalSeqFloor(t *testing.T) {
	now := time.Now()
	s := NewDelegationSession("s", "a", "b", "n", "p", "t", 999, now.Add(time.Hour), false, staticClock(now))
	if s.PrincipalSeqFloor != 999 {
		t.Fatalf("got %d, want 999", s.PrincipalSeqFloor)
	}
}

func TestSessionFieldsCreatedWithMFA(t *testing.T) {
	now := time.Now()
	s := NewDelegationSession("s", "a", "b", "n", "p", "t", 0, now.Add(time.Hour), true, staticClock(now))
	if !s.CreatedWithMFA {
		t.Fatal("expected CreatedWithMFA=true")
	}
}

func TestSessionFieldsCreatedAtUsesClock(t *testing.T) {
	fixed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s := NewDelegationSession("s", "a", "b", "n", "p", "t", 0, fixed.Add(time.Hour), false, staticClock(fixed))
	if !s.CreatedAt.Equal(fixed) {
		t.Fatalf("CreatedAt=%v, want %v", s.CreatedAt, fixed)
	}
}

func TestSessionFieldsNilClockUsesWallClock(t *testing.T) {
	before := time.Now().Add(-time.Second)
	s := NewDelegationSession("s", "a", "b", "n", "p", "t", 0, time.Now().Add(time.Hour), false, nil)
	if s.CreatedAt.Before(before) {
		t.Fatal("CreatedAt should be near wall clock time")
	}
}

func TestSessionFieldsExpiresAt(t *testing.T) {
	now := time.Now()
	exp := now.Add(2 * time.Hour)
	s := NewDelegationSession("s", "a", "b", "n", "p", "t", 0, exp, false, staticClock(now))
	if !s.ExpiresAt.Equal(exp) {
		t.Fatalf("ExpiresAt=%v, want %v", s.ExpiresAt, exp)
	}
}

// ── ValidateSession ──────────────────────────────────────────

func TestValidateSessionNilReturnsError(t *testing.T) {
	err := ValidateSession(nil, "", time.Now(), nil)
	if err == nil {
		t.Fatal("expected error for nil session")
	}
}

func TestValidateSessionExpiredSession(t *testing.T) {
	now := time.Now()
	s := validSession(now)
	s.ExpiresAt = now.Add(-time.Minute)
	err := ValidateSession(s, "", now, nil)
	if err == nil {
		t.Fatal("expected expiry error")
	}
}

func TestValidateSessionExpiredExactBoundary(t *testing.T) {
	now := time.Now()
	s := validSession(now)
	s.ExpiresAt = now // now.After(now) is false, so this passes
	err := ValidateSession(s, "", now, nil)
	if err != nil {
		t.Fatalf("at exact expiry boundary should pass: %v", err)
	}
}

func TestValidateSessionMissingSessionID(t *testing.T) {
	now := time.Now()
	s := validSession(now)
	s.SessionID = ""
	err := ValidateSession(s, "", now, nil)
	if err == nil {
		t.Fatal("expected error for missing SessionID")
	}
}

func TestValidateSessionMissingDelegator(t *testing.T) {
	now := time.Now()
	s := validSession(now)
	s.DelegatorPrincipal = ""
	err := ValidateSession(s, "", now, nil)
	if err == nil {
		t.Fatal("expected error for missing DelegatorPrincipal")
	}
}

func TestValidateSessionMissingDelegate(t *testing.T) {
	now := time.Now()
	s := validSession(now)
	s.DelegatePrincipal = ""
	err := ValidateSession(s, "", now, nil)
	if err == nil {
		t.Fatal("expected error for missing DelegatePrincipal")
	}
}

func TestValidateSessionEmptyNonce(t *testing.T) {
	now := time.Now()
	s := validSession(now)
	s.SessionNonce = ""
	err := ValidateSession(s, "", now, nil)
	if err == nil {
		t.Fatal("expected error for empty nonce")
	}
}

func TestValidateSessionNonceReplayDetected(t *testing.T) {
	now := time.Now()
	s := validSession(now)
	checker := func(nonce string) bool { return nonce == "nonce-1" }
	err := ValidateSession(s, "", now, checker)
	if err == nil {
		t.Fatal("expected nonce replay error")
	}
}

func TestValidateSessionNonceNotReplayed(t *testing.T) {
	now := time.Now()
	s := validSession(now)
	checker := func(string) bool { return false }
	err := ValidateSession(s, "", now, checker)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateSessionNilNonceChecker(t *testing.T) {
	now := time.Now()
	s := validSession(now)
	err := ValidateSession(s, "", now, nil)
	if err != nil {
		t.Fatalf("nil nonceChecker should skip check: %v", err)
	}
}

func TestValidateSessionVerifierRequired(t *testing.T) {
	now := time.Now()
	s := validSession(now)
	s.BindVerifier("my-secret")
	err := ValidateSession(s, "", now, nil)
	if err == nil {
		t.Fatal("expected error when verifier missing for bound session")
	}
}

func TestValidateSessionVerifierCorrect(t *testing.T) {
	now := time.Now()
	s := validSession(now)
	s.BindVerifier("correct-secret")
	err := ValidateSession(s, "correct-secret", now, nil)
	if err != nil {
		t.Fatalf("correct verifier should pass: %v", err)
	}
}

func TestValidateSessionVerifierIncorrect(t *testing.T) {
	now := time.Now()
	s := validSession(now)
	s.BindVerifier("right")
	err := ValidateSession(s, "wrong", now, nil)
	if err == nil {
		t.Fatal("expected verifier mismatch error")
	}
}

func TestValidateSessionMissingPolicyHash(t *testing.T) {
	now := time.Now()
	s := validSession(now)
	s.DelegationPolicyHash = ""
	err := ValidateSession(s, "", now, nil)
	if err == nil {
		t.Fatal("expected error for missing policy hash")
	}
}

func TestValidateSessionErrorCodeIsDelegationInvalid(t *testing.T) {
	err := ValidateSession(nil, "", time.Now(), nil)
	de, ok := err.(*DelegationError)
	if !ok {
		t.Fatalf("expected *DelegationError, got %T", err)
	}
	if de.Code != "DELEGATION_INVALID" {
		t.Fatalf("got code %s, want DELEGATION_INVALID", de.Code)
	}
}

// ── CapabilityGrant ──────────────────────────────────────────

func TestCapabilityGrantValidAdd(t *testing.T) {
	now := time.Now()
	s := validSession(now)
	err := s.AddCapability(CapabilityGrant{Resource: "tool-x", Actions: []string{"READ"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(s.Capabilities) != 1 {
		t.Fatalf("want 1 capability, got %d", len(s.Capabilities))
	}
}

func TestCapabilityGrantEmptyResource(t *testing.T) {
	now := time.Now()
	s := validSession(now)
	err := s.AddCapability(CapabilityGrant{Resource: "", Actions: []string{"READ"}})
	if err == nil {
		t.Fatal("expected error for empty resource")
	}
}

func TestCapabilityGrantEmptyActions(t *testing.T) {
	now := time.Now()
	s := validSession(now)
	err := s.AddCapability(CapabilityGrant{Resource: "tool", Actions: []string{}})
	if err == nil {
		t.Fatal("expected error for empty actions")
	}
}

func TestCapabilityGrantNilActions(t *testing.T) {
	now := time.Now()
	s := validSession(now)
	err := s.AddCapability(CapabilityGrant{Resource: "tool", Actions: nil})
	if err == nil {
		t.Fatal("expected error for nil actions")
	}
}

func TestCapabilityGrantMultipleActions(t *testing.T) {
	now := time.Now()
	s := validSession(now)
	_ = s.AddCapability(CapabilityGrant{Resource: "r1", Actions: []string{"READ", "WRITE", "DELETE"}})
	if !s.IsActionAllowed("r1", "WRITE") {
		t.Fatal("WRITE should be allowed on r1")
	}
}

func TestCapabilityGrantWithConditions(t *testing.T) {
	g := CapabilityGrant{
		Resource:   "db",
		Actions:    []string{"READ"},
		Conditions: []string{"size < 100"},
	}
	if len(g.Conditions) != 1 || g.Conditions[0] != "size < 100" {
		t.Fatal("conditions not stored correctly")
	}
}

func TestCapabilityGrantActionNotAllowedOnWrongResource(t *testing.T) {
	now := time.Now()
	s := validSession(now)
	_ = s.AddCapability(CapabilityGrant{Resource: "res-A", Actions: []string{"EXEC"}})
	if s.IsActionAllowed("res-B", "EXEC") {
		t.Fatal("action should not be allowed on a different resource")
	}
}

// ── Tool Scoping ─────────────────────────────────────────────

func TestToolAllowedDenyAllByDefault(t *testing.T) {
	now := time.Now()
	s := validSession(now)
	if s.IsToolAllowed("anything") {
		t.Fatal("deny-all session should not allow any tool")
	}
}

func TestToolAllowedAfterAdd(t *testing.T) {
	now := time.Now()
	s := validSession(now)
	s.AddAllowedTool("git_push")
	if !s.IsToolAllowed("git_push") {
		t.Fatal("git_push should be allowed after adding")
	}
}

func TestToolNotInAllowList(t *testing.T) {
	now := time.Now()
	s := validSession(now)
	s.AddAllowedTool("git_push")
	if s.IsToolAllowed("rm_rf") {
		t.Fatal("rm_rf should not be allowed")
	}
}

func TestEffectiveToolsIntersection(t *testing.T) {
	now := time.Now()
	s := validSession(now)
	s.AddAllowedTool("a")
	s.AddAllowedTool("b")
	result := s.EffectiveTools([]string{"b", "c"})
	if len(result) != 1 || result[0] != "b" {
		t.Fatalf("expected [b], got %v", result)
	}
}

func TestEffectiveToolsEmptyAllowed(t *testing.T) {
	now := time.Now()
	s := validSession(now)
	result := s.EffectiveTools([]string{"a", "b"})
	if result != nil {
		t.Fatalf("deny-all should return nil, got %v", result)
	}
}

func TestSetRiskCeiling(t *testing.T) {
	now := time.Now()
	s := validSession(now)
	s.SetRiskCeiling("HIGH")
	if s.RiskCeiling != "HIGH" {
		t.Fatalf("got %s, want HIGH", s.RiskCeiling)
	}
}

// ── BindVerifier ─────────────────────────────────────────────

func TestBindVerifierSetsHash(t *testing.T) {
	now := time.Now()
	s := validSession(now)
	s.BindVerifier("pkce-value")
	h := sha256.Sum256([]byte("pkce-value"))
	expected := hex.EncodeToString(h[:])
	if s.VerifierBinding != expected {
		t.Fatalf("verifier binding mismatch")
	}
}

// ── IsolationChecker ─────────────────────────────────────────

func TestIsolationFirstBindSucceeds(t *testing.T) {
	ic := NewIsolationChecker()
	err := ic.ValidateAgentIdentity("p1", "cred1", "sess1")
	if err != nil {
		t.Fatalf("first bind should succeed: %v", err)
	}
}

func TestIsolationIdempotentRebind(t *testing.T) {
	ic := NewIsolationChecker()
	_ = ic.ValidateAgentIdentity("p1", "cred1", "s1")
	err := ic.ValidateAgentIdentity("p1", "cred1", "s2")
	if err != nil {
		t.Fatalf("idempotent rebind failed: %v", err)
	}
}

func TestIsolationCrossPrincipalRejected(t *testing.T) {
	ic := NewIsolationChecker()
	_ = ic.ValidateAgentIdentity("p1", "cred1", "s1")
	err := ic.ValidateAgentIdentity("p2", "cred1", "s2")
	if err == nil {
		t.Fatal("cross-principal credential reuse should be rejected")
	}
}

func TestIsolationViolationErrorType(t *testing.T) {
	ic := NewIsolationChecker()
	_ = ic.ValidateAgentIdentity("p1", "cred1", "s1")
	err := ic.ValidateAgentIdentity("p2", "cred1", "s2")
	_, ok := err.(*IsolationViolationError)
	if !ok {
		t.Fatalf("expected *IsolationViolationError, got %T", err)
	}
}

func TestIsolationViolationErrorMessage(t *testing.T) {
	ic := NewIsolationChecker()
	_ = ic.ValidateAgentIdentity("owner", "cred", "s1")
	err := ic.ValidateAgentIdentity("intruder", "cred", "s2")
	msg := err.Error()
	if msg == "" {
		t.Fatal("error message should not be empty")
	}
}

func TestIsolationViolationRecordFields(t *testing.T) {
	fixed := time.Date(2026, 6, 1, 10, 0, 0, 0, time.UTC)
	ic := NewIsolationChecker().WithClock(staticClock(fixed))
	_ = ic.ValidateAgentIdentity("original", "c", "s1")
	_ = ic.ValidateAgentIdentity("imposter", "c", "s2")
	v := ic.Violations()
	if len(v) != 1 {
		t.Fatalf("want 1 violation, got %d", len(v))
	}
	if v[0].BoundPrincipal != "original" || v[0].AttemptingPrincipal != "imposter" {
		t.Fatal("violation record has wrong principals")
	}
	if !v[0].DetectedAt.Equal(fixed) {
		t.Fatalf("DetectedAt=%v, want %v", v[0].DetectedAt, fixed)
	}
}

func TestIsolationNoViolationsInitially(t *testing.T) {
	ic := NewIsolationChecker()
	if len(ic.Violations()) != 0 {
		t.Fatal("new checker should have no violations")
	}
}

func TestIsolationBindingCountMultipleCredentials(t *testing.T) {
	ic := NewIsolationChecker()
	_ = ic.ValidateAgentIdentity("a", "c1", "s")
	_ = ic.ValidateAgentIdentity("b", "c2", "s")
	_ = ic.ValidateAgentIdentity("c", "c3", "s")
	if ic.BindingCount() != 3 {
		t.Fatalf("want 3 bindings, got %d", ic.BindingCount())
	}
}

func TestIsolationConcurrentValidate(t *testing.T) {
	ic := NewIsolationChecker()
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			p := fmt.Sprintf("agent-%d", idx)
			c := fmt.Sprintf("cred-%d", idx)
			ic.ValidateAgentIdentity(p, c, "s")
		}(i)
	}
	wg.Wait()
	if ic.BindingCount() != 100 {
		t.Fatalf("want 100 bindings, got %d", ic.BindingCount())
	}
}

// ── InMemoryDelegationStore ──────────────────────────────────

func TestStoreAndLoadSession(t *testing.T) {
	store := NewInMemoryDelegationStore()
	now := time.Now()
	s := validSession(now)
	_ = store.Store(s)
	loaded, err := store.Load("s-valid")
	if err != nil || loaded == nil {
		t.Fatalf("load failed: err=%v, loaded=%v", err, loaded)
	}
	if loaded.SessionID != "s-valid" {
		t.Fatalf("wrong session ID: %s", loaded.SessionID)
	}
}

func TestLoadNonexistentReturnsNil(t *testing.T) {
	store := NewInMemoryDelegationStore()
	loaded, err := store.Load("does-not-exist")
	if err != nil || loaded != nil {
		t.Fatalf("expected (nil, nil), got (%v, %v)", loaded, err)
	}
}

func TestRevokeBlocksLoad(t *testing.T) {
	store := NewInMemoryDelegationStore()
	now := time.Now()
	s := validSession(now)
	_ = store.Store(s)
	_ = store.Revoke("s-valid")
	_, err := store.Load("s-valid")
	if err == nil {
		t.Fatal("expected error loading revoked session")
	}
}

func TestRevokeErrorType(t *testing.T) {
	store := NewInMemoryDelegationStore()
	now := time.Now()
	s := validSession(now)
	_ = store.Store(s)
	_ = store.Revoke("s-valid")
	_, err := store.Load("s-valid")
	de, ok := err.(*DelegationError)
	if !ok {
		t.Fatalf("expected *DelegationError, got %T", err)
	}
	if de.Code != "DELEGATION_INVALID" {
		t.Fatalf("got code %s, want DELEGATION_INVALID", de.Code)
	}
}

func TestNonceNotUsedInitially(t *testing.T) {
	store := NewInMemoryDelegationStore()
	if store.IsNonceUsed("fresh-nonce") {
		t.Fatal("fresh nonce should not be marked used")
	}
}

func TestMarkNonceUsed(t *testing.T) {
	store := NewInMemoryDelegationStore()
	store.MarkNonceUsed("n1")
	if !store.IsNonceUsed("n1") {
		t.Fatal("nonce should be marked used after MarkNonceUsed")
	}
}

func TestMarkNonceUsedIdempotent(t *testing.T) {
	store := NewInMemoryDelegationStore()
	store.MarkNonceUsed("n1")
	store.MarkNonceUsed("n1")
	if !store.IsNonceUsed("n1") {
		t.Fatal("nonce should still be used after double mark")
	}
}

func TestStoreMultipleSessions(t *testing.T) {
	store := NewInMemoryDelegationStore()
	now := time.Now()
	for i := 0; i < 5; i++ {
		s := NewDelegationSession(
			fmt.Sprintf("s-%d", i), "d", "g", fmt.Sprintf("n-%d", i),
			"p", "t", 0, now.Add(time.Hour), false, staticClock(now),
		)
		_ = store.Store(s)
	}
	for i := 0; i < 5; i++ {
		loaded, _ := store.Load(fmt.Sprintf("s-%d", i))
		if loaded == nil {
			t.Fatalf("session s-%d not found", i)
		}
	}
}

func TestStoreConcurrentAccess(t *testing.T) {
	store := NewInMemoryDelegationStore()
	now := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			s := NewDelegationSession(
				fmt.Sprintf("cs-%d", idx), "d", "g", fmt.Sprintf("cn-%d", idx),
				"p", "t", 0, now.Add(time.Hour), false, staticClock(now),
			)
			store.Store(s)
			store.Load(fmt.Sprintf("cs-%d", idx))
			store.IsNonceUsed(fmt.Sprintf("cn-%d", idx))
			store.MarkNonceUsed(fmt.Sprintf("cn-%d", idx))
		}(i)
	}
	wg.Wait()
}

func TestStoreRevokeNonexistentDoesNotPanic(t *testing.T) {
	store := NewInMemoryDelegationStore()
	err := store.Revoke("ghost-session")
	if err != nil {
		t.Fatalf("revoking nonexistent session should not error: %v", err)
	}
}

// ── DelegationError ──────────────────────────────────────────

func TestDelegationErrorFormat(t *testing.T) {
	e := &DelegationError{Code: "SOME_CODE", Message: "detail"}
	expected := "SOME_CODE: detail"
	if e.Error() != expected {
		t.Fatalf("got %q, want %q", e.Error(), expected)
	}
}

// ── AgentIdentity (types.go) ─────────────────────────────────

func TestAgentIdentityID(t *testing.T) {
	a := &AgentIdentity{AgentID: "agent-007", DelegatorID: "user-1"}
	if a.ID() != "agent-007" {
		t.Fatalf("got %s", a.ID())
	}
}

func TestAgentIdentityType(t *testing.T) {
	a := &AgentIdentity{AgentID: "a", DelegatorID: "u"}
	if a.Type() != PrincipalAgent {
		t.Fatalf("got %s, want AGENT", a.Type())
	}
}

func TestPrincipalTypeConstants(t *testing.T) {
	if PrincipalUser != "USER" || PrincipalAgent != "AGENT" || PrincipalService != "SERVICE" {
		t.Fatal("principal type constants have unexpected values")
	}
}
