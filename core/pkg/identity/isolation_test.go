package identity

import (
	"sync"
	"testing"
	"time"
)

func TestIsolationChecker_FirstBindingAllowed(t *testing.T) {
	ic := NewIsolationChecker()
	err := ic.ValidateAgentIdentity("agent-1", "cred-hash-aaa", "session-1")
	if err != nil {
		t.Errorf("first binding should succeed: %v", err)
	}
	if ic.BindingCount() != 1 {
		t.Errorf("binding count = %d, want 1", ic.BindingCount())
	}
}

func TestIsolationChecker_SamePrincipalIdempotent(t *testing.T) {
	ic := NewIsolationChecker()
	ic.ValidateAgentIdentity("agent-1", "cred-hash-aaa", "session-1")
	err := ic.ValidateAgentIdentity("agent-1", "cred-hash-aaa", "session-2")
	if err != nil {
		t.Errorf("same principal re-binding should be idempotent: %v", err)
	}
	if ic.BindingCount() != 1 {
		t.Errorf("binding count = %d, want 1 (idempotent)", ic.BindingCount())
	}
}

func TestIsolationChecker_DifferentPrincipalReuse(t *testing.T) {
	ts := time.Date(2026, 3, 7, 12, 0, 0, 0, time.UTC)
	ic := NewIsolationChecker().WithClock(func() time.Time { return ts })

	ic.ValidateAgentIdentity("agent-1", "shared-cred", "session-1")
	err := ic.ValidateAgentIdentity("agent-2", "shared-cred", "session-2")
	if err == nil {
		t.Fatal("different principal reusing credential should be rejected")
	}

	violation, ok := err.(*IsolationViolationError)
	if !ok {
		t.Fatalf("error should be *IsolationViolationError, got %T", err)
	}
	if violation.BoundPrincipal != "agent-1" {
		t.Errorf("bound principal = %s, want agent-1", violation.BoundPrincipal)
	}
	if violation.AttemptingPrincipal != "agent-2" {
		t.Errorf("attempting principal = %s, want agent-2", violation.AttemptingPrincipal)
	}
}

func TestIsolationChecker_MultipleDifferentCredentials(t *testing.T) {
	ic := NewIsolationChecker()
	ic.ValidateAgentIdentity("agent-1", "cred-1", "s1")
	ic.ValidateAgentIdentity("agent-2", "cred-2", "s2")
	ic.ValidateAgentIdentity("agent-3", "cred-3", "s3")

	if ic.BindingCount() != 3 {
		t.Errorf("binding count = %d, want 3", ic.BindingCount())
	}

	// Each agent using their own cred should be fine
	if err := ic.ValidateAgentIdentity("agent-1", "cred-1", "s4"); err != nil {
		t.Errorf("own credential should work: %v", err)
	}
	// But cross-use should fail
	if err := ic.ValidateAgentIdentity("agent-1", "cred-2", "s5"); err == nil {
		t.Error("agent-1 using cred-2 should be rejected")
	}
}

func TestIsolationChecker_ViolationHistory(t *testing.T) {
	ic := NewIsolationChecker()
	ic.ValidateAgentIdentity("agent-1", "cred-1", "s1")
	ic.ValidateAgentIdentity("agent-2", "cred-1", "s2") // violation 1
	ic.ValidateAgentIdentity("agent-3", "cred-1", "s3") // violation 2

	violations := ic.Violations()
	if len(violations) != 2 {
		t.Fatalf("want 2 violations, got %d", len(violations))
	}
	if violations[0].AttemptingPrincipal != "agent-2" {
		t.Errorf("violation[0] attempting = %s, want agent-2", violations[0].AttemptingPrincipal)
	}
	if violations[1].AttemptingPrincipal != "agent-3" {
		t.Errorf("violation[1] attempting = %s, want agent-3", violations[1].AttemptingPrincipal)
	}
}

func TestIsolationChecker_ConcurrentAccess(t *testing.T) {
	ic := NewIsolationChecker()
	var wg sync.WaitGroup

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			principal := "agent-unique"
			if idx%2 == 0 {
				principal = "agent-even"
			}
			// Mix of unique and shared credentials
			ic.ValidateAgentIdentity(principal, "shared-cred", "session")
		}(i)
	}
	wg.Wait()
	// Should not panic or deadlock
}
