package identity

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// ────────────────────────────────────────────────────────────────────────
// 100 concurrent delegation sessions
// ────────────────────────────────────────────────────────────────────────

func TestStress_ConcurrentDelegationSessionCreation(t *testing.T) {
	store := NewInMemoryDelegationStore()
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			s := NewDelegationSession(fmt.Sprintf("sess-%d", n), "delegator", "delegate", fmt.Sprintf("nonce-%d", n), "hash", "trust", 0, time.Now().Add(time.Hour), true, nil)
			if err := store.Store(s); err != nil {
				t.Errorf("store session %d: %v", n, err)
			}
		}(i)
	}
	wg.Wait()
}

func TestStress_ConcurrentDelegationSessionLoad(t *testing.T) {
	store := NewInMemoryDelegationStore()
	for i := 0; i < 100; i++ {
		s := NewDelegationSession(fmt.Sprintf("sess-%d", i), "d", "d2", fmt.Sprintf("n-%d", i), "h", "t", 0, time.Now().Add(time.Hour), false, nil)
		_ = store.Store(s)
	}
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			loaded, err := store.Load(fmt.Sprintf("sess-%d", n))
			if err != nil || loaded == nil {
				t.Errorf("load session %d failed", n)
			}
		}(i)
	}
	wg.Wait()
}

func TestStress_ConcurrentDelegationStoreAndRevoke(t *testing.T) {
	store := NewInMemoryDelegationStore()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			s := NewDelegationSession(fmt.Sprintf("s-%d", n), "d", "d2", fmt.Sprintf("n-%d", n), "h", "t", 0, time.Now().Add(time.Hour), false, nil)
			_ = store.Store(s)
			_ = store.Revoke(fmt.Sprintf("s-%d", n))
		}(i)
	}
	wg.Wait()
}

func TestStress_ConcurrentDelegationSessionWithCapabilities(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			s := NewDelegationSession(fmt.Sprintf("s-%d", n), "d", "d2", "nonce", "h", "t", 0, time.Now().Add(time.Hour), false, nil)
			for j := 0; j < 10; j++ {
				_ = s.AddCapability(CapabilityGrant{Resource: fmt.Sprintf("res-%d", j), Actions: []string{"EXECUTE_TOOL"}})
			}
			if len(s.Capabilities) != 10 {
				t.Errorf("expected 10 caps, got %d", len(s.Capabilities))
			}
		}(i)
	}
	wg.Wait()
}

// ────────────────────────────────────────────────────────────────────────
// 200 nonce checks
// ────────────────────────────────────────────────────────────────────────

func TestStress_200NonceMarksSequential(t *testing.T) {
	store := NewInMemoryDelegationStore()
	for i := 0; i < 200; i++ {
		nonce := fmt.Sprintf("nonce-%d", i)
		store.MarkNonceUsed(nonce)
		if !store.IsNonceUsed(nonce) {
			t.Fatalf("nonce %d not found after marking", i)
		}
	}
}

func TestStress_200NonceConcurrentMarks(t *testing.T) {
	store := NewInMemoryDelegationStore()
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			store.MarkNonceUsed(fmt.Sprintf("n-%d", n))
		}(i)
	}
	wg.Wait()
	for i := 0; i < 200; i++ {
		if !store.IsNonceUsed(fmt.Sprintf("n-%d", i)) {
			t.Errorf("nonce %d missing", i)
		}
	}
}

func TestStress_NonceUnusedReturnsFalse(t *testing.T) {
	store := NewInMemoryDelegationStore()
	for i := 0; i < 200; i++ {
		if store.IsNonceUsed(fmt.Sprintf("unused-%d", i)) {
			t.Fatalf("unused nonce %d reported as used", i)
		}
	}
}

func TestStress_NonceDuplicateMarkIdempotent(t *testing.T) {
	store := NewInMemoryDelegationStore()
	for i := 0; i < 200; i++ {
		store.MarkNonceUsed("same-nonce")
	}
	if !store.IsNonceUsed("same-nonce") {
		t.Fatal("nonce not found after 200 marks")
	}
}

// ────────────────────────────────────────────────────────────────────────
// Isolation checker with 50 principals
// ────────────────────────────────────────────────────────────────────────

func TestStress_IsolationChecker50UniquePrincipals(t *testing.T) {
	ic := NewIsolationChecker()
	for i := 0; i < 50; i++ {
		err := ic.ValidateAgentIdentity(fmt.Sprintf("agent-%d", i), fmt.Sprintf("cred-%d", i), "sess-1")
		if err != nil {
			t.Fatalf("unexpected error for agent %d: %v", i, err)
		}
	}
	if ic.BindingCount() != 50 {
		t.Fatalf("expected 50 bindings, got %d", ic.BindingCount())
	}
}

func TestStress_IsolationCheckerIdempotentRebind(t *testing.T) {
	ic := NewIsolationChecker()
	for i := 0; i < 50; i++ {
		_ = ic.ValidateAgentIdentity("same-agent", "same-cred", fmt.Sprintf("sess-%d", i))
	}
	if ic.BindingCount() != 1 {
		t.Fatalf("expected 1 binding, got %d", ic.BindingCount())
	}
}

func TestStress_IsolationCheckerViolationDetection(t *testing.T) {
	ic := NewIsolationChecker()
	_ = ic.ValidateAgentIdentity("agent-0", "shared-cred", "sess-0")
	for i := 1; i < 50; i++ {
		err := ic.ValidateAgentIdentity(fmt.Sprintf("agent-%d", i), "shared-cred", fmt.Sprintf("sess-%d", i))
		if err == nil {
			t.Fatalf("expected violation for agent %d", i)
		}
	}
	if len(ic.Violations()) != 49 {
		t.Fatalf("expected 49 violations, got %d", len(ic.Violations()))
	}
}

func TestStress_IsolationCheckerConcurrentBindings(t *testing.T) {
	ic := NewIsolationChecker()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			_ = ic.ValidateAgentIdentity(fmt.Sprintf("a-%d", n), fmt.Sprintf("c-%d", n), "s")
		}(i)
	}
	wg.Wait()
	if ic.BindingCount() != 50 {
		t.Fatalf("expected 50 bindings, got %d", ic.BindingCount())
	}
}

func TestStress_IsolationViolationRecordHasPrincipalInfo(t *testing.T) {
	ic := NewIsolationChecker()
	_ = ic.ValidateAgentIdentity("original", "cred-x", "s1")
	_ = ic.ValidateAgentIdentity("imposter", "cred-x", "s2")
	v := ic.Violations()
	if len(v) != 1 || v[0].BoundPrincipal != "original" || v[0].AttemptingPrincipal != "imposter" {
		t.Fatal("violation record mismatch")
	}
}

// ────────────────────────────────────────────────────────────────────────
// File store with 100 sessions
// ────────────────────────────────────────────────────────────────────────

func TestStress_FileStore100Sessions(t *testing.T) {
	dir := t.TempDir()
	fs, err := NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		s := NewDelegationSession(fmt.Sprintf("fs-%d", i), "d", "d2", fmt.Sprintf("n-%d", i), "h", "t", 0, time.Now().Add(time.Hour), false, nil)
		if err := fs.Store(s); err != nil {
			t.Fatalf("store %d: %v", i, err)
		}
	}
	ids, err := fs.ListSessions()
	if err != nil || len(ids) != 100 {
		t.Fatalf("expected 100 sessions, got %d (err: %v)", len(ids), err)
	}
}

func TestStress_FileStoreLoadAfterStore(t *testing.T) {
	dir := t.TempDir()
	fs, _ := NewFileStore(dir)
	for i := 0; i < 100; i++ {
		s := NewDelegationSession(fmt.Sprintf("fs-%d", i), "d", "d2", fmt.Sprintf("n-%d", i), "h", "t", 0, time.Now().Add(time.Hour), false, nil)
		_ = fs.Store(s)
	}
	for i := 0; i < 100; i++ {
		loaded, err := fs.Load(fmt.Sprintf("fs-%d", i))
		if err != nil || loaded == nil {
			t.Fatalf("load %d: err=%v loaded=%v", i, err, loaded)
		}
	}
}

func TestStress_FileStoreRevokeAndLoad(t *testing.T) {
	dir := t.TempDir()
	fs, _ := NewFileStore(dir)
	s := NewDelegationSession("rev-1", "d", "d2", "n", "h", "t", 0, time.Now().Add(time.Hour), false, nil)
	_ = fs.Store(s)
	_ = fs.Revoke("rev-1")
	_, err := fs.Load("rev-1")
	if err == nil {
		t.Fatal("expected error loading revoked session")
	}
}

func TestStress_FileStoreNonceTracking(t *testing.T) {
	dir := t.TempDir()
	fs, _ := NewFileStore(dir)
	for i := 0; i < 100; i++ {
		fs.MarkNonceUsed(fmt.Sprintf("fn-%d", i))
	}
	for i := 0; i < 100; i++ {
		if !fs.IsNonceUsed(fmt.Sprintf("fn-%d", i)) {
			t.Fatalf("nonce %d not found in file store", i)
		}
	}
}

func TestStress_FileStoreLoadNonExistent(t *testing.T) {
	dir := t.TempDir()
	fs, _ := NewFileStore(dir)
	loaded, err := fs.Load("nonexistent")
	if err != nil || loaded != nil {
		t.Fatalf("expected nil, got err=%v loaded=%v", err, loaded)
	}
}

func TestStress_FileStoreDirectoryPermissions(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "nested", "deep")
	fs, err := NewFileStore(sub)
	if err != nil {
		t.Fatalf("failed to create nested store: %v", err)
	}
	s := NewDelegationSession("perm-1", "d", "d2", "n", "h", "t", 0, time.Now().Add(time.Hour), false, nil)
	if err := fs.Store(s); err != nil {
		t.Fatalf("store in nested dir: %v", err)
	}
}

// ────────────────────────────────────────────────────────────────────────
// Validation error paths
// ────────────────────────────────────────────────────────────────────────

func TestStress_ValidateSessionNil(t *testing.T) {
	err := ValidateSession(nil, "", time.Now(), nil)
	if err == nil {
		t.Fatal("expected error for nil session")
	}
}

func TestStress_ValidateSessionMissingSessionID(t *testing.T) {
	s := &DelegationSession{DelegatorPrincipal: "d", DelegatePrincipal: "d2"}
	err := ValidateSession(s, "", time.Now(), nil)
	if err == nil {
		t.Fatal("expected error for missing session ID")
	}
}

func TestStress_ValidateSessionMissingDelegator(t *testing.T) {
	s := &DelegationSession{SessionID: "s1", DelegatePrincipal: "d2"}
	err := ValidateSession(s, "", time.Now(), nil)
	if err == nil {
		t.Fatal("expected error for missing delegator")
	}
}

func TestStress_ValidateSessionMissingDelegate(t *testing.T) {
	s := &DelegationSession{SessionID: "s1", DelegatorPrincipal: "d"}
	err := ValidateSession(s, "", time.Now(), nil)
	if err == nil {
		t.Fatal("expected error for missing delegate")
	}
}

func TestStress_ValidateSessionExpired(t *testing.T) {
	s := NewDelegationSession("s1", "d", "d2", "n", "h", "t", 0, time.Now().Add(-time.Hour), false, nil)
	s.DelegationPolicyHash = "hash"
	err := ValidateSession(s, "", time.Now(), nil)
	if err == nil {
		t.Fatal("expected expiry error")
	}
}

func TestStress_ValidateSessionEmptyNonce(t *testing.T) {
	s := NewDelegationSession("s1", "d", "d2", "", "h", "t", 0, time.Now().Add(time.Hour), false, nil)
	s.DelegationPolicyHash = "hash"
	err := ValidateSession(s, "", time.Now(), nil)
	if err == nil {
		t.Fatal("expected error for empty nonce")
	}
}

func TestStress_ValidateSessionNonceReplay(t *testing.T) {
	s := NewDelegationSession("s1", "d", "d2", "nonce", "h", "t", 0, time.Now().Add(time.Hour), false, nil)
	s.DelegationPolicyHash = "hash"
	err := ValidateSession(s, "", time.Now(), func(n string) bool { return true })
	if err == nil {
		t.Fatal("expected nonce replay error")
	}
}

func TestStress_ValidateSessionVerifierRequired(t *testing.T) {
	s := NewDelegationSession("s1", "d", "d2", "nonce", "h", "t", 0, time.Now().Add(time.Hour), false, nil)
	s.DelegationPolicyHash = "hash"
	s.BindVerifier("secret")
	err := ValidateSession(s, "", time.Now(), nil)
	if err == nil {
		t.Fatal("expected verifier required error")
	}
}

func TestStress_ValidateSessionVerifierMismatch(t *testing.T) {
	s := NewDelegationSession("s1", "d", "d2", "nonce", "h", "t", 0, time.Now().Add(time.Hour), false, nil)
	s.DelegationPolicyHash = "hash"
	s.BindVerifier("secret")
	err := ValidateSession(s, "wrong-secret", time.Now(), nil)
	if err == nil {
		t.Fatal("expected verifier mismatch error")
	}
}

func TestStress_ValidateSessionMissingPolicyHash(t *testing.T) {
	s := NewDelegationSession("s1", "d", "d2", "nonce", "", "t", 0, time.Now().Add(time.Hour), false, nil)
	err := ValidateSession(s, "", time.Now(), nil)
	if err == nil {
		t.Fatal("expected error for missing policy hash")
	}
}

func TestStress_ValidateSessionValid(t *testing.T) {
	s := NewDelegationSession("s1", "d", "d2", "nonce", "h", "t", 0, time.Now().Add(time.Hour), true, nil)
	err := ValidateSession(s, "", time.Now(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestStress_ValidateSessionVerifierCorrect(t *testing.T) {
	s := NewDelegationSession("s1", "d", "d2", "nonce", "h", "t", 0, time.Now().Add(time.Hour), true, nil)
	s.BindVerifier("correct-secret")
	err := ValidateSession(s, "correct-secret", time.Now(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestStress_AddCapabilityEmptyResource(t *testing.T) {
	s := NewDelegationSession("s1", "d", "d2", "n", "h", "t", 0, time.Now().Add(time.Hour), false, nil)
	err := s.AddCapability(CapabilityGrant{Resource: "", Actions: []string{"READ"}})
	if err == nil {
		t.Fatal("expected error for empty resource")
	}
}

func TestStress_AddCapabilityEmptyActions(t *testing.T) {
	s := NewDelegationSession("s1", "d", "d2", "n", "h", "t", 0, time.Now().Add(time.Hour), false, nil)
	err := s.AddCapability(CapabilityGrant{Resource: "res", Actions: []string{}})
	if err == nil {
		t.Fatal("expected error for empty actions")
	}
}

func TestStress_IsToolAllowedDenyAll(t *testing.T) {
	s := NewDelegationSession("s1", "d", "d2", "n", "h", "t", 0, time.Now().Add(time.Hour), false, nil)
	if s.IsToolAllowed("anything") {
		t.Fatal("expected deny-all for empty AllowedTools")
	}
}

func TestStress_EffectiveToolsIntersection(t *testing.T) {
	s := NewDelegationSession("s1", "d", "d2", "n", "h", "t", 0, time.Now().Add(time.Hour), false, nil)
	s.AddAllowedTool("tool-a")
	s.AddAllowedTool("tool-b")
	eff := s.EffectiveTools([]string{"tool-a", "tool-c"})
	if len(eff) != 1 || eff[0] != "tool-a" {
		t.Fatalf("expected [tool-a], got %v", eff)
	}
}

func TestStress_IsActionAllowedTrue(t *testing.T) {
	s := NewDelegationSession("s1", "d", "d2", "n", "h", "t", 0, time.Now().Add(time.Hour), false, nil)
	_ = s.AddCapability(CapabilityGrant{Resource: "file", Actions: []string{"READ", "WRITE"}})
	if !s.IsActionAllowed("file", "READ") {
		t.Fatal("expected READ allowed")
	}
}

func TestStress_IsActionAllowedWrongResource(t *testing.T) {
	s := NewDelegationSession("s1", "d", "d2", "n", "h", "t", 0, time.Now().Add(time.Hour), false, nil)
	_ = s.AddCapability(CapabilityGrant{Resource: "file", Actions: []string{"READ"}})
	if s.IsActionAllowed("database", "READ") {
		t.Fatal("expected false for wrong resource")
	}
}

func TestStress_DelegationErrorString(t *testing.T) {
	err := &DelegationError{Code: "TEST_CODE", Message: "test message"}
	if err.Error() != "TEST_CODE: test message" {
		t.Fatalf("unexpected error string: %s", err.Error())
	}
}

func TestStress_InMemoryStoreLoadReturnsNilForMissing(t *testing.T) {
	store := NewInMemoryDelegationStore()
	s, err := store.Load("missing")
	if err != nil || s != nil {
		t.Fatal("expected nil for missing session")
	}
}

func TestStress_InMemoryStoreRevokedSessionReturnsError(t *testing.T) {
	store := NewInMemoryDelegationStore()
	s := NewDelegationSession("rev", "d", "d2", "n", "h", "t", 0, time.Now().Add(time.Hour), false, nil)
	_ = store.Store(s)
	_ = store.Revoke("rev")
	_, err := store.Load("rev")
	if err == nil {
		t.Fatal("expected error for revoked session")
	}
}

func TestStress_FileStoreInvalidDir(t *testing.T) {
	_, err := NewFileStore(string([]byte{0}))
	if err == nil {
		_ = os.Remove(string([]byte{0}))
		// On some platforms the null byte is invalid, on others it might succeed.
		// We just check the function doesn't panic.
	}
}
