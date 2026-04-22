package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func deepFixedClock() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }

// ── 1-6: Delegation session 6 validation failures ───────────────

func TestDeep_ValidateNilSession(t *testing.T) {
	err := ValidateSession(nil, "", time.Now(), nil)
	if err == nil {
		t.Fatal("nil session must fail")
	}
	de := err.(*DelegationError)
	if de.Code != "DELEGATION_INVALID" {
		t.Fatalf("want DELEGATION_INVALID got %s", de.Code)
	}
}

func TestDeep_ValidateMissingFields(t *testing.T) {
	s := &DelegationSession{SessionNonce: "n", DelegationPolicyHash: "h"}
	err := ValidateSession(s, "", time.Now(), nil)
	if err == nil {
		t.Fatal("missing identity fields must fail")
	}
}

func TestDeep_ValidateExpired(t *testing.T) {
	s := NewDelegationSession("s1", "d", "del", "n", "h", "tr", 0, time.Now().Add(-time.Hour), false, nil)
	err := ValidateSession(s, "", time.Now(), nil)
	if err == nil {
		t.Fatal("expired session must fail")
	}
}

func TestDeep_ValidateNonceReplay(t *testing.T) {
	s := NewDelegationSession("s1", "d", "del", "n1", "h", "tr", 0, time.Now().Add(time.Hour), false, nil)
	checker := func(nonce string) bool { return nonce == "n1" }
	err := ValidateSession(s, "", time.Now(), checker)
	if err == nil {
		t.Fatal("replayed nonce must fail")
	}
}

func TestDeep_ValidateVerifierMismatch(t *testing.T) {
	s := NewDelegationSession("s1", "d", "del", "n1", "h", "tr", 0, time.Now().Add(time.Hour), false, nil)
	s.BindVerifier("correct-verifier")
	err := ValidateSession(s, "wrong-verifier", time.Now(), func(string) bool { return false })
	if err == nil {
		t.Fatal("wrong verifier must fail")
	}
}

func TestDeep_ValidateMissingPolicyHash(t *testing.T) {
	s := NewDelegationSession("s1", "d", "del", "n1", "", "tr", 0, time.Now().Add(time.Hour), false, nil)
	err := ValidateSession(s, "", time.Now(), func(string) bool { return false })
	if err == nil {
		t.Fatal("empty policy hash must fail")
	}
}

// ── 7-11: Concurrent nonce checks (50) ──────────────────────────

func TestDeep_ConcurrentNonceStore(t *testing.T) {
	store := NewInMemoryDelegationStore()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			nonce := fmt.Sprintf("nonce-%d", i)
			store.MarkNonceUsed(nonce)
		}(i)
	}
	wg.Wait()
	for i := 0; i < 50; i++ {
		if !store.IsNonceUsed(fmt.Sprintf("nonce-%d", i)) {
			t.Fatalf("nonce-%d should be marked used", i)
		}
	}
}

func TestDeep_ConcurrentNonceCheck(t *testing.T) {
	store := NewInMemoryDelegationStore()
	store.MarkNonceUsed("dup")
	var wg sync.WaitGroup
	var hits atomic.Int32
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if store.IsNonceUsed("dup") {
				hits.Add(1)
			}
		}()
	}
	wg.Wait()
	if hits.Load() != 50 {
		t.Fatalf("all 50 checks should see nonce, got %d", hits.Load())
	}
}

func TestDeep_ConcurrentStoreAndLoad(t *testing.T) {
	store := NewInMemoryDelegationStore()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s := NewDelegationSession(fmt.Sprintf("s%d", i), "d", "del", "n", "h", "tr", 0, time.Now().Add(time.Hour), false, nil)
			store.Store(s)
			store.Load(fmt.Sprintf("s%d", i))
		}(i)
	}
	wg.Wait()
}

func TestDeep_ConcurrentRevoke(t *testing.T) {
	store := NewInMemoryDelegationStore()
	s := NewDelegationSession("rev", "d", "del", "n", "h", "tr", 0, time.Now().Add(time.Hour), false, nil)
	store.Store(s)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			store.Revoke("rev")
		}()
	}
	wg.Wait()
	_, err := store.Load("rev")
	if err == nil {
		t.Fatal("revoked session load must error")
	}
}

func TestDeep_NonceUnused(t *testing.T) {
	store := NewInMemoryDelegationStore()
	if store.IsNonceUsed("fresh") {
		t.Error("fresh nonce should not be used")
	}
}

// ── 12-16: Capability intersection / scope ──────────────────────

func TestDeep_EffectiveToolsIntersection(t *testing.T) {
	s := NewDelegationSession("s1", "d", "del", "n", "h", "tr", 0, time.Now().Add(time.Hour), false, nil)
	s.AddAllowedTool("read")
	s.AddAllowedTool("write")
	result := s.EffectiveTools([]string{"read", "delete", "write", "admin"})
	if len(result) != 2 {
		t.Fatalf("want 2 effective tools got %d", len(result))
	}
}

func TestDeep_EffectiveToolsEmpty(t *testing.T) {
	s := NewDelegationSession("s1", "d", "del", "n", "h", "tr", 0, time.Now().Add(time.Hour), false, nil)
	result := s.EffectiveTools([]string{"read"})
	if result != nil {
		t.Error("no allowed tools should return nil")
	}
}

func TestDeep_IsActionAllowedMultiCap(t *testing.T) {
	s := NewDelegationSession("s1", "d", "del", "n", "h", "tr", 0, time.Now().Add(time.Hour), false, nil)
	s.AddCapability(CapabilityGrant{Resource: "file", Actions: []string{"READ", "WRITE"}})
	s.AddCapability(CapabilityGrant{Resource: "db", Actions: []string{"QUERY"}})
	if !s.IsActionAllowed("file", "READ") {
		t.Error("file/READ should be allowed")
	}
	if s.IsActionAllowed("file", "DELETE") {
		t.Error("file/DELETE not granted")
	}
	if !s.IsActionAllowed("db", "QUERY") {
		t.Error("db/QUERY should be allowed")
	}
}

func TestDeep_AddCapabilityEmptyResource(t *testing.T) {
	s := NewDelegationSession("s1", "d", "del", "n", "h", "tr", 0, time.Now().Add(time.Hour), false, nil)
	err := s.AddCapability(CapabilityGrant{Resource: "", Actions: []string{"X"}})
	if err == nil {
		t.Error("empty resource must error")
	}
}

func TestDeep_AddCapabilityNoActions(t *testing.T) {
	s := NewDelegationSession("s1", "d", "del", "n", "h", "tr", 0, time.Now().Add(time.Hour), false, nil)
	err := s.AddCapability(CapabilityGrant{Resource: "x"})
	if err == nil {
		t.Error("no actions must error")
	}
}

// ── 17-19: PKCE with known SHA-256 vectors ──────────────────────

func TestDeep_PKCEKnownVector(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	h := sha256.Sum256([]byte(verifier))
	expected := hex.EncodeToString(h[:])

	s := NewDelegationSession("s1", "d", "del", "n", "h", "tr", 0, time.Now().Add(time.Hour), false, nil)
	s.BindVerifier(verifier)
	if s.VerifierBinding != expected {
		t.Fatalf("binding %s != expected %s", s.VerifierBinding, expected)
	}
}

func TestDeep_PKCEEmptyVerifier(t *testing.T) {
	s := NewDelegationSession("s1", "d", "del", "n", "h", "tr", 0, time.Now().Add(time.Hour), false, nil)
	s.BindVerifier("secret")
	err := ValidateSession(s, "", time.Now(), func(string) bool { return false })
	if err == nil {
		t.Error("empty verifier for bound session must fail")
	}
}

func TestDeep_PKCECorrectVerifier(t *testing.T) {
	s := NewDelegationSession("s1", "d", "del", "n1", "h", "tr", 0, time.Now().Add(time.Hour), false, nil)
	s.BindVerifier("my-secret")
	err := ValidateSession(s, "my-secret", time.Now(), func(string) bool { return false })
	if err != nil {
		t.Fatalf("correct verifier should pass: %v", err)
	}
}

// ── 20-23: FileStore with concurrent writes ─────────────────────

func TestDeep_FileStoreConcurrentWrites(t *testing.T) {
	dir := t.TempDir()
	fs, err := NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s := NewDelegationSession(fmt.Sprintf("fs-%d", i), "d", "del", "n", "h", "tr", 0, time.Now().Add(time.Hour), false, nil)
			fs.Store(s)
		}(i)
	}
	wg.Wait()
	ids, err := fs.ListSessions()
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 100 {
		t.Fatalf("want 100 sessions got %d", len(ids))
	}
}

func TestDeep_FileStoreLoadMissing(t *testing.T) {
	dir := t.TempDir()
	fs, _ := NewFileStore(dir)
	s, err := fs.Load("nonexistent")
	if err != nil || s != nil {
		t.Fatalf("missing session should return nil, nil; got %v, %v", s, err)
	}
}

func TestDeep_FileStoreRevokeAndLoad(t *testing.T) {
	dir := t.TempDir()
	fs, _ := NewFileStore(dir)
	s := NewDelegationSession("r1", "d", "del", "n", "h", "tr", 0, time.Now().Add(time.Hour), false, nil)
	fs.Store(s)
	fs.Revoke("r1")
	_, err := fs.Load("r1")
	if err == nil {
		t.Error("revoked session load must return error")
	}
}

func TestDeep_FileStoreNonce(t *testing.T) {
	dir := t.TempDir()
	fs, _ := NewFileStore(dir)
	if fs.IsNonceUsed("abc") {
		t.Error("unused nonce should not be flagged")
	}
	fs.MarkNonceUsed("abc")
	if !fs.IsNonceUsed("abc") {
		t.Error("marked nonce should be flagged")
	}
}

// ── 24-25: Edge cases ───────────────────────────────────────────

func TestDeep_SessionClockOverride(t *testing.T) {
	s := NewDelegationSession("s1", "d", "del", "n", "h", "tr", 0, time.Now().Add(time.Hour), false, deepFixedClock)
	if !s.CreatedAt.Equal(deepFixedClock()) {
		t.Fatalf("clock override should set CreatedAt to fixed time")
	}
}

func TestDeep_FileStoreCreatesDirOnInit(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sub", "deep")
	_, err := NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		t.Fatal("NewFileStore must create nested directories")
	}
}
