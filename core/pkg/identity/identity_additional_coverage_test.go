package identity

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// ── FileStore Persistence ───────────────────────────────────

func TestExtFileStore_StoreAndLoad(t *testing.T) {
	dir := t.TempDir()
	fs, err := NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	s := validSession(now)
	_ = fs.Store(s)
	loaded, err := fs.Load("s-valid")
	if err != nil || loaded == nil || loaded.SessionID != "s-valid" {
		t.Fatalf("FileStore round-trip failed: err=%v loaded=%v", err, loaded)
	}
}

func TestExtFileStore_LoadNonexistentReturnsNil(t *testing.T) {
	dir := t.TempDir()
	fs, _ := NewFileStore(dir)
	loaded, err := fs.Load("ghost")
	if err != nil || loaded != nil {
		t.Fatalf("expected (nil, nil), got (%v, %v)", loaded, err)
	}
}

func TestExtFileStore_RevokeBlocksLoad(t *testing.T) {
	dir := t.TempDir()
	fs, _ := NewFileStore(dir)
	now := time.Now()
	s := validSession(now)
	_ = fs.Store(s)
	_ = fs.Revoke("s-valid")
	_, err := fs.Load("s-valid")
	if err == nil {
		t.Fatal("loading revoked session should error")
	}
}

func TestExtFileStore_NonceTracking(t *testing.T) {
	dir := t.TempDir()
	fs, _ := NewFileStore(dir)
	if fs.IsNonceUsed("n1") {
		t.Fatal("fresh nonce should not be used")
	}
	fs.MarkNonceUsed("n1")
	if !fs.IsNonceUsed("n1") {
		t.Fatal("nonce should be marked used")
	}
}

func TestExtFileStore_ListSessions(t *testing.T) {
	dir := t.TempDir()
	fs, _ := NewFileStore(dir)
	now := time.Now()
	for i := 0; i < 3; i++ {
		s := NewDelegationSession(fmt.Sprintf("ls-%d", i), "d", "g", fmt.Sprintf("n%d", i), "p", "t", 0, now.Add(time.Hour), false, staticClock(now))
		_ = fs.Store(s)
	}
	ids, err := fs.ListSessions()
	if err != nil || len(ids) != 3 {
		t.Fatalf("expected 3 sessions, got %d (err=%v)", len(ids), err)
	}
}

func TestExtFileStore_DirectoryCreatedIfMissing(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sub", "nested")
	fs, err := NewFileStore(dir)
	if err != nil || fs == nil {
		t.Fatalf("NewFileStore should create nested dirs: %v", err)
	}
	info, _ := os.Stat(dir)
	if info == nil || !info.IsDir() {
		t.Fatal("directory should exist")
	}
}

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

func TestAgentIdentity_ImplementsPrincipal(t *testing.T) {
	var p Principal = &AgentIdentity{AgentID: "test"}
	if p.ID() != "test" || p.Type() != PrincipalAgent {
		t.Fatal("AgentIdentity should satisfy Principal interface")
	}
}

// ── Device Identity ─────────────────────────────────────────

func TestDeviceIdentity_NewSetsDefaults(t *testing.T) {
	d := NewDeviceIdentity("d1", "t1", "Robot Arm", DeviceClassRobot, "owner1", []string{"move"})
	if d.TrustLevel != DeviceTrustUnverified {
		t.Errorf("expected UNVERIFIED, got %s", d.TrustLevel)
	}
	if d.ContentHash == "" {
		t.Error("content hash should be computed")
	}
}

func TestDeviceIdentity_AttestRaisesLevel(t *testing.T) {
	d := NewDeviceIdentity("d1", "t1", "Sensor", DeviceClassSensor, "o1", nil)
	d.Attest("sha256:firmware")
	if d.TrustLevel != DeviceTrustAttested {
		t.Errorf("expected ATTESTED, got %s", d.TrustLevel)
	}
}

func TestDeviceIdentity_ValidateMissingID(t *testing.T) {
	d := &DeviceIdentity{TenantID: "t", Class: DeviceClassSensor, OwnerID: "o"}
	if d.Validate() == nil {
		t.Error("missing ID should fail validation")
	}
}

func TestDeviceIdentity_ValidateSuccess(t *testing.T) {
	d := NewDeviceIdentity("d1", "t1", "G", DeviceClassGateway, "o1", nil)
	if err := d.Validate(); err != nil {
		t.Fatalf("valid device should pass: %v", err)
	}
}

// ── Concurrent Store Access ─────────────────────────────────

func TestExtFileStore_ConcurrentStoreAndLoad(t *testing.T) {
	dir := t.TempDir()
	fs, _ := NewFileStore(dir)
	now := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			s := NewDelegationSession(fmt.Sprintf("c-%d", idx), "d", "g", fmt.Sprintf("n%d", idx), "p", "t", 0, now.Add(time.Hour), false, staticClock(now))
			_ = fs.Store(s)
			_, _ = fs.Load(fmt.Sprintf("c-%d", idx))
		}(i)
	}
	wg.Wait()
}

// ── InMemoryKeySet ──────────────────────────────────────────

func TestInMemoryKeySet_RotateChangesKID(t *testing.T) {
	ks, err := NewInMemoryKeySet()
	if err != nil {
		t.Fatal(err)
	}
	kid1 := ks.currentKID
	_ = ks.Rotate()
	if ks.currentKID == kid1 {
		t.Error("Rotate should change currentKID")
	}
}
