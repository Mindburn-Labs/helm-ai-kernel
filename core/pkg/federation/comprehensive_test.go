package federation

import (
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/crypto"
)

var fixedTime = time.Date(2026, 4, 12, 0, 0, 0, 0, time.UTC)

func fixedClock() time.Time { return fixedTime }

func makeOrg(id, name string, pub string) OrgTrustRoot {
	return OrgTrustRoot{
		OrgID:         id,
		OrgDID:        "did:helm:" + id,
		OrgName:       name,
		PublicKey:     pub,
		Algorithm:     "ed25519",
		EstablishedAt: fixedTime,
	}
}

func TestTrustRootStoreRegisterAndGet(t *testing.T) {
	s := NewTrustRootStore()
	org := makeOrg("org-1", "Org One", "aabbcc")
	if err := s.Register(org); err != nil {
		t.Fatalf("register: %v", err)
	}
	got, ok := s.Get("org-1")
	if !ok || got.OrgName != "Org One" {
		t.Fatalf("expected Org One, got %v", got)
	}
}

func TestTrustRootStoreRejectEmptyOrgID(t *testing.T) {
	s := NewTrustRootStore()
	err := s.Register(OrgTrustRoot{PublicKey: "abc"})
	if err == nil || !strings.Contains(err.Error(), "org_id") {
		t.Fatalf("expected org_id error, got %v", err)
	}
}

func TestTrustRootStoreRejectEmptyPublicKey(t *testing.T) {
	s := NewTrustRootStore()
	err := s.Register(OrgTrustRoot{OrgID: "o1"})
	if err == nil || !strings.Contains(err.Error(), "public_key") {
		t.Fatalf("expected public_key error, got %v", err)
	}
}

func TestTrustRootStoreRejectDuplicate(t *testing.T) {
	s := NewTrustRootStore()
	org := makeOrg("org-1", "O", "aabb")
	s.Register(org)
	err := s.Register(org)
	if err == nil || !strings.Contains(err.Error(), "already registered") {
		t.Fatalf("expected duplicate error, got %v", err)
	}
}

func TestTrustRootStoreRevokeAndReregister(t *testing.T) {
	s := NewTrustRootStore()
	s.Register(makeOrg("org-1", "O", "aabb"))
	s.Revoke("org-1")
	if s.IsTrusted("org-1") {
		t.Fatal("revoked org should not be trusted")
	}
	// Re-register after revocation should succeed.
	err := s.Register(makeOrg("org-1", "O2", "ccdd"))
	if err != nil {
		t.Fatalf("re-register after revocation should work: %v", err)
	}
}

func TestTrustRootStoreRevokeNotFound(t *testing.T) {
	s := NewTrustRootStore()
	err := s.Revoke("nonexistent")
	if err == nil {
		t.Fatal("expected error revoking nonexistent org")
	}
}

func TestTrustRootStoreListTrustedSorted(t *testing.T) {
	s := NewTrustRootStore()
	s.Register(makeOrg("c-org", "C", "aa"))
	s.Register(makeOrg("a-org", "A", "bb"))
	s.Register(makeOrg("b-org", "B", "cc"))
	s.Revoke("b-org")
	trusted := s.ListTrusted()
	if len(trusted) != 2 || trusted[0].OrgID != "a-org" || trusted[1].OrgID != "c-org" {
		t.Fatalf("expected [a-org, c-org], got %v", trusted)
	}
}

func TestTrustRootStoreContentHashPopulated(t *testing.T) {
	s := NewTrustRootStore()
	s.Register(makeOrg("org-1", "O", "aabb"))
	got, _ := s.Get("org-1")
	if got.ContentHash == "" {
		t.Fatal("content hash should be populated on register")
	}
}

func TestPolicyInheritorEffectiveCaps(t *testing.T) {
	pi := NewPolicyInheritor()
	pi.SetPolicy(FederationPolicy{
		PolicyID:      "p1",
		ParentOrgID:   "parent",
		ChildOrgID:    "child",
		InheritedCaps: []string{"read", "write", "delete"},
		DeniedCaps:    []string{"delete"},
		NarrowingOnly: true,
	})
	eff := pi.EffectiveCapabilities("child", []string{"read", "write", "delete", "admin"})
	if len(eff) != 2 || eff[0] != "read" || eff[1] != "write" {
		t.Fatalf("expected [read, write], got %v", eff)
	}
}

func TestPolicyInheritorNoPolicyFailsClosed(t *testing.T) {
	pi := NewPolicyInheritor()
	eff := pi.EffectiveCapabilities("unknown", []string{"read"})
	if len(eff) != 0 {
		t.Fatal("no policy should yield zero capabilities (fail-closed)")
	}
}

func TestPolicyInheritorValidateNarrowingRejectsExpansion(t *testing.T) {
	pi := NewPolicyInheritor()
	pi.SetPolicy(FederationPolicy{
		PolicyID: "p1", ParentOrgID: "parent", ChildOrgID: "child", NarrowingOnly: true,
	})
	err := pi.ValidateNarrowing("child", []string{"read", "super-admin"}, []string{"read"})
	if err == nil || !strings.Contains(err.Error(), "super-admin") {
		t.Fatalf("expected narrowing violation, got %v", err)
	}
}

func TestPolicyInheritorValidateNarrowingAllowsSubset(t *testing.T) {
	pi := NewPolicyInheritor()
	pi.SetPolicy(FederationPolicy{
		PolicyID: "p1", ParentOrgID: "parent", ChildOrgID: "child", NarrowingOnly: true,
	})
	err := pi.ValidateNarrowing("child", []string{"read"}, []string{"read", "write"})
	if err != nil {
		t.Fatalf("subset should pass narrowing: %v", err)
	}
}

func TestPolicyInheritorSetPolicyRejectsSameOrgIDs(t *testing.T) {
	pi := NewPolicyInheritor()
	err := pi.SetPolicy(FederationPolicy{
		PolicyID: "p", ParentOrgID: "same", ChildOrgID: "same",
	})
	if err == nil || !strings.Contains(err.Error(), "must differ") {
		t.Fatalf("expected parent==child error, got %v", err)
	}
}

func TestProtocolProposeAgreementRejectsEmptyRemote(t *testing.T) {
	signer, _ := crypto.NewEd25519Signer("k1")
	store := NewTrustRootStore()
	localOrg := makeOrg("local", "Local", signer.PublicKey())
	proto := NewFederationProtocol(localOrg, signer, store).WithClock(fixedClock)
	_, err := proto.ProposeAgreement(OrgTrustRoot{}, []string{"read"}, time.Hour)
	if err == nil || !strings.Contains(err.Error(), "org_id") {
		t.Fatalf("expected empty remote error, got %v", err)
	}
}

func TestProtocolCannotFederateWithSelf(t *testing.T) {
	signer, _ := crypto.NewEd25519Signer("k1")
	store := NewTrustRootStore()
	localOrg := makeOrg("local", "Local", signer.PublicKey())
	proto := NewFederationProtocol(localOrg, signer, store).WithClock(fixedClock)
	_, err := proto.ProposeAgreement(localOrg, []string{"read"}, time.Hour)
	if err == nil || !strings.Contains(err.Error(), "self") {
		t.Fatalf("expected self-federation error, got %v", err)
	}
}
