package federation

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

func deepOrg(id, name string, pub string) OrgTrustRoot {
	return OrgTrustRoot{
		OrgID:         id,
		OrgDID:        "did:helm:" + id,
		OrgName:       name,
		PublicKey:     pub,
		Algorithm:     "ed25519",
		EstablishedAt: fixedTime,
	}
}

func TestDeep_DeepTrustRootStore50Orgs(t *testing.T) {
	s := NewTrustRootStore()
	for i := 0; i < 50; i++ {
		org := deepOrg(fmt.Sprintf("deep-org-%d", i), fmt.Sprintf("Org %d", i), fmt.Sprintf("%064x", i+1))
		if err := s.Register(org); err != nil {
			t.Fatalf("org %d: %v", i, err)
		}
	}
	trusted := s.ListTrusted()
	if len(trusted) != 50 {
		t.Fatalf("expected 50 trusted orgs, got %d", len(trusted))
	}
}

func TestDeep_DeepTrustRootStoreListSorted(t *testing.T) {
	s := NewTrustRootStore()
	for _, id := range []string{"zeta-deep", "alpha-deep", "mu-deep"} {
		s.Register(deepOrg(id, id, "aabb"))
	}
	trusted := s.ListTrusted()
	if trusted[0].OrgID != "alpha-deep" || trusted[2].OrgID != "zeta-deep" {
		t.Fatal("ListTrusted not sorted")
	}
}

func TestDeep_DeepTrustRootStoreRevokeExcludes(t *testing.T) {
	s := NewTrustRootStore()
	s.Register(deepOrg("da", "A", "ab"))
	s.Register(deepOrg("db", "B", "cd"))
	s.Revoke("da")
	if s.IsTrusted("da") {
		t.Fatal("revoked org should not be trusted")
	}
	if len(s.ListTrusted()) != 1 {
		t.Fatal("only one org should remain trusted")
	}
}

func TestDeep_DeepTrustRootStoreReRegisterAfterRevoke(t *testing.T) {
	s := NewTrustRootStore()
	s.Register(deepOrg("da", "A", "ab"))
	s.Revoke("da")
	err := s.Register(deepOrg("da", "A-v2", "cd"))
	if err != nil {
		t.Fatalf("re-register after revoke should succeed: %v", err)
	}
}

func TestDeep_DeepTrustRootStoreDuplicateReject(t *testing.T) {
	s := NewTrustRootStore()
	s.Register(deepOrg("da", "A", "ab"))
	err := s.Register(deepOrg("da", "A2", "cd"))
	if err == nil {
		t.Fatal("should reject duplicate non-revoked org")
	}
}

func TestDeep_DeepTrustRootStoreEmptyOrgID(t *testing.T) {
	s := NewTrustRootStore()
	err := s.Register(deepOrg("", "No ID", "ab"))
	if err == nil {
		t.Fatal("should reject empty org_id")
	}
}

func TestDeep_DeepTrustRootStoreEmptyPublicKey(t *testing.T) {
	s := NewTrustRootStore()
	err := s.Register(deepOrg("da", "A", ""))
	if err == nil {
		t.Fatal("should reject empty public_key")
	}
}

func TestDeep_DeepTrustRootStoreContentHashSet(t *testing.T) {
	s := NewTrustRootStore()
	s.Register(deepOrg("da", "A", "ab"))
	org, _ := s.Get("da")
	if org.ContentHash == "" {
		t.Fatal("content hash should be set on register")
	}
}

func TestDeep_DeepFederationAgreementFullLifecycle(t *testing.T) {
	signerA, _ := crypto.NewEd25519Signer("deep-key-a")
	signerB, _ := crypto.NewEd25519Signer("deep-key-b")
	store := NewTrustRootStore()

	orgA := deepOrg("deepA", "Org A", signerA.PublicKey())
	orgB := deepOrg("deepB", "Org B", signerB.PublicKey())
	store.Register(orgA)
	store.Register(orgB)

	protoA := NewFederationProtocol(orgA, signerA, store).WithClock(fixedClock)
	protoB := NewFederationProtocol(orgB, signerB, store).WithClock(fixedClock)

	proposal, err := protoA.ProposeAgreement(orgB, []string{"read", "write"}, time.Hour)
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	accepted, err := protoB.AcceptAgreement(proposal)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	if err := protoA.VerifyAgreement(accepted); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestDeep_DeepFederationRejectsSelfFederation(t *testing.T) {
	signer, _ := crypto.NewEd25519Signer("dk")
	store := NewTrustRootStore()
	org := deepOrg("dx", "X", signer.PublicKey())
	store.Register(org)
	proto := NewFederationProtocol(org, signer, store)
	_, err := proto.ProposeAgreement(org, []string{"r"}, time.Hour)
	if err == nil {
		t.Fatal("should reject self-federation")
	}
}

func TestDeep_DeepFederationRejectsEmptyCaps(t *testing.T) {
	signer, _ := crypto.NewEd25519Signer("dk")
	store := NewTrustRootStore()
	org := deepOrg("da", "A", signer.PublicKey())
	remote := deepOrg("db", "B", "aabb")
	store.Register(org)
	proto := NewFederationProtocol(org, signer, store)
	_, err := proto.ProposeAgreement(remote, []string{}, time.Hour)
	if err == nil {
		t.Fatal("should reject empty capabilities")
	}
}

func TestDeep_DeepFederationRejectsExpiredProposal(t *testing.T) {
	signerA, _ := crypto.NewEd25519Signer("da")
	signerB, _ := crypto.NewEd25519Signer("db")
	store := NewTrustRootStore()
	orgA := deepOrg("da", "A", signerA.PublicKey())
	orgB := deepOrg("db", "B", signerB.PublicKey())
	store.Register(orgA)
	store.Register(orgB)

	past := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	protoA := NewFederationProtocol(orgA, signerA, store).WithClock(func() time.Time { return past })
	proposal, _ := protoA.ProposeAgreement(orgB, []string{"r"}, time.Millisecond)

	protoB := NewFederationProtocol(orgB, signerB, store).WithClock(fixedClock)
	_, err := protoB.AcceptAgreement(proposal)
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected expired error, got: %v", err)
	}
}

func TestDeep_DeepPolicyInheritance3LevelsDeep(t *testing.T) {
	pi := NewPolicyInheritor()
	pi.SetPolicy(FederationPolicy{
		PolicyID: "dp1", ParentOrgID: "root", ChildOrgID: "mid",
		InheritedCaps: []string{"read", "write", "admin"}, NarrowingOnly: true,
	})
	pi.SetPolicy(FederationPolicy{
		PolicyID: "dp2", ParentOrgID: "mid", ChildOrgID: "leaf",
		InheritedCaps: []string{"read", "write"}, NarrowingOnly: true,
	})

	midCaps := pi.EffectiveCapabilities("mid", []string{"read", "write", "admin", "delete"})
	leafCaps := pi.EffectiveCapabilities("leaf", midCaps)

	if len(leafCaps) != 2 || leafCaps[0] != "read" || leafCaps[1] != "write" {
		t.Fatalf("leaf caps = %v, want [read, write]", leafCaps)
	}
}

func TestDeep_DeepPolicyNarrowingViolation(t *testing.T) {
	pi := NewPolicyInheritor()
	pi.SetPolicy(FederationPolicy{
		PolicyID: "dp1", ParentOrgID: "root", ChildOrgID: "dchild",
		InheritedCaps: []string{"read"}, NarrowingOnly: true,
	})
	err := pi.ValidateNarrowing("dchild", []string{"read", "write"}, []string{"read"})
	if err == nil || !strings.Contains(err.Error(), "narrowing violation") {
		t.Fatalf("expected narrowing violation, got: %v", err)
	}
}

func TestDeep_DeepPolicyNarrowingAllowsSubset(t *testing.T) {
	pi := NewPolicyInheritor()
	pi.SetPolicy(FederationPolicy{
		PolicyID: "dp1", ParentOrgID: "root", ChildOrgID: "dchild",
		InheritedCaps: []string{"read", "write"}, NarrowingOnly: true,
	})
	err := pi.ValidateNarrowing("dchild", []string{"read"}, []string{"read", "write"})
	if err != nil {
		t.Fatalf("subset should be valid: %v", err)
	}
}

func TestDeep_DeepPolicyDeniedCapsOverride(t *testing.T) {
	pi := NewPolicyInheritor()
	pi.SetPolicy(FederationPolicy{
		PolicyID: "dp1", ParentOrgID: "root", ChildOrgID: "dchild",
		InheritedCaps: []string{"read", "write", "admin"},
		DeniedCaps:    []string{"admin"},
		NarrowingOnly: true,
	})
	caps := pi.EffectiveCapabilities("dchild", []string{"read", "write", "admin"})
	for _, c := range caps {
		if c == "admin" {
			t.Fatal("admin should be denied")
		}
	}
}

func TestDeep_DeepPolicyFailClosedNoPolicy(t *testing.T) {
	pi := NewPolicyInheritor()
	caps := pi.EffectiveCapabilities("unknown-deep", []string{"read", "write"})
	if len(caps) != 0 {
		t.Fatal("no policy should mean no capabilities (fail-closed)")
	}
}

func TestDeep_DeepPolicyNarrowingDisabled(t *testing.T) {
	pi := NewPolicyInheritor()
	pi.SetPolicy(FederationPolicy{
		PolicyID: "dp1", ParentOrgID: "root", ChildOrgID: "dchild",
		InheritedCaps: []string{"read"}, NarrowingOnly: false,
	})
	err := pi.ValidateNarrowing("dchild", []string{"read", "extra"}, []string{"read"})
	if err != nil {
		t.Fatal("narrowing disabled should allow expansion")
	}
}

func TestDeep_DeepPolicySetRejectsSameParentChild(t *testing.T) {
	pi := NewPolicyInheritor()
	err := pi.SetPolicy(FederationPolicy{
		PolicyID: "dp1", ParentOrgID: "dx", ChildOrgID: "dx",
		InheritedCaps: []string{"r"},
	})
	if err == nil {
		t.Fatal("should reject same parent and child")
	}
}

func TestDeep_DeepConcurrentProtocolNegotiations(t *testing.T) {
	var wg sync.WaitGroup
	store := NewTrustRootStore()
	signers := make([]crypto.Signer, 20)

	for i := 0; i < 20; i++ {
		s, _ := crypto.NewEd25519Signer(fmt.Sprintf("dk%d", i))
		signers[i] = s
		org := deepOrg(fmt.Sprintf("deep-org-%d", i), fmt.Sprintf("Org %d", i), s.PublicKey())
		store.Register(org)
	}

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			peer := (idx + 1) % 20
			orgLocal := deepOrg(fmt.Sprintf("deep-org-%d", idx), fmt.Sprintf("Org %d", idx), signers[idx].PublicKey())
			orgRemote := deepOrg(fmt.Sprintf("deep-org-%d", peer), fmt.Sprintf("Org %d", peer), signers[peer].PublicKey())
			proto := NewFederationProtocol(orgLocal, signers[idx], store).WithClock(fixedClock)
			_, err := proto.ProposeAgreement(orgRemote, []string{"read"}, time.Hour)
			if err != nil {
				t.Errorf("goroutine %d: %v", idx, err)
			}
		}(i)
	}
	wg.Wait()
}

func TestDeep_DeepFederationAgreementCapsSorted(t *testing.T) {
	signerA, _ := crypto.NewEd25519Signer("da")
	store := NewTrustRootStore()
	orgA := deepOrg("da", "A", signerA.PublicKey())
	orgB := deepOrg("db", "B", "aabb")
	store.Register(orgA)
	store.Register(orgB)

	proto := NewFederationProtocol(orgA, signerA, store).WithClock(fixedClock)
	proposal, _ := proto.ProposeAgreement(orgB, []string{"write", "admin", "read"}, time.Hour)
	if proposal.Capabilities[0] != "admin" || proposal.Capabilities[2] != "write" {
		t.Fatalf("caps not sorted: %v", proposal.Capabilities)
	}
}

func TestDeep_DeepTrustRootStoreRevokeUnknown(t *testing.T) {
	s := NewTrustRootStore()
	err := s.Revoke("deep-ghost")
	if err == nil {
		t.Fatal("revoking non-existent org should fail")
	}
}

func TestDeep_DeepTrustRootStoreGetNotFound(t *testing.T) {
	s := NewTrustRootStore()
	_, found := s.Get("deep-ghost")
	if found {
		t.Fatal("should not find non-existent org")
	}
}

func TestDeep_DeepTrustRootStoreIsTrustedFalseForUnknown(t *testing.T) {
	s := NewTrustRootStore()
	if s.IsTrusted("nonexistent") {
		t.Fatal("unknown org should not be trusted")
	}
}

func TestDeep_DeepPolicySetRejectsEmptyFields(t *testing.T) {
	pi := NewPolicyInheritor()
	cases := []FederationPolicy{
		{PolicyID: "", ParentOrgID: "p", ChildOrgID: "c"},
		{PolicyID: "dp1", ParentOrgID: "", ChildOrgID: "c"},
		{PolicyID: "dp1", ParentOrgID: "p", ChildOrgID: ""},
	}
	for i, c := range cases {
		if err := pi.SetPolicy(c); err == nil {
			t.Errorf("case %d: should reject empty field", i)
		}
	}
}
