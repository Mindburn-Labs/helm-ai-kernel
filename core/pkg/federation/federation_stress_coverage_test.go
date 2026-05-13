package federation

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

// ────────────────────────────────────────────────────────────────────────
// helpers
// ────────────────────────────────────────────────────────────────────────

func makeOrgRootAndSigner(id string) (OrgTrustRoot, crypto.Signer) {
	signer, err := crypto.NewEd25519Signer(id + "-key")
	if err != nil {
		panic(err)
	}
	root := OrgTrustRoot{
		OrgID:         id,
		OrgDID:        fmt.Sprintf("did:helm:%s", id),
		OrgName:       fmt.Sprintf("Org %s", id),
		PublicKey:     signer.PublicKey(),
		Algorithm:     "ed25519",
		EstablishedAt: time.Now().UTC(),
		ExpiresAt:     time.Now().Add(24 * time.Hour),
	}
	return root, signer
}

func makeOrgRoot(id string) OrgTrustRoot {
	root, _ := makeOrgRootAndSigner(id)
	return root
}

func makeProtocol(orgID string) (*FederationProtocol, OrgTrustRoot, crypto.Signer) {
	root, signer := makeOrgRootAndSigner(orgID)
	store := NewTrustRootStore()
	return NewFederationProtocol(root, signer, store), root, signer
}

// ────────────────────────────────────────────────────────────────────────
// 50 org trust roots
// ────────────────────────────────────────────────────────────────────────

func TestStress_50OrgTrustRoots(t *testing.T) {
	store := NewTrustRootStore()
	for i := 0; i < 50; i++ {
		root := makeOrgRoot(fmt.Sprintf("org-%d", i))
		if err := store.Register(root); err != nil {
			t.Fatalf("register org-%d: %v", i, err)
		}
	}
	trusted := store.ListTrusted()
	if len(trusted) != 50 {
		t.Fatalf("expected 50 trusted, got %d", len(trusted))
	}
}

func TestStress_TrustRootStoreRegisterDuplicate(t *testing.T) {
	store := NewTrustRootStore()
	root := makeOrgRoot("org-dup")
	_ = store.Register(root)
	err := store.Register(root)
	if err == nil {
		t.Fatal("expected error for duplicate registration")
	}
}

func TestStress_TrustRootStoreRegisterEmptyID(t *testing.T) {
	store := NewTrustRootStore()
	err := store.Register(OrgTrustRoot{PublicKey: "abc"})
	if err == nil {
		t.Fatal("expected error for empty org_id")
	}
}

func TestStress_TrustRootStoreRegisterEmptyKey(t *testing.T) {
	store := NewTrustRootStore()
	err := store.Register(OrgTrustRoot{OrgID: "org"})
	if err == nil {
		t.Fatal("expected error for empty public_key")
	}
}

func TestStress_TrustRootStoreRevoke(t *testing.T) {
	store := NewTrustRootStore()
	_ = store.Register(makeOrgRoot("org-rev"))
	_ = store.Revoke("org-rev")
	if store.IsTrusted("org-rev") {
		t.Fatal("expected revoked org to not be trusted")
	}
}

func TestStress_TrustRootStoreRevokeNotFound(t *testing.T) {
	store := NewTrustRootStore()
	err := store.Revoke("missing")
	if err == nil {
		t.Fatal("expected error for revoking missing org")
	}
}

func TestStress_TrustRootStoreGet(t *testing.T) {
	store := NewTrustRootStore()
	_ = store.Register(makeOrgRoot("org-get"))
	root, ok := store.Get("org-get")
	if !ok || root.OrgID != "org-get" {
		t.Fatal("get failed")
	}
}

func TestStress_TrustRootStoreGetNotFound(t *testing.T) {
	store := NewTrustRootStore()
	_, ok := store.Get("missing")
	if ok {
		t.Fatal("expected not found")
	}
}

func TestStress_TrustRootStoreIsTrusted(t *testing.T) {
	store := NewTrustRootStore()
	_ = store.Register(makeOrgRoot("org-tr"))
	if !store.IsTrusted("org-tr") {
		t.Fatal("expected trusted")
	}
}

func TestStress_TrustRootStoreListTrustedSorted(t *testing.T) {
	store := NewTrustRootStore()
	_ = store.Register(makeOrgRoot("z-org"))
	_ = store.Register(makeOrgRoot("a-org"))
	trusted := store.ListTrusted()
	if trusted[0].OrgID != "a-org" {
		t.Fatal("expected sorted by OrgID")
	}
}

func TestStress_TrustRootStoreReRegisterAfterRevoke(t *testing.T) {
	store := NewTrustRootStore()
	_ = store.Register(makeOrgRoot("org-reuse"))
	_ = store.Revoke("org-reuse")
	err := store.Register(makeOrgRoot("org-reuse"))
	if err != nil {
		t.Fatalf("expected re-registration after revoke to succeed: %v", err)
	}
}

func TestStress_TrustRootContentHash(t *testing.T) {
	store := NewTrustRootStore()
	_ = store.Register(makeOrgRoot("org-hash"))
	root, _ := store.Get("org-hash")
	if root.ContentHash == "" {
		t.Fatal("content hash not set")
	}
}

// ────────────────────────────────────────────────────────────────────────
// 20 federation agreements
// ────────────────────────────────────────────────────────────────────────

func TestStress_20FederationAgreements(t *testing.T) {
	for i := 0; i < 20; i++ {
		rootA, signerA := makeOrgRootAndSigner(fmt.Sprintf("a-%d", i))
		rootB, signerB := makeOrgRootAndSigner(fmt.Sprintf("b-%d", i))

		storeA := NewTrustRootStore()
		_ = storeA.Register(rootB)
		protA := NewFederationProtocol(rootA, signerA, storeA)

		storeB := NewTrustRootStore()
		_ = storeB.Register(rootA)
		protB := NewFederationProtocol(rootB, signerB, storeB)

		proposal, err := protA.ProposeAgreement(rootB, []string{"EXECUTE_TOOL", "READ"}, 24*time.Hour)
		if err != nil {
			t.Fatalf("propose %d: %v", i, err)
		}
		accepted, err := protB.AcceptAgreement(proposal)
		if err != nil {
			t.Fatalf("accept %d: %v", i, err)
		}
		if accepted.SignatureB == "" {
			t.Fatalf("agreement %d: missing SignatureB", i)
		}
	}
}

func TestStress_ProposeAgreementSelfFederation(t *testing.T) {
	prot, root, _ := makeProtocol("self-org")
	_, err := prot.ProposeAgreement(root, []string{"CAP"}, time.Hour)
	if err == nil {
		t.Fatal("expected error for self-federation")
	}
}

func TestStress_ProposeAgreementEmptyCaps(t *testing.T) {
	prot, _, _ := makeProtocol("org-a")
	_, err := prot.ProposeAgreement(makeOrgRoot("org-b"), nil, time.Hour)
	if err == nil {
		t.Fatal("expected error for empty capabilities")
	}
}

func TestStress_ProposeAgreementEmptyRemoteOrg(t *testing.T) {
	prot, _, _ := makeProtocol("org-a")
	_, err := prot.ProposeAgreement(OrgTrustRoot{}, []string{"CAP"}, time.Hour)
	if err == nil {
		t.Fatal("expected error for empty remote org_id")
	}
}

func TestStress_AcceptAgreementNil(t *testing.T) {
	prot, _, _ := makeProtocol("org-a")
	_, err := prot.AcceptAgreement(nil)
	if err == nil {
		t.Fatal("expected error for nil proposal")
	}
}

func TestStress_AcceptAgreementWrongOrgB(t *testing.T) {
	rootA, signerA := makeOrgRootAndSigner("org-a")
	rootB := makeOrgRoot("org-b")

	storeA := NewTrustRootStore()
	protA := NewFederationProtocol(rootA, signerA, storeA)
	proposal, _ := protA.ProposeAgreement(rootB, []string{"CAP"}, time.Hour)

	protC, _, _ := makeProtocol("org-c")
	_, err := protC.AcceptAgreement(proposal)
	if err == nil {
		t.Fatal("expected error for wrong OrgB")
	}
}

func TestStress_VerifyAgreementNil(t *testing.T) {
	prot, _, _ := makeProtocol("org-a")
	err := prot.VerifyAgreement(nil)
	if err == nil {
		t.Fatal("expected error for nil agreement")
	}
}

func TestStress_VerifyAgreementMissingSignatures(t *testing.T) {
	prot, _, _ := makeProtocol("org-a")
	err := prot.VerifyAgreement(&FederationAgreement{})
	if err == nil {
		t.Fatal("expected error for missing signatures")
	}
}

// ────────────────────────────────────────────────────────────────────────
// Policy inheritance 5 levels deep
// ────────────────────────────────────────────────────────────────────────

func TestStress_PolicyInheritance5Levels(t *testing.T) {
	pi := NewPolicyInheritor()
	allCaps := []string{"CAP_A", "CAP_B", "CAP_C", "CAP_D", "CAP_E"}
	for level := 0; level < 5; level++ {
		child := fmt.Sprintf("child-%d", level)
		parent := "root-org"
		if level > 0 {
			parent = fmt.Sprintf("child-%d", level-1)
		}
		inherited := allCaps[:len(allCaps)-level]
		_ = pi.SetPolicy(FederationPolicy{
			PolicyID:      fmt.Sprintf("pol-%d", level),
			ParentOrgID:   parent,
			ChildOrgID:    child,
			InheritedCaps: inherited,
			NarrowingOnly: true,
		})
	}
	eff := pi.EffectiveCapabilities("child-4", []string{"CAP_A"})
	if len(eff) != 1 || eff[0] != "CAP_A" {
		t.Fatalf("expected [CAP_A], got %v", eff)
	}
}

func TestStress_PolicyInheritanceFailClosed(t *testing.T) {
	pi := NewPolicyInheritor()
	eff := pi.EffectiveCapabilities("unknown-child", []string{"CAP_A"})
	if len(eff) != 0 {
		t.Fatal("expected no capabilities for unknown child (fail-closed)")
	}
}

func TestStress_PolicyInheritanceDeniedCaps(t *testing.T) {
	pi := NewPolicyInheritor()
	_ = pi.SetPolicy(FederationPolicy{
		PolicyID: "p1", ParentOrgID: "parent", ChildOrgID: "child",
		InheritedCaps: []string{"CAP_A", "CAP_B", "CAP_C"},
		DeniedCaps:    []string{"CAP_B"},
	})
	eff := pi.EffectiveCapabilities("child", []string{"CAP_A", "CAP_B", "CAP_C"})
	for _, c := range eff {
		if c == "CAP_B" {
			t.Fatal("CAP_B should be denied")
		}
	}
}

func TestStress_PolicySetPolicyInvalidEmptyID(t *testing.T) {
	pi := NewPolicyInheritor()
	err := pi.SetPolicy(FederationPolicy{ParentOrgID: "p", ChildOrgID: "c"})
	if err == nil {
		t.Fatal("expected error for empty policy_id")
	}
}

func TestStress_PolicySetPolicyEmptyParent(t *testing.T) {
	pi := NewPolicyInheritor()
	err := pi.SetPolicy(FederationPolicy{PolicyID: "p1", ChildOrgID: "c"})
	if err == nil {
		t.Fatal("expected error for empty parent_org_id")
	}
}

func TestStress_PolicySetPolicyEmptyChild(t *testing.T) {
	pi := NewPolicyInheritor()
	err := pi.SetPolicy(FederationPolicy{PolicyID: "p1", ParentOrgID: "p"})
	if err == nil {
		t.Fatal("expected error for empty child_org_id")
	}
}

func TestStress_PolicySetPolicySameParentChild(t *testing.T) {
	pi := NewPolicyInheritor()
	err := pi.SetPolicy(FederationPolicy{PolicyID: "p1", ParentOrgID: "same", ChildOrgID: "same"})
	if err == nil {
		t.Fatal("expected error for same parent and child")
	}
}

// ────────────────────────────────────────────────────────────────────────
// Concurrent protocol negotiations
// ────────────────────────────────────────────────────────────────────────

func TestStress_ConcurrentTrustRootRegistrations(t *testing.T) {
	store := NewTrustRootStore()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			_ = store.Register(makeOrgRoot(fmt.Sprintf("conc-%d", n)))
		}(i)
	}
	wg.Wait()
	trusted := store.ListTrusted()
	if len(trusted) != 50 {
		t.Fatalf("expected 50, got %d", len(trusted))
	}
}

func TestStress_ConcurrentIsTrustedChecks(t *testing.T) {
	store := NewTrustRootStore()
	for i := 0; i < 20; i++ {
		_ = store.Register(makeOrgRoot(fmt.Sprintf("ct-%d", i)))
	}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			store.IsTrusted(fmt.Sprintf("ct-%d", n%20))
		}(i)
	}
	wg.Wait()
}

// ────────────────────────────────────────────────────────────────────────
// Narrowing enforcement with 100 capabilities
// ────────────────────────────────────────────────────────────────────────

func TestStress_NarrowingEnforcement100Caps(t *testing.T) {
	pi := NewPolicyInheritor()
	parentCaps := make([]string, 100)
	for i := 0; i < 100; i++ {
		parentCaps[i] = fmt.Sprintf("CAP_%d", i)
	}
	_ = pi.SetPolicy(FederationPolicy{
		PolicyID: "p1", ParentOrgID: "parent", ChildOrgID: "child",
		InheritedCaps: parentCaps, NarrowingOnly: true,
	})
	err := pi.ValidateNarrowing("child", parentCaps, parentCaps)
	if err != nil {
		t.Fatalf("valid narrowing should pass: %v", err)
	}
}

func TestStress_NarrowingViolation(t *testing.T) {
	pi := NewPolicyInheritor()
	_ = pi.SetPolicy(FederationPolicy{
		PolicyID: "p1", ParentOrgID: "parent", ChildOrgID: "child",
		InheritedCaps: []string{"CAP_A"}, NarrowingOnly: true,
	})
	err := pi.ValidateNarrowing("child", []string{"CAP_A", "CAP_EXTRA"}, []string{"CAP_A"})
	if err == nil {
		t.Fatal("expected narrowing violation for extra capability")
	}
}

func TestStress_NarrowingNoPolicyFound(t *testing.T) {
	pi := NewPolicyInheritor()
	err := pi.ValidateNarrowing("unknown", []string{"CAP_A"}, []string{"CAP_A"})
	if err == nil {
		t.Fatal("expected error for missing policy")
	}
}

func TestStress_NarrowingNotEnforced(t *testing.T) {
	pi := NewPolicyInheritor()
	_ = pi.SetPolicy(FederationPolicy{
		PolicyID: "p1", ParentOrgID: "parent", ChildOrgID: "child",
		InheritedCaps: []string{"CAP_A"}, NarrowingOnly: false,
	})
	err := pi.ValidateNarrowing("child", []string{"CAP_A", "CAP_EXTRA"}, []string{"CAP_A"})
	if err != nil {
		t.Fatal("narrowing should not be enforced when NarrowingOnly is false")
	}
}

func TestStress_EffectiveCapsSorted(t *testing.T) {
	pi := NewPolicyInheritor()
	_ = pi.SetPolicy(FederationPolicy{
		PolicyID: "p1", ParentOrgID: "parent", ChildOrgID: "child",
		InheritedCaps: []string{"Z_CAP", "A_CAP", "M_CAP"},
	})
	eff := pi.EffectiveCapabilities("child", []string{"Z_CAP", "A_CAP", "M_CAP"})
	if len(eff) != 3 || eff[0] != "A_CAP" {
		t.Fatalf("expected sorted caps, got %v", eff)
	}
}

func TestStress_EffectiveCapsIntersection(t *testing.T) {
	pi := NewPolicyInheritor()
	_ = pi.SetPolicy(FederationPolicy{
		PolicyID: "p1", ParentOrgID: "parent", ChildOrgID: "child",
		InheritedCaps: []string{"CAP_A", "CAP_B"},
	})
	eff := pi.EffectiveCapabilities("child", []string{"CAP_B", "CAP_C"})
	if len(eff) != 1 || eff[0] != "CAP_B" {
		t.Fatalf("expected [CAP_B], got %v", eff)
	}
}
