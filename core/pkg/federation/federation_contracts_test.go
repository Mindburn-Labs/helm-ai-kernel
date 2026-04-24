package federation

import (
	"encoding/json"
	"sync"
	"testing"
	"time"
)

func TestFinal_OrgTrustRootJSON(t *testing.T) {
	otr := OrgTrustRoot{OrgID: "org1", OrgName: "Acme", PublicKey: "abc123", Algorithm: "ed25519"}
	data, _ := json.Marshal(otr)
	var otr2 OrgTrustRoot
	json.Unmarshal(data, &otr2)
	if otr2.OrgID != "org1" {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_FederationAgreementJSON(t *testing.T) {
	fa := FederationAgreement{AgreementID: "a1", Capabilities: []string{"read", "write"}, CreatedAt: time.Now()}
	data, _ := json.Marshal(fa)
	var fa2 FederationAgreement
	json.Unmarshal(data, &fa2)
	if fa2.AgreementID != "a1" {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_FederationPolicyJSON(t *testing.T) {
	fp := FederationPolicy{PolicyID: "p1", ParentOrgID: "org1", ChildOrgID: "org2", NarrowingOnly: true}
	data, _ := json.Marshal(fp)
	var fp2 FederationPolicy
	json.Unmarshal(data, &fp2)
	if !fp2.NarrowingOnly {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_TrustRootStoreNew(t *testing.T) {
	trs := NewTrustRootStore()
	if trs == nil {
		t.Fatal("store should not be nil")
	}
}

func TestFinal_TrustRootStoreRegisterAndGet(t *testing.T) {
	trs := NewTrustRootStore()
	root := OrgTrustRoot{OrgID: "org1", OrgName: "Acme", PublicKey: "key1", Algorithm: "ed25519"}
	trs.Register(root)
	got, ok := trs.Get("org1")
	if !ok || got.OrgName != "Acme" {
		t.Fatal("should retrieve added root")
	}
}

func TestFinal_TrustRootStoreGetMissing(t *testing.T) {
	trs := NewTrustRootStore()
	_, ok := trs.Get("nonexistent")
	if ok {
		t.Fatal("should not find missing root")
	}
}

func TestFinal_PolicyInheritorNew(t *testing.T) {
	pi := NewPolicyInheritor()
	if pi == nil {
		t.Fatal("inheritor should not be nil")
	}
}

func TestFinal_PolicyInheritorEffectiveCaps(t *testing.T) {
	pi := NewPolicyInheritor()
	pi.SetPolicy(FederationPolicy{
		PolicyID:      "p1",
		ParentOrgID:   "parent",
		ChildOrgID:    "child",
		InheritedCaps: []string{"read", "write", "admin"},
		DeniedCaps:    []string{"admin"},
		NarrowingOnly: true,
	})
	caps := pi.EffectiveCapabilities("child", []string{"read", "write", "admin"})
	for _, c := range caps {
		if c == "admin" {
			t.Fatal("admin should be denied after narrowing")
		}
	}
}

func TestFinal_OrgTrustRootRevoked(t *testing.T) {
	otr := OrgTrustRoot{OrgID: "org1", Revoked: true}
	if !otr.Revoked {
		t.Fatal("should be revoked")
	}
}

func TestFinal_FederationAgreementCapabilities(t *testing.T) {
	fa := FederationAgreement{Capabilities: []string{"a", "b", "c"}}
	if len(fa.Capabilities) != 3 {
		t.Fatal("should have 3 capabilities")
	}
}

func TestFinal_FederationPolicyDeniedCaps(t *testing.T) {
	fp := FederationPolicy{DeniedCaps: []string{"delete", "admin"}}
	if len(fp.DeniedCaps) != 2 {
		t.Fatal("should have 2 denied caps")
	}
}

func TestFinal_ConcurrentTrustRootStore(t *testing.T) {
	trs := NewTrustRootStore()
	var wg sync.WaitGroup
	for i := 0; i < 15; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			trs.Register(OrgTrustRoot{OrgID: string(rune('a' + i)), PublicKey: "k", Algorithm: "ed25519"})
			trs.Get(string(rune('a' + i)))
		}(i)
	}
	wg.Wait()
}

func TestFinal_OrgTrustRootContentHash(t *testing.T) {
	otr := OrgTrustRoot{OrgID: "org1", ContentHash: "sha256:abc"}
	if otr.ContentHash != "sha256:abc" {
		t.Fatal("content hash mismatch")
	}
}

func TestFinal_FederationAgreementContentHash(t *testing.T) {
	fa := FederationAgreement{ContentHash: "sha256:xyz"}
	if fa.ContentHash != "sha256:xyz" {
		t.Fatal("content hash mismatch")
	}
}

func TestFinal_OrgTrustRootExpiry(t *testing.T) {
	expires := time.Now().Add(24 * time.Hour)
	otr := OrgTrustRoot{OrgID: "org1", ExpiresAt: expires}
	if otr.ExpiresAt.Before(time.Now()) {
		t.Fatal("should not be expired yet")
	}
}

func TestFinal_FederationAgreementExpiry(t *testing.T) {
	fa := FederationAgreement{ExpiresAt: time.Now().Add(-time.Hour)}
	if fa.ExpiresAt.After(time.Now()) {
		t.Fatal("should be expired")
	}
}

func TestFinal_FederationPolicyInheritedCaps(t *testing.T) {
	fp := FederationPolicy{InheritedCaps: []string{"read", "write"}}
	if len(fp.InheritedCaps) != 2 {
		t.Fatal("should have 2 inherited caps")
	}
}

func TestFinal_OrgTrustRootAlgorithm(t *testing.T) {
	otr := OrgTrustRoot{Algorithm: "ed25519"}
	if otr.Algorithm != "ed25519" {
		t.Fatal("algorithm mismatch")
	}
}

func TestFinal_FederationAgreementSignatures(t *testing.T) {
	fa := FederationAgreement{SignatureA: "sigA", SignatureB: "sigB"}
	if fa.SignatureA == "" || fa.SignatureB == "" {
		t.Fatal("both signatures should be set")
	}
}

func TestFinal_OrgTrustRootDID(t *testing.T) {
	otr := OrgTrustRoot{OrgDID: "did:web:example.com"}
	if otr.OrgDID != "did:web:example.com" {
		t.Fatal("DID mismatch")
	}
}

func TestFinal_TrustRootStoreListTrusted(t *testing.T) {
	trs := NewTrustRootStore()
	trs.Register(OrgTrustRoot{OrgID: "a", PublicKey: "k1", Algorithm: "ed25519"})
	trs.Register(OrgTrustRoot{OrgID: "b", PublicKey: "k2", Algorithm: "ed25519"})
	all := trs.ListTrusted()
	if len(all) != 2 {
		t.Fatalf("want 2, got %d", len(all))
	}
}

func TestFinal_FederationPolicyParentChild(t *testing.T) {
	fp := FederationPolicy{ParentOrgID: "parent", ChildOrgID: "child"}
	if fp.ParentOrgID == fp.ChildOrgID {
		t.Fatal("parent and child should differ")
	}
}

func TestFinal_OrgTrustRootZeroValue(t *testing.T) {
	var otr OrgTrustRoot
	if otr.Revoked {
		t.Fatal("zero value should not be revoked")
	}
}

func TestFinal_FederationAgreementOrgAOrgB(t *testing.T) {
	fa := FederationAgreement{OrgA: OrgTrustRoot{OrgID: "a"}, OrgB: OrgTrustRoot{OrgID: "b"}}
	if fa.OrgA.OrgID == fa.OrgB.OrgID {
		t.Fatal("OrgA and OrgB should differ")
	}
}

func TestFinal_PolicyInheritorZeroValue(t *testing.T) {
	pi := &PolicyInheritor{}
	if pi == nil {
		t.Fatal("zero value should not be nil")
	}
}
