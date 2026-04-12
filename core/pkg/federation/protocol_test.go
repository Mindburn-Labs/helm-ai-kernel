package federation

import (
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/crypto"
)

// setupProtocolPair creates two federation protocol instances (OrgA and OrgB)
// with real Ed25519 signers and a shared trust store.
func setupProtocolPair(t *testing.T, clock func() time.Time) (protocolA, protocolB *FederationProtocol, orgA, orgB OrgTrustRoot) {
	t.Helper()

	signerA, err := crypto.NewEd25519Signer("key-orgA")
	if err != nil {
		t.Fatalf("NewEd25519Signer A: %v", err)
	}
	signerB, err := crypto.NewEd25519Signer("key-orgB")
	if err != nil {
		t.Fatalf("NewEd25519Signer B: %v", err)
	}

	orgA = OrgTrustRoot{
		OrgID:         "org-alpha",
		OrgDID:        "did:helm:org-alpha",
		OrgName:       "Alpha Corp",
		PublicKey:     signerA.PublicKey(),
		Algorithm:     "ed25519",
		EstablishedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	orgB = OrgTrustRoot{
		OrgID:         "org-beta",
		OrgDID:        "did:helm:org-beta",
		OrgName:       "Beta Corp",
		PublicKey:     signerB.PublicKey(),
		Algorithm:     "ed25519",
		EstablishedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	store := NewTrustRootStore()
	if err := store.Register(orgA); err != nil {
		t.Fatalf("register orgA: %v", err)
	}
	if err := store.Register(orgB); err != nil {
		t.Fatalf("register orgB: %v", err)
	}

	protocolA = NewFederationProtocol(orgA, signerA, store).WithClock(clock)
	protocolB = NewFederationProtocol(orgB, signerB, store).WithClock(clock)
	return
}

func TestFederationProtocol_ProposeAccept(t *testing.T) {
	now := time.Date(2026, 4, 12, 10, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	protocolA, protocolB, _, _ := setupProtocolPair(t, clock)

	// OrgA proposes.
	proposal, err := protocolA.ProposeAgreement(protocolB.localOrg, []string{"EXECUTE_TOOL", "READ"}, 24*time.Hour)
	if err != nil {
		t.Fatalf("ProposeAgreement: %v", err)
	}
	if proposal.SignatureA == "" {
		t.Fatal("proposal should have OrgA signature")
	}
	if proposal.SignatureB != "" {
		t.Fatal("proposal should not have OrgB signature yet")
	}
	if proposal.ContentHash == "" {
		t.Fatal("proposal should have content hash")
	}

	// OrgB accepts.
	accepted, err := protocolB.AcceptAgreement(proposal)
	if err != nil {
		t.Fatalf("AcceptAgreement: %v", err)
	}
	if accepted.SignatureA == "" {
		t.Fatal("accepted agreement should have OrgA signature")
	}
	if accepted.SignatureB == "" {
		t.Fatal("accepted agreement should have OrgB signature")
	}

	// Verify the full agreement from either side.
	if err := protocolA.VerifyAgreement(accepted); err != nil {
		t.Fatalf("VerifyAgreement from A: %v", err)
	}
	if err := protocolB.VerifyAgreement(accepted); err != nil {
		t.Fatalf("VerifyAgreement from B: %v", err)
	}
}

func TestFederationProtocol_VerifyAgreement_Valid(t *testing.T) {
	now := time.Date(2026, 4, 12, 10, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	protocolA, protocolB, _, _ := setupProtocolPair(t, clock)

	proposal, err := protocolA.ProposeAgreement(protocolB.localOrg, []string{"READ"}, 1*time.Hour)
	if err != nil {
		t.Fatalf("ProposeAgreement: %v", err)
	}
	accepted, err := protocolB.AcceptAgreement(proposal)
	if err != nil {
		t.Fatalf("AcceptAgreement: %v", err)
	}

	// Verification should succeed.
	if err := protocolA.VerifyAgreement(accepted); err != nil {
		t.Fatalf("VerifyAgreement: %v", err)
	}
}

func TestFederationProtocol_ExpiredAgreement(t *testing.T) {
	now := time.Date(2026, 4, 12, 10, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	protocolA, protocolB, _, _ := setupProtocolPair(t, clock)

	proposal, err := protocolA.ProposeAgreement(protocolB.localOrg, []string{"READ"}, 1*time.Hour)
	if err != nil {
		t.Fatalf("ProposeAgreement: %v", err)
	}

	accepted, err := protocolB.AcceptAgreement(proposal)
	if err != nil {
		t.Fatalf("AcceptAgreement: %v", err)
	}

	// Advance clock past expiry.
	expired := now.Add(2 * time.Hour)
	protocolA.clock = func() time.Time { return expired }

	err = protocolA.VerifyAgreement(accepted)
	if err == nil {
		t.Fatal("VerifyAgreement should fail for expired agreement")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("error should mention expiry, got: %v", err)
	}
}

func TestFederationProtocol_ExpiredProposal_AcceptFails(t *testing.T) {
	now := time.Date(2026, 4, 12, 10, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	protocolA, protocolB, _, _ := setupProtocolPair(t, clock)

	proposal, err := protocolA.ProposeAgreement(protocolB.localOrg, []string{"READ"}, 1*time.Hour)
	if err != nil {
		t.Fatalf("ProposeAgreement: %v", err)
	}

	// Advance clock past expiry before accept.
	expired := now.Add(2 * time.Hour)
	protocolB.clock = func() time.Time { return expired }

	_, err = protocolB.AcceptAgreement(proposal)
	if err == nil {
		t.Fatal("AcceptAgreement should fail for expired proposal")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("error should mention expiry, got: %v", err)
	}
}

func TestFederationProtocol_RevokedOrg(t *testing.T) {
	now := time.Date(2026, 4, 12, 10, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	protocolA, protocolB, _, _ := setupProtocolPair(t, clock)

	proposal, err := protocolA.ProposeAgreement(protocolB.localOrg, []string{"READ"}, 1*time.Hour)
	if err != nil {
		t.Fatalf("ProposeAgreement: %v", err)
	}

	// Revoke OrgA before OrgB accepts.
	if err := protocolB.trustStore.Revoke("org-alpha"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	_, err = protocolB.AcceptAgreement(proposal)
	if err == nil {
		t.Fatal("AcceptAgreement should fail for revoked OrgA")
	}
	if !strings.Contains(err.Error(), "not trusted") {
		t.Errorf("error should mention trust, got: %v", err)
	}
}

func TestFederationProtocol_RevokedOrg_VerifyFails(t *testing.T) {
	now := time.Date(2026, 4, 12, 10, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	protocolA, protocolB, _, _ := setupProtocolPair(t, clock)

	proposal, err := protocolA.ProposeAgreement(protocolB.localOrg, []string{"READ"}, 1*time.Hour)
	if err != nil {
		t.Fatalf("ProposeAgreement: %v", err)
	}
	accepted, err := protocolB.AcceptAgreement(proposal)
	if err != nil {
		t.Fatalf("AcceptAgreement: %v", err)
	}

	// Revoke OrgB after agreement is signed but before verification.
	if err := protocolA.trustStore.Revoke("org-beta"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	err = protocolA.VerifyAgreement(accepted)
	if err == nil {
		t.Fatal("VerifyAgreement should fail for revoked OrgB")
	}
	if !strings.Contains(err.Error(), "not trusted") {
		t.Errorf("error should mention trust, got: %v", err)
	}
}

func TestFederationProtocol_Propose_EmptyCapabilities(t *testing.T) {
	now := time.Date(2026, 4, 12, 10, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	protocolA, _, _, orgB := setupProtocolPair(t, clock)

	_, err := protocolA.ProposeAgreement(orgB, nil, 1*time.Hour)
	if err == nil {
		t.Fatal("ProposeAgreement should fail with empty capabilities")
	}
}

func TestFederationProtocol_Propose_SelfFederation(t *testing.T) {
	now := time.Date(2026, 4, 12, 10, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	protocolA, _, orgA, _ := setupProtocolPair(t, clock)

	_, err := protocolA.ProposeAgreement(orgA, []string{"READ"}, 1*time.Hour)
	if err == nil {
		t.Fatal("ProposeAgreement should fail for self-federation")
	}
	if !strings.Contains(err.Error(), "self") {
		t.Errorf("error should mention self, got: %v", err)
	}
}

func TestFederationProtocol_Accept_WrongOrg(t *testing.T) {
	now := time.Date(2026, 4, 12, 10, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	protocolA, _, _, orgB := setupProtocolPair(t, clock)

	proposal, err := protocolA.ProposeAgreement(orgB, []string{"READ"}, 1*time.Hour)
	if err != nil {
		t.Fatalf("ProposeAgreement: %v", err)
	}

	// OrgA tries to accept its own proposal (it should be OrgB).
	_, err = protocolA.AcceptAgreement(proposal)
	if err == nil {
		t.Fatal("AcceptAgreement should fail when local org is not OrgB")
	}
}

func TestFederationProtocol_Verify_MissingSignature(t *testing.T) {
	now := time.Date(2026, 4, 12, 10, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	protocolA, _, _, orgB := setupProtocolPair(t, clock)

	proposal, err := protocolA.ProposeAgreement(orgB, []string{"READ"}, 1*time.Hour)
	if err != nil {
		t.Fatalf("ProposeAgreement: %v", err)
	}

	// Proposal only has SignatureA, not SignatureB.
	err = protocolA.VerifyAgreement(proposal)
	if err == nil {
		t.Fatal("VerifyAgreement should fail with missing OrgB signature")
	}
	if !strings.Contains(err.Error(), "missing OrgB signature") {
		t.Errorf("error should mention missing OrgB signature, got: %v", err)
	}
}

func TestFederationProtocol_Verify_NilAgreement(t *testing.T) {
	now := time.Date(2026, 4, 12, 10, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	protocolA, _, _, _ := setupProtocolPair(t, clock)

	if err := protocolA.VerifyAgreement(nil); err == nil {
		t.Fatal("VerifyAgreement should fail for nil agreement")
	}
}

func TestFederationProtocol_CapabilitiesSorted(t *testing.T) {
	now := time.Date(2026, 4, 12, 10, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	protocolA, _, _, orgB := setupProtocolPair(t, clock)

	// Pass capabilities in unsorted order.
	proposal, err := protocolA.ProposeAgreement(orgB, []string{"WRITE", "EXECUTE", "READ"}, 1*time.Hour)
	if err != nil {
		t.Fatalf("ProposeAgreement: %v", err)
	}

	// Capabilities should be sorted in the proposal.
	expected := []string{"EXECUTE", "READ", "WRITE"}
	if len(proposal.Capabilities) != len(expected) {
		t.Fatalf("capabilities length = %d, want %d", len(proposal.Capabilities), len(expected))
	}
	for i, cap := range proposal.Capabilities {
		if cap != expected[i] {
			t.Errorf("capabilities[%d] = %q, want %q", i, cap, expected[i])
		}
	}
}
