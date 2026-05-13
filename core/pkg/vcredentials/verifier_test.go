package vcredentials

import (
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

func issueTestVC(t *testing.T, signer *crypto.Ed25519Signer, now time.Time) *VerifiableCredential {
	t.Helper()
	issuer := NewIssuerWithClock("did:helm:instance:test", "Test Instance", signer, fixedClock(now))
	vc, err := issuer.Issue("urn:uuid:verify-test", testSubject(), 24*time.Hour)
	if err != nil {
		t.Fatalf("issue test VC: %v", err)
	}
	return vc
}

func TestVerifier_ValidVC(t *testing.T) {
	signer := testSigner(t)
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	vc := issueTestVC(t, signer, now)

	// Verify at a time within the validity window.
	verifyTime := now.Add(1 * time.Hour)
	verifier := NewVerifierWithClock([]string{"did:helm:instance:test"}, fixedClock(verifyTime))

	err := verifier.Verify(vc, signer.PublicKeyBytes())
	if err != nil {
		t.Fatalf("Verify failed for valid VC: %v", err)
	}
}

func TestVerifier_UntrustedIssuer(t *testing.T) {
	signer := testSigner(t)
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	vc := issueTestVC(t, signer, now)

	// Verifier does not trust the issuer DID.
	verifyTime := now.Add(1 * time.Hour)
	verifier := NewVerifierWithClock([]string{"did:helm:instance:other"}, fixedClock(verifyTime))

	err := verifier.Verify(vc, signer.PublicKeyBytes())
	if err == nil {
		t.Fatal("expected error for untrusted issuer")
	}
}

func TestVerifier_Expired(t *testing.T) {
	signer := testSigner(t)
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	vc := issueTestVC(t, signer, now)

	// Verify after the credential has expired (validDuration was 24h).
	verifyTime := now.Add(48 * time.Hour)
	verifier := NewVerifierWithClock([]string{"did:helm:instance:test"}, fixedClock(verifyTime))

	err := verifier.Verify(vc, signer.PublicKeyBytes())
	if err == nil {
		t.Fatal("expected error for expired VC")
	}
}

func TestVerifier_NotYetValid(t *testing.T) {
	signer := testSigner(t)
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	vc := issueTestVC(t, signer, now)

	// Verify before the credential's ValidFrom.
	verifyTime := now.Add(-1 * time.Hour)
	verifier := NewVerifierWithClock([]string{"did:helm:instance:test"}, fixedClock(verifyTime))

	err := verifier.Verify(vc, signer.PublicKeyBytes())
	if err == nil {
		t.Fatal("expected error for not-yet-valid VC")
	}
}

func TestVerifier_TamperedVC(t *testing.T) {
	signer := testSigner(t)
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	vc := issueTestVC(t, signer, now)

	// Tamper with the credential after signing.
	vc.CredentialSubject.AgentName = "Evil Agent"

	verifyTime := now.Add(1 * time.Hour)
	verifier := NewVerifierWithClock([]string{"did:helm:instance:test"}, fixedClock(verifyTime))

	err := verifier.Verify(vc, signer.PublicKeyBytes())
	if err == nil {
		t.Fatal("expected error for tampered VC")
	}
}

func TestVerifier_WrongKey(t *testing.T) {
	signer := testSigner(t)
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	vc := issueTestVC(t, signer, now)

	// Create a different key pair for verification.
	otherSigner, err := crypto.NewEd25519Signer("other-key")
	if err != nil {
		t.Fatalf("failed to create other signer: %v", err)
	}

	verifyTime := now.Add(1 * time.Hour)
	verifier := NewVerifierWithClock([]string{"did:helm:instance:test"}, fixedClock(verifyTime))

	err = verifier.Verify(vc, otherSigner.PublicKeyBytes())
	if err == nil {
		t.Fatal("expected error for wrong public key")
	}
}

func TestVerifier_NoProof(t *testing.T) {
	signer := testSigner(t)
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	vc := issueTestVC(t, signer, now)

	// Strip the proof.
	vc.Proof = nil

	verifyTime := now.Add(1 * time.Hour)
	verifier := NewVerifierWithClock([]string{"did:helm:instance:test"}, fixedClock(verifyTime))

	err := verifier.Verify(vc, signer.PublicKeyBytes())
	if err == nil {
		t.Fatal("expected error for missing proof")
	}
}

func TestVerifier_MissingContext(t *testing.T) {
	signer := testSigner(t)
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	vc := issueTestVC(t, signer, now)

	// Remove the HELM context (breaks context check before sig check).
	vc.Context = []string{ContextW3CCredentials}

	verifyTime := now.Add(1 * time.Hour)
	verifier := NewVerifierWithClock([]string{"did:helm:instance:test"}, fixedClock(verifyTime))

	err := verifier.Verify(vc, signer.PublicKeyBytes())
	if err == nil {
		t.Fatal("expected error for missing HELM context")
	}
}

func TestVerifier_CheckCapability(t *testing.T) {
	signer := testSigner(t)
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)

	verifiedAt := time.Date(2026, 4, 12, 0, 0, 0, 0, time.UTC)
	subject := AgentCapabilitySubject{
		ID: "did:helm:agent:cap-check",
		Capabilities: []CapabilityClaim{
			{Action: "EXECUTE_TOOL", Resource: "github.com/repos", Verified: true, VerifiedAt: verifiedAt},
			{Action: "SEND_EMAIL", Resource: "smtp.corp.example", Verified: true, VerifiedAt: verifiedAt},
			{Action: "READ_DATABASE", Resource: "pg:analytics", Verified: false, VerifiedAt: verifiedAt},
		},
	}

	issuer := NewIssuerWithClock("did:helm:instance:test", "Test", signer, fixedClock(now))
	vc, err := issuer.Issue("urn:uuid:cap-check", subject, 24*time.Hour)
	if err != nil {
		t.Fatalf("Issue failed: %v", err)
	}

	verifier := NewVerifier([]string{"did:helm:instance:test"})

	// Exact match: action + resource.
	if !verifier.CheckCapability(vc, "EXECUTE_TOOL", "github.com/repos") {
		t.Error("expected EXECUTE_TOOL on github.com/repos to be granted")
	}

	// Action match, any resource (empty resource query).
	if !verifier.CheckCapability(vc, "SEND_EMAIL", "") {
		t.Error("expected SEND_EMAIL with empty resource query to match")
	}

	// Action exists but resource mismatch.
	if verifier.CheckCapability(vc, "EXECUTE_TOOL", "slack.com/channels") {
		t.Error("expected EXECUTE_TOOL on slack.com/channels to NOT be granted")
	}

	// Action does not exist at all.
	if verifier.CheckCapability(vc, "DELETE_DATABASE", "") {
		t.Error("expected DELETE_DATABASE to NOT be granted")
	}

	// Unverified capability should not be granted.
	if verifier.CheckCapability(vc, "READ_DATABASE", "pg:analytics") {
		t.Error("expected unverified READ_DATABASE to NOT be granted")
	}
}

func TestVerifier_CheckCapability_UnrestrictedResource(t *testing.T) {
	signer := testSigner(t)
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)

	verifiedAt := time.Date(2026, 4, 12, 0, 0, 0, 0, time.UTC)
	subject := AgentCapabilitySubject{
		ID: "did:helm:agent:unrestricted",
		Capabilities: []CapabilityClaim{
			// No resource means unrestricted scope for this action.
			{Action: "EXECUTE_TOOL", Verified: true, VerifiedAt: verifiedAt},
		},
	}

	issuer := NewIssuerWithClock("did:helm:instance:test", "Test", signer, fixedClock(now))
	vc, err := issuer.Issue("urn:uuid:unrestricted", subject, 24*time.Hour)
	if err != nil {
		t.Fatalf("Issue failed: %v", err)
	}

	verifier := NewVerifier([]string{"did:helm:instance:test"})

	// Unrestricted resource in claim should match any specific resource query.
	if !verifier.CheckCapability(vc, "EXECUTE_TOOL", "any-resource") {
		t.Error("expected unrestricted EXECUTE_TOOL to match any resource")
	}
	if !verifier.CheckCapability(vc, "EXECUTE_TOOL", "") {
		t.Error("expected unrestricted EXECUTE_TOOL to match empty resource")
	}
}
