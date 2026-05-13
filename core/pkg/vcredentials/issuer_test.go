package vcredentials

import (
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

func fixedClock(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

func testSigner(t *testing.T) *crypto.Ed25519Signer {
	t.Helper()
	s, err := crypto.NewEd25519Signer("test-key-1")
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}
	return s
}

func testSubject() AgentCapabilitySubject {
	return AgentCapabilitySubject{
		ID:        "did:helm:agent:test-agent-001",
		AgentName: "Test Agent",
		Capabilities: []CapabilityClaim{
			{
				Action:     "EXECUTE_TOOL",
				Resource:   "github.com/repos",
				Verified:   true,
				VerifiedAt: time.Date(2026, 4, 12, 0, 0, 0, 0, time.UTC),
			},
		},
		Constraints: CapabilityConstraints{
			RiskCeiling:   "MEDIUM",
			PrivilegeTier: "STANDARD",
		},
	}
}

func TestIssuer_Issue(t *testing.T) {
	signer := testSigner(t)
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	issuer := NewIssuerWithClock("did:helm:instance:prod-1", "HELM Production", signer, fixedClock(now))

	vc, err := issuer.Issue("urn:uuid:test-vc-001", testSubject(), 24*time.Hour)
	if err != nil {
		t.Fatalf("Issue failed: %v", err)
	}

	if vc.ID != "urn:uuid:test-vc-001" {
		t.Errorf("ID = %q, want %q", vc.ID, "urn:uuid:test-vc-001")
	}
	if vc.Issuer.ID != "did:helm:instance:prod-1" {
		t.Errorf("Issuer.ID = %q, want %q", vc.Issuer.ID, "did:helm:instance:prod-1")
	}
	if vc.Issuer.Name != "HELM Production" {
		t.Errorf("Issuer.Name = %q, want %q", vc.Issuer.Name, "HELM Production")
	}
	if vc.CredentialSubject.ID != "did:helm:agent:test-agent-001" {
		t.Errorf("Subject.ID = %q, want agent DID", vc.CredentialSubject.ID)
	}
	if vc.CredentialSubject.AgentName != "Test Agent" {
		t.Errorf("Subject.AgentName = %q, want %q", vc.CredentialSubject.AgentName, "Test Agent")
	}
	if len(vc.CredentialSubject.Capabilities) != 1 {
		t.Fatalf("expected 1 capability, got %d", len(vc.CredentialSubject.Capabilities))
	}
	if vc.CredentialSubject.Capabilities[0].Action != "EXECUTE_TOOL" {
		t.Errorf("capability action = %q, want EXECUTE_TOOL", vc.CredentialSubject.Capabilities[0].Action)
	}
	if vc.CredentialSubject.Constraints.RiskCeiling != "MEDIUM" {
		t.Errorf("constraints.RiskCeiling = %q, want MEDIUM", vc.CredentialSubject.Constraints.RiskCeiling)
	}
}

func TestIssuer_Sign(t *testing.T) {
	signer := testSigner(t)
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	issuer := NewIssuerWithClock("did:helm:instance:prod-1", "HELM Production", signer, fixedClock(now))

	vc, err := issuer.Issue("urn:uuid:test-vc-002", testSubject(), 24*time.Hour)
	if err != nil {
		t.Fatalf("Issue failed: %v", err)
	}

	if vc.Proof == nil {
		t.Fatal("Proof is nil, expected signed credential")
	}
	if vc.Proof.Type != ProofTypeEd25519 {
		t.Errorf("Proof.Type = %q, want %q", vc.Proof.Type, ProofTypeEd25519)
	}
	if vc.Proof.ProofPurpose != ProofPurposeAssertion {
		t.Errorf("Proof.ProofPurpose = %q, want %q", vc.Proof.ProofPurpose, ProofPurposeAssertion)
	}
	if vc.Proof.VerificationMethod != "did:helm:instance:prod-1#key-1" {
		t.Errorf("Proof.VerificationMethod = %q, want did:helm:instance:prod-1#key-1", vc.Proof.VerificationMethod)
	}
	if vc.Proof.ProofValue == "" {
		t.Error("Proof.ProofValue is empty")
	}
	if !vc.Proof.Created.Equal(now) {
		t.Errorf("Proof.Created = %v, want %v", vc.Proof.Created, now)
	}
}

func TestIssuer_Contexts(t *testing.T) {
	signer := testSigner(t)
	issuer := NewIssuer("did:helm:instance:ctx-test", "Context Test", signer)

	vc, err := issuer.Issue("urn:uuid:test-vc-ctx", testSubject(), time.Hour)
	if err != nil {
		t.Fatalf("Issue failed: %v", err)
	}

	if len(vc.Context) != 2 {
		t.Fatalf("expected 2 contexts, got %d", len(vc.Context))
	}
	if vc.Context[0] != ContextW3CCredentials {
		t.Errorf("Context[0] = %q, want W3C VC context", vc.Context[0])
	}
	if vc.Context[1] != ContextHELMAgent {
		t.Errorf("Context[1] = %q, want HELM agent context", vc.Context[1])
	}

	if len(vc.Type) != 2 {
		t.Fatalf("expected 2 types, got %d", len(vc.Type))
	}
	if vc.Type[0] != TypeVerifiableCredential {
		t.Errorf("Type[0] = %q, want %q", vc.Type[0], TypeVerifiableCredential)
	}
	if vc.Type[1] != TypeAgentCapabilityCredential {
		t.Errorf("Type[1] = %q, want %q", vc.Type[1], TypeAgentCapabilityCredential)
	}
}

func TestIssuer_Expiry(t *testing.T) {
	signer := testSigner(t)
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	issuer := NewIssuerWithClock("did:helm:instance:expiry-test", "Expiry Test", signer, fixedClock(now))

	vc, err := issuer.Issue("urn:uuid:test-vc-expiry", testSubject(), 48*time.Hour)
	if err != nil {
		t.Fatalf("Issue failed: %v", err)
	}

	if !vc.ValidFrom.Equal(now) {
		t.Errorf("ValidFrom = %v, want %v", vc.ValidFrom, now)
	}
	expectedExpiry := now.Add(48 * time.Hour)
	if !vc.ValidUntil.Equal(expectedExpiry) {
		t.Errorf("ValidUntil = %v, want %v", vc.ValidUntil, expectedExpiry)
	}
}

func TestIssuer_MultipleCaps(t *testing.T) {
	signer := testSigner(t)
	issuer := NewIssuer("did:helm:instance:multi-test", "Multi Test", signer)

	verifiedAt := time.Date(2026, 4, 12, 0, 0, 0, 0, time.UTC)
	subject := AgentCapabilitySubject{
		ID:        "did:helm:agent:multi-agent",
		AgentName: "Multi-Cap Agent",
		Capabilities: []CapabilityClaim{
			{Action: "EXECUTE_TOOL", Resource: "github.com/repos", Verified: true, VerifiedAt: verifiedAt},
			{Action: "SEND_EMAIL", Resource: "smtp.corp.example", Verified: true, VerifiedAt: verifiedAt},
			{Action: "READ_DATABASE", Resource: "pg:analytics", Verified: true, VerifiedAt: verifiedAt},
		},
		Constraints: CapabilityConstraints{
			RiskCeiling:    "HIGH",
			Geofence:       []string{"US", "EU"},
			MaxBudgetCents: 500000,
			PrivilegeTier:  "ELEVATED",
			TrustFloor:     750,
		},
	}

	vc, err := issuer.Issue("urn:uuid:test-vc-multi", subject, 24*time.Hour)
	if err != nil {
		t.Fatalf("Issue failed: %v", err)
	}

	if len(vc.CredentialSubject.Capabilities) != 3 {
		t.Fatalf("expected 3 capabilities, got %d", len(vc.CredentialSubject.Capabilities))
	}

	actions := make(map[string]bool)
	for _, cap := range vc.CredentialSubject.Capabilities {
		actions[cap.Action] = true
	}
	for _, expected := range []string{"EXECUTE_TOOL", "SEND_EMAIL", "READ_DATABASE"} {
		if !actions[expected] {
			t.Errorf("missing expected capability action: %s", expected)
		}
	}

	if vc.CredentialSubject.Constraints.MaxBudgetCents != 500000 {
		t.Errorf("MaxBudgetCents = %d, want 500000", vc.CredentialSubject.Constraints.MaxBudgetCents)
	}
	if vc.CredentialSubject.Constraints.TrustFloor != 750 {
		t.Errorf("TrustFloor = %d, want 750", vc.CredentialSubject.Constraints.TrustFloor)
	}
	if len(vc.CredentialSubject.Constraints.Geofence) != 2 {
		t.Errorf("Geofence length = %d, want 2", len(vc.CredentialSubject.Constraints.Geofence))
	}
}

func TestIssuer_EmptyID(t *testing.T) {
	signer := testSigner(t)
	issuer := NewIssuer("did:helm:instance:err-test", "Error Test", signer)

	_, err := issuer.Issue("", testSubject(), time.Hour)
	if err == nil {
		t.Fatal("expected error for empty credential ID")
	}
}

func TestIssuer_EmptySubjectID(t *testing.T) {
	signer := testSigner(t)
	issuer := NewIssuer("did:helm:instance:err-test", "Error Test", signer)

	subject := testSubject()
	subject.ID = ""
	_, err := issuer.Issue("urn:uuid:test", subject, time.Hour)
	if err == nil {
		t.Fatal("expected error for empty subject ID")
	}
}

func TestIssuer_NoCaps(t *testing.T) {
	signer := testSigner(t)
	issuer := NewIssuer("did:helm:instance:err-test", "Error Test", signer)

	subject := AgentCapabilitySubject{
		ID:           "did:helm:agent:nocap",
		Capabilities: nil,
	}
	_, err := issuer.Issue("urn:uuid:test", subject, time.Hour)
	if err == nil {
		t.Fatal("expected error for empty capabilities")
	}
}

func TestIssuer_ZeroDuration(t *testing.T) {
	signer := testSigner(t)
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	issuer := NewIssuerWithClock("did:helm:instance:zero-dur", "Zero Duration", signer, fixedClock(now))

	vc, err := issuer.Issue("urn:uuid:test-zero-dur", testSubject(), 0)
	if err != nil {
		t.Fatalf("Issue failed: %v", err)
	}

	if !vc.ValidUntil.IsZero() {
		t.Errorf("ValidUntil should be zero for zero duration, got %v", vc.ValidUntil)
	}
}
