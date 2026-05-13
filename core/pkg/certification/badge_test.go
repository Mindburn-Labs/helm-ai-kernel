package certification

import (
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/vcredentials"
)

func newTestBadgeIssuer(t *testing.T) *BadgeIssuer {
	t.Helper()

	signer, err := crypto.NewEd25519Signer("test-cert-key")
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	vcIssuer := vcredentials.NewIssuerWithClock(
		"did:helm:test-instance",
		"HELM Test Instance",
		signer,
		fixedClock,
	)

	framework := NewFramework().WithClock(fixedClock)

	return NewBadgeIssuer(vcIssuer, framework)
}

func TestBadgeIssuer_IssueBadge(t *testing.T) {
	issuer := newTestBadgeIssuer(t)

	scores := CertificationScores{
		TrustScore:      600,
		ComplianceScore: 80,
		ObservationDays: 30,
		ViolationCount:  3,
	}

	vc, result, err := issuer.IssueBadge(
		"agent-certified",
		"did:agent:certified-001",
		scores,
		24*time.Hour,
	)
	if err != nil {
		t.Fatalf("IssueBadge failed: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if !result.Passed {
		t.Fatalf("expected agent to pass certification: %s", result.Reason)
	}
	if vc == nil {
		t.Fatal("expected non-nil VC for certified agent")
	}

	// Verify VC structure.
	if vc.CredentialSubject.ID != "did:agent:certified-001" {
		t.Fatalf("expected agent DID in VC subject, got %s", vc.CredentialSubject.ID)
	}
	if vc.Proof == nil {
		t.Fatal("expected VC to have cryptographic proof")
	}
	if vc.Proof.ProofValue == "" {
		t.Fatal("expected non-empty proof value")
	}
}

func TestBadgeIssuer_NoBadgeOnFail(t *testing.T) {
	issuer := newTestBadgeIssuer(t)

	scores := CertificationScores{
		TrustScore:      100,
		ComplianceScore: 20,
		ObservationDays: 1,
		ViolationCount:  50,
	}

	vc, result, err := issuer.IssueBadge(
		"agent-failed",
		"did:agent:failed-001",
		scores,
		24*time.Hour,
	)
	if err != nil {
		t.Fatalf("IssueBadge returned unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result even on failure")
	}
	if result.Passed {
		t.Fatal("expected agent to fail certification")
	}
	if vc != nil {
		t.Fatal("expected nil VC for failed agent")
	}
	if result.Reason == "" {
		t.Fatal("expected failure reason")
	}
}

func TestBadgeIssuer_BadgeContainsLevel(t *testing.T) {
	issuer := newTestBadgeIssuer(t)

	// Gold-level scores.
	scores := CertificationScores{
		TrustScore:      750,
		ComplianceScore: 92,
		ObservationDays: 65,
		ViolationCount:  1,
		HasAIBOM:        true,
	}

	vc, result, err := issuer.IssueBadge(
		"agent-gold-badge",
		"did:agent:gold-001",
		scores,
		7*24*time.Hour,
	)
	if err != nil {
		t.Fatalf("IssueBadge failed: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected pass: %s", result.Reason)
	}
	if result.Level != CertGold {
		t.Fatalf("expected GOLD level, got %s", result.Level)
	}
	if vc == nil {
		t.Fatal("expected non-nil VC")
	}

	// Verify the VC capability action contains the certification level.
	if len(vc.CredentialSubject.Capabilities) == 0 {
		t.Fatal("expected at least one capability in badge VC")
	}

	action := vc.CredentialSubject.Capabilities[0].Action
	if !strings.Contains(action, "GOLD") {
		t.Fatalf("expected badge action to contain GOLD, got %s", action)
	}
	expectedAction := "HELM_CERTIFIED_GOLD"
	if action != expectedAction {
		t.Fatalf("expected action %s, got %s", expectedAction, action)
	}

	// Verify constraints encode the trust floor and privilege tier.
	if vc.CredentialSubject.Constraints.TrustFloor != scores.TrustScore {
		t.Fatalf("expected trust floor %d, got %d", scores.TrustScore, vc.CredentialSubject.Constraints.TrustFloor)
	}
	if vc.CredentialSubject.Constraints.PrivilegeTier != string(CertGold) {
		t.Fatalf("expected privilege tier GOLD, got %s", vc.CredentialSubject.Constraints.PrivilegeTier)
	}
}

func TestBadgeIssuer_PlatinumBadge(t *testing.T) {
	issuer := newTestBadgeIssuer(t)

	scores := CertificationScores{
		TrustScore:      900,
		ComplianceScore: 99,
		ObservationDays: 120,
		ViolationCount:  0,
		HasAIBOM:        true,
		HasZKProof:      true,
	}

	vc, result, err := issuer.IssueBadge(
		"agent-platinum-badge",
		"did:agent:platinum-001",
		scores,
		30*24*time.Hour,
	)
	if err != nil {
		t.Fatalf("IssueBadge failed: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected pass: %s", result.Reason)
	}
	if result.Level != CertPlatinum {
		t.Fatalf("expected PLATINUM, got %s", result.Level)
	}
	if vc == nil {
		t.Fatal("expected non-nil VC")
	}

	action := vc.CredentialSubject.Capabilities[0].Action
	if action != "HELM_CERTIFIED_PLATINUM" {
		t.Fatalf("expected HELM_CERTIFIED_PLATINUM, got %s", action)
	}
}

func TestBadgeIssuer_VCHasValidDuration(t *testing.T) {
	issuer := newTestBadgeIssuer(t)

	scores := CertificationScores{
		TrustScore:      500,
		ComplianceScore: 70,
		ObservationDays: 14,
		ViolationCount:  2,
	}

	duration := 48 * time.Hour
	vc, _, err := issuer.IssueBadge(
		"agent-duration",
		"did:agent:duration-001",
		scores,
		duration,
	)
	if err != nil {
		t.Fatalf("IssueBadge failed: %v", err)
	}
	if vc == nil {
		t.Fatal("expected non-nil VC")
	}

	expectedUntil := fixedClock().Add(duration)
	if !vc.ValidUntil.Equal(expectedUntil) {
		t.Fatalf("expected ValidUntil %v, got %v", expectedUntil, vc.ValidUntil)
	}
}
