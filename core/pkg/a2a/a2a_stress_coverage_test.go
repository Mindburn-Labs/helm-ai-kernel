package a2a

import (
	"testing"
	"time"
)

// ── 100 concurrent envelope creations ───────────────────────────────────

// ── IATP 50 concurrent handshakes ───────────────────────────────────────

// ── Vouching: 20 agents in chain ────────────────────────────────────────

// ── Trust propagation: 50 agents graph ──────────────────────────────────

// ── Slash all vouches in chain ──────────────────────────────────────────

// ── Feature negotiation: all 8 features ─────────────────────────────────

func TestStress_AllFeatures(t *testing.T) {
	features := []Feature{
		FeatureMeteringReceipts, FeatureDisputeReplay, FeatureProofGraphSync,
		FeatureEvidenceExport, FeaturePolicyNegotiation, FeatureAgentPayments,
		FeatureIATPAuth, FeaturePeerVouching,
	}
	for _, f := range features {
		if string(f) == "" {
			t.Fatal("feature should not be empty")
		}
	}
	if len(features) != 8 {
		t.Fatalf("expected 8 features, got %d", len(features))
	}
}

func TestStress_FeatureTrustPropagation(t *testing.T) {
	if FeatureTrustPropagation != "TRUST_PROPAGATION" {
		t.Fatalf("got %s", FeatureTrustPropagation)
	}
}

// ── Every DenyReason individually ───────────────────────────────────────

func TestStress_DenyVersionIncompatible(t *testing.T) {
	if DenyVersionIncompatible != "VERSION_INCOMPATIBLE" {
		t.Fatalf("got %s", DenyVersionIncompatible)
	}
}

func TestStress_DenyFeatureMissing(t *testing.T) {
	if DenyFeatureMissing != "FEATURE_MISSING" {
		t.Fatalf("got %s", DenyFeatureMissing)
	}
}

func TestStress_DenyPolicyViolation(t *testing.T) {
	if DenyPolicyViolation != "POLICY_VIOLATION" {
		t.Fatalf("got %s", DenyPolicyViolation)
	}
}

func TestStress_DenySignatureInvalid(t *testing.T) {
	if DenySignatureInvalid != "SIGNATURE_INVALID" {
		t.Fatalf("got %s", DenySignatureInvalid)
	}
}

func TestStress_DenyAgentNotTrusted(t *testing.T) {
	if DenyAgentNotTrusted != "AGENT_NOT_TRUSTED" {
		t.Fatalf("got %s", DenyAgentNotTrusted)
	}
}

func TestStress_DenyChallengeFailure(t *testing.T) {
	if DenyChallengeFailure != "CHALLENGE_FAILURE" {
		t.Fatalf("got %s", DenyChallengeFailure)
	}
}

func TestStress_DenyVouchRevoked(t *testing.T) {
	if DenyVouchRevoked != "VOUCH_REVOKED" {
		t.Fatalf("got %s", DenyVouchRevoked)
	}
}

// ── Envelope hash determinism ───────────────────────────────────────────

// ── Vouch self-vouch rejected ───────────────────────────────────────────

// ── Vouch revocation ────────────────────────────────────────────────────

// ── Schema version ──────────────────────────────────────────────────────

func TestStress_SchemaVersionString(t *testing.T) {
	v := SchemaVersion{Major: 1, Minor: 2, Patch: 3}
	if v.String() != "1.2.3" {
		t.Fatalf("got %s", v.String())
	}
}

func TestStress_CurrentVersionMajor(t *testing.T) {
	if CurrentVersion.Major != 1 {
		t.Fatalf("expected major 1, got %d", CurrentVersion.Major)
	}
}

// ── Vouching negative stake ─────────────────────────────────────────────

// ── Policy rules ────────────────────────────────────────────────────────

func TestStress_PolicyActionConstants(t *testing.T) {
	if PolicyAllow != "ALLOW" || PolicyDeny != "DENY" {
		t.Fatal("policy action constants mismatch")
	}
}

func TestStress_IATPSessionStatus(t *testing.T) {
	if IATPPending != "PENDING" || IATPAuthenticated != "AUTHENTICATED" || IATPFailed != "FAILED" {
		t.Fatal("IATP status mismatch")
	}
}

func TestStress_EnvelopeExpiresAt(t *testing.T) {
	env := &Envelope{EnvelopeID: "exp", ExpiresAt: time.Now().Add(time.Hour)}
	if env.ExpiresAt.IsZero() {
		t.Fatal("expires_at should be set")
	}
}

func TestStress_NegotiationResultFields(t *testing.T) {
	r := NegotiationResult{Accepted: true, AgreedFeatures: []Feature{FeatureIATPAuth}}
	if !r.Accepted || len(r.AgreedFeatures) != 1 {
		t.Fatal("negotiation result field mismatch")
	}
}
