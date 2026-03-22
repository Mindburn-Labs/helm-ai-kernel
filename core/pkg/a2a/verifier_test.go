package a2a

import (
	"context"
	"testing"
	"time"
)

func testEnvelope() *Envelope {
	env := &Envelope{
		EnvelopeID:    "a2a-test-001",
		SchemaVersion: CurrentVersion,
		OriginAgentID: "agent-alpha",
		TargetAgentID: "agent-beta",
		RequiredFeatures: []Feature{FeatureEvidenceExport},
		OfferedFeatures:  []Feature{FeatureEvidenceExport, FeatureProofGraphSync, FeatureMeteringReceipts},
		PayloadHash:      "sha256:abc123",
		CreatedAt:        time.Now().UTC(),
		ExpiresAt:        time.Now().Add(1 * time.Hour).UTC(),
	}
	SignEnvelope(env, "key-001", "ed25519", "agent-alpha")
	return env
}

func testVerifier() *DefaultVerifier {
	v := NewDefaultVerifier()
	v.RegisterKey(TrustedKey{
		KeyID:     "key-001",
		AgentID:   "agent-alpha",
		Algorithm: "ed25519",
		PublicKey: "base64-test-key",
		Active:    true,
	})
	return v
}

func TestNegotiateAccepts(t *testing.T) {
	v := testVerifier()
	env := testEnvelope()
	local := []Feature{FeatureEvidenceExport, FeatureProofGraphSync}

	result, err := v.Negotiate(context.Background(), env, local)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Accepted {
		t.Fatalf("expected accepted, got deny: %s (%s)", result.DenyReason, result.DenyDetails)
	}
	if len(result.AgreedFeatures) != 2 {
		t.Fatalf("expected 2 agreed features, got %d", len(result.AgreedFeatures))
	}
}

func TestNegotiateRejectsExpired(t *testing.T) {
	v := testVerifier()
	env := testEnvelope()
	env.ExpiresAt = time.Now().Add(-1 * time.Hour)
	SignEnvelope(env, "key-001", "ed25519", "agent-alpha")

	result, err := v.Negotiate(context.Background(), env, []Feature{FeatureEvidenceExport})
	if err != nil {
		t.Fatal(err)
	}
	if result.Accepted {
		t.Fatal("expected expired envelope to be rejected")
	}
	if result.DenyReason != DenyVersionIncompatible {
		t.Fatalf("expected VERSION_INCOMPATIBLE for expiry, got %s", result.DenyReason)
	}
}

func TestNegotiateRejectsIncompatibleVersion(t *testing.T) {
	v := testVerifier()
	env := testEnvelope()
	env.SchemaVersion = SchemaVersion{Major: 99, Minor: 0, Patch: 0}
	SignEnvelope(env, "key-001", "ed25519", "agent-alpha")

	result, err := v.Negotiate(context.Background(), env, []Feature{FeatureEvidenceExport})
	if err != nil {
		t.Fatal(err)
	}
	if result.Accepted {
		t.Fatal("expected version mismatch to be rejected")
	}
}

func TestNegotiateRejectsMissingFeature(t *testing.T) {
	v := testVerifier()
	env := testEnvelope()
	env.RequiredFeatures = []Feature{FeatureDisputeReplay}
	SignEnvelope(env, "key-001", "ed25519", "agent-alpha")

	// Local agent doesn't support DISPUTE_REPLAY
	result, err := v.Negotiate(context.Background(), env, []Feature{FeatureEvidenceExport})
	if err != nil {
		t.Fatal(err)
	}
	if result.Accepted {
		t.Fatal("expected missing feature to be rejected")
	}
	if result.DenyReason != DenyFeatureMissing {
		t.Fatalf("expected FEATURE_MISSING, got %s", result.DenyReason)
	}
}

func TestNegotiateRejectsPolicyViolation(t *testing.T) {
	v := testVerifier()
	v.AddPolicyRule(PolicyRule{
		RuleID:         "deny-pg-sync",
		OriginAgent:    "agent-alpha",
		TargetAgent:    "*",
		DeniedFeatures: []Feature{FeatureProofGraphSync},
		Action:         PolicyDeny,
	})

	env := testEnvelope()
	env.RequiredFeatures = []Feature{FeatureProofGraphSync}
	SignEnvelope(env, "key-001", "ed25519", "agent-alpha")

	result, err := v.Negotiate(context.Background(), env, []Feature{FeatureProofGraphSync})
	if err != nil {
		t.Fatal(err)
	}
	if result.Accepted {
		t.Fatal("expected policy violation to be rejected")
	}
	if result.DenyReason != DenyPolicyViolation {
		t.Fatalf("expected POLICY_VIOLATION, got %s", result.DenyReason)
	}
}

func TestVerifySignatureValid(t *testing.T) {
	v := testVerifier()
	env := testEnvelope()

	valid, err := v.VerifySignature(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if !valid {
		t.Fatal("expected valid signature")
	}
}

func TestVerifySignatureRejectsUnknownKey(t *testing.T) {
	v := NewDefaultVerifier() // No keys registered
	env := testEnvelope()

	valid, err := v.VerifySignature(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Fatal("expected unknown key to fail verification")
	}
}

func TestVerifySignatureRejectsInactiveKey(t *testing.T) {
	v := NewDefaultVerifier()
	v.RegisterKey(TrustedKey{
		KeyID:     "key-001",
		AgentID:   "agent-alpha",
		Algorithm: "ed25519",
		Active:    false, // Inactive
	})
	env := testEnvelope()

	valid, err := v.VerifySignature(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Fatal("expected inactive key to fail verification")
	}
}

func TestVerifySignatureRejectsTamperedEnvelope(t *testing.T) {
	v := testVerifier()
	env := testEnvelope()
	env.PayloadHash = "sha256:tampered" // Tamper after signing

	valid, err := v.VerifySignature(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Fatal("expected tampered envelope to fail verification")
	}
}

func TestEnvelopeHashDeterminism(t *testing.T) {
	env := testEnvelope()
	h1 := ComputeEnvelopeHash(env)
	h2 := ComputeEnvelopeHash(env)
	if h1 != h2 {
		t.Fatalf("envelope hash not deterministic: %s vs %s", h1, h2)
	}
}
