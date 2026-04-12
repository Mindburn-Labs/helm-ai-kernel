package a2a

import (
	"context"
	"strings"
	"testing"
	"time"
)

// ══════════════════════════════════════════════════════════════════════════════
// A2A Conformance Test Vectors
//
// These tests provide deterministic coverage of every negotiation code path:
//   - Version negotiation (semver major/minor/patch compatibility)
//   - Feature negotiation (required, offered, intersection)
//   - Signature validation (key lookup, agent binding, algorithm, tamper)
//   - Envelope completeness (missing fields → deterministic deny)
//   - Expiry handling (expired → deny)
//   - Policy enforcement (deny rules, wildcard matching)
//
// Each deny case asserts the exact DenyReason code.
// ══════════════════════════════════════════════════════════════════════════════

// --- Helpers ----------------------------------------------------------------

func staticClock(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

func baseEnvelope(now time.Time) *Envelope {
	env := &Envelope{
		EnvelopeID:       "a2a-conform-001",
		SchemaVersion:    SchemaVersion{Major: 1, Minor: 0, Patch: 0},
		OriginAgentID:    "agent-origin",
		TargetAgentID:    "agent-target",
		RequiredFeatures: []Feature{FeatureEvidenceExport},
		OfferedFeatures:  []Feature{FeatureEvidenceExport, FeatureMeteringReceipts},
		PayloadHash:      "sha256:deadbeef",
		CreatedAt:        now.Add(-5 * time.Minute),
		ExpiresAt:        now.Add(1 * time.Hour),
	}
	SignEnvelope(env, "key-origin-001", "ed25519", "agent-origin")
	return env
}

func baseVerifier(now time.Time) *DefaultVerifier {
	v := NewDefaultVerifier()
	v.WithClock(staticClock(now))
	v.RegisterKey(TrustedKey{
		KeyID:     "key-origin-001",
		AgentID:   "agent-origin",
		Algorithm: "ed25519",
		PublicKey: "base64-pubkey-origin",
		Active:    true,
	})
	return v
}

// --- Version Negotiation ----------------------------------------------------

func TestConformance_VersionNegotiation_SameMajor(t *testing.T) {
	// v1.0.0 ↔ v1.0.0 → pass
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	v := baseVerifier(now)
	env := baseEnvelope(now)
	env.SchemaVersion = SchemaVersion{Major: 1, Minor: 0, Patch: 0}
	SignEnvelope(env, "key-origin-001", "ed25519", "agent-origin")

	result, err := v.Negotiate(context.Background(), env, []Feature{FeatureEvidenceExport})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Accepted {
		t.Fatalf("expected accept for v1.0.0 ↔ v1.0.0, got deny: %s (%s)", result.DenyReason, result.DenyDetails)
	}
	if result.AgreedVersion == nil {
		t.Fatal("expected AgreedVersion to be set")
	}
	if result.AgreedVersion.Major != 1 || result.AgreedVersion.Minor != 0 || result.AgreedVersion.Patch != 0 {
		t.Fatalf("expected agreed version 1.0.0, got %s", result.AgreedVersion.String())
	}
}

func TestConformance_VersionNegotiation_DifferentMajor(t *testing.T) {
	// v1.0.0 ↔ v2.0.0 → fail with VERSION_INCOMPATIBLE
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	v := baseVerifier(now)
	env := baseEnvelope(now)
	env.SchemaVersion = SchemaVersion{Major: 2, Minor: 0, Patch: 0}
	SignEnvelope(env, "key-origin-001", "ed25519", "agent-origin")

	result, err := v.Negotiate(context.Background(), env, []Feature{FeatureEvidenceExport})
	if err != nil {
		t.Fatal(err)
	}
	if result.Accepted {
		t.Fatal("expected deny for v2.0.0 ↔ v1.0.0")
	}
	if result.DenyReason != DenyVersionIncompatible {
		t.Fatalf("expected VERSION_INCOMPATIBLE, got %s", result.DenyReason)
	}
	if !strings.Contains(result.DenyDetails, "incompatible version") {
		t.Fatalf("expected deny details to mention incompatible version, got: %s", result.DenyDetails)
	}
}

func TestConformance_VersionNegotiation_HigherMajor(t *testing.T) {
	// v99.0.0 → fail (future major version)
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	v := baseVerifier(now)
	env := baseEnvelope(now)
	env.SchemaVersion = SchemaVersion{Major: 99, Minor: 1, Patch: 5}
	SignEnvelope(env, "key-origin-001", "ed25519", "agent-origin")

	result, err := v.Negotiate(context.Background(), env, []Feature{FeatureEvidenceExport})
	if err != nil {
		t.Fatal(err)
	}
	if result.Accepted {
		t.Fatal("expected deny for future major version 99")
	}
	if result.DenyReason != DenyVersionIncompatible {
		t.Fatalf("expected VERSION_INCOMPATIBLE, got %s", result.DenyReason)
	}
}

func TestConformance_VersionNegotiation_MinorBackwardCompat(t *testing.T) {
	// v1.1.0 ↔ v1.0.0 → pass (same major, backward compatible)
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	v := baseVerifier(now)
	env := baseEnvelope(now)
	env.SchemaVersion = SchemaVersion{Major: 1, Minor: 1, Patch: 0}
	SignEnvelope(env, "key-origin-001", "ed25519", "agent-origin")

	result, err := v.Negotiate(context.Background(), env, []Feature{FeatureEvidenceExport})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Accepted {
		t.Fatalf("expected accept for v1.1.0 ↔ v1.0.0 (same major), got deny: %s", result.DenyReason)
	}
}

func TestConformance_VersionNegotiation_PatchBackwardCompat(t *testing.T) {
	// v1.0.5 ↔ v1.0.0 → pass (same major, patch difference)
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	v := baseVerifier(now)
	env := baseEnvelope(now)
	env.SchemaVersion = SchemaVersion{Major: 1, Minor: 0, Patch: 5}
	SignEnvelope(env, "key-origin-001", "ed25519", "agent-origin")

	result, err := v.Negotiate(context.Background(), env, []Feature{FeatureEvidenceExport})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Accepted {
		t.Fatalf("expected accept for v1.0.5 ↔ v1.0.0 (same major), got deny: %s", result.DenyReason)
	}
}

func TestConformance_VersionNegotiation_MajorZero(t *testing.T) {
	// v0.x.y → fail (major 0 != current major 1)
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	v := baseVerifier(now)
	env := baseEnvelope(now)
	env.SchemaVersion = SchemaVersion{Major: 0, Minor: 9, Patch: 9}
	SignEnvelope(env, "key-origin-001", "ed25519", "agent-origin")

	result, err := v.Negotiate(context.Background(), env, []Feature{FeatureEvidenceExport})
	if err != nil {
		t.Fatal(err)
	}
	if result.Accepted {
		t.Fatal("expected deny for major version 0 (pre-release)")
	}
	if result.DenyReason != DenyVersionIncompatible {
		t.Fatalf("expected VERSION_INCOMPATIBLE, got %s", result.DenyReason)
	}
}

// --- Feature Negotiation ----------------------------------------------------

func TestConformance_FeatureNegotiation_AllRequiredPresent(t *testing.T) {
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	v := baseVerifier(now)
	env := baseEnvelope(now)
	env.RequiredFeatures = []Feature{FeatureEvidenceExport, FeatureProofGraphSync}
	SignEnvelope(env, "key-origin-001", "ed25519", "agent-origin")

	local := []Feature{FeatureEvidenceExport, FeatureProofGraphSync, FeatureMeteringReceipts}
	result, err := v.Negotiate(context.Background(), env, local)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Accepted {
		t.Fatalf("expected accept when all required features present, got deny: %s", result.DenyReason)
	}
}

func TestConformance_FeatureNegotiation_MissingRequired(t *testing.T) {
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	v := baseVerifier(now)
	env := baseEnvelope(now)
	env.RequiredFeatures = []Feature{FeatureDisputeReplay}
	SignEnvelope(env, "key-origin-001", "ed25519", "agent-origin")

	// Local agent does NOT support DISPUTE_REPLAY
	local := []Feature{FeatureEvidenceExport, FeatureMeteringReceipts}
	result, err := v.Negotiate(context.Background(), env, local)
	if err != nil {
		t.Fatal(err)
	}
	if result.Accepted {
		t.Fatal("expected deny when required feature missing")
	}
	if result.DenyReason != DenyFeatureMissing {
		t.Fatalf("expected FEATURE_MISSING, got %s", result.DenyReason)
	}
	if !strings.Contains(result.DenyDetails, string(FeatureDisputeReplay)) {
		t.Fatalf("expected deny details to mention DISPUTE_REPLAY, got: %s", result.DenyDetails)
	}
}

func TestConformance_FeatureNegotiation_MultipleRequiredOneMissing(t *testing.T) {
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	v := baseVerifier(now)
	env := baseEnvelope(now)
	env.RequiredFeatures = []Feature{FeatureEvidenceExport, FeatureAgentPayments, FeaturePolicyNegotiation}
	SignEnvelope(env, "key-origin-001", "ed25519", "agent-origin")

	// Missing AGENT_PAYMENTS
	local := []Feature{FeatureEvidenceExport, FeaturePolicyNegotiation}
	result, err := v.Negotiate(context.Background(), env, local)
	if err != nil {
		t.Fatal(err)
	}
	if result.Accepted {
		t.Fatal("expected deny when one of multiple required features is missing")
	}
	if result.DenyReason != DenyFeatureMissing {
		t.Fatalf("expected FEATURE_MISSING, got %s", result.DenyReason)
	}
}

func TestConformance_FeatureNegotiation_NoRequiredFeatures(t *testing.T) {
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	v := baseVerifier(now)
	env := baseEnvelope(now)
	env.RequiredFeatures = nil
	env.OfferedFeatures = []Feature{FeatureMeteringReceipts, FeatureProofGraphSync}
	SignEnvelope(env, "key-origin-001", "ed25519", "agent-origin")

	local := []Feature{FeatureMeteringReceipts}
	result, err := v.Negotiate(context.Background(), env, local)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Accepted {
		t.Fatalf("expected accept when no required features, got deny: %s", result.DenyReason)
	}
	// Agreed = intersection of offered and local
	if len(result.AgreedFeatures) != 1 {
		t.Fatalf("expected 1 agreed feature (METERING_RECEIPTS), got %d", len(result.AgreedFeatures))
	}
	if result.AgreedFeatures[0] != FeatureMeteringReceipts {
		t.Fatalf("expected agreed feature METERING_RECEIPTS, got %s", result.AgreedFeatures[0])
	}
}

func TestConformance_FeatureNegotiation_EmptyLocalFeatures(t *testing.T) {
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	v := baseVerifier(now)
	env := baseEnvelope(now)
	env.RequiredFeatures = []Feature{FeatureEvidenceExport}
	SignEnvelope(env, "key-origin-001", "ed25519", "agent-origin")

	// Empty local features → required feature missing
	result, err := v.Negotiate(context.Background(), env, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Accepted {
		t.Fatal("expected deny when local features empty but required features exist")
	}
	if result.DenyReason != DenyFeatureMissing {
		t.Fatalf("expected FEATURE_MISSING, got %s", result.DenyReason)
	}
}

func TestConformance_FeatureNegotiation_AgreedIntersection(t *testing.T) {
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	v := baseVerifier(now)
	env := baseEnvelope(now)
	env.RequiredFeatures = nil
	env.OfferedFeatures = []Feature{FeatureEvidenceExport, FeatureProofGraphSync, FeatureIATPAuth}
	SignEnvelope(env, "key-origin-001", "ed25519", "agent-origin")

	local := []Feature{FeatureProofGraphSync, FeatureIATPAuth, FeaturePeerVouching}
	result, err := v.Negotiate(context.Background(), env, local)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Accepted {
		t.Fatalf("expected accept, got deny: %s", result.DenyReason)
	}
	// Agreed = intersection: PROOFGRAPH_SYNC, IATP_AUTH
	if len(result.AgreedFeatures) != 2 {
		t.Fatalf("expected 2 agreed features, got %d: %v", len(result.AgreedFeatures), result.AgreedFeatures)
	}
	agreedSet := make(map[Feature]bool)
	for _, f := range result.AgreedFeatures {
		agreedSet[f] = true
	}
	if !agreedSet[FeatureProofGraphSync] || !agreedSet[FeatureIATPAuth] {
		t.Fatalf("expected PROOFGRAPH_SYNC and IATP_AUTH in agreed, got %v", result.AgreedFeatures)
	}
}

func TestConformance_FeatureNegotiation_AllNineFeatures(t *testing.T) {
	// Verify all defined features can appear in negotiation
	allFeatures := []Feature{
		FeatureMeteringReceipts,
		FeatureDisputeReplay,
		FeatureProofGraphSync,
		FeatureEvidenceExport,
		FeaturePolicyNegotiation,
		FeatureAgentPayments,
		FeatureIATPAuth,
		FeaturePeerVouching,
		FeatureTrustPropagation,
	}

	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	v := baseVerifier(now)
	env := baseEnvelope(now)
	env.RequiredFeatures = allFeatures
	env.OfferedFeatures = allFeatures
	SignEnvelope(env, "key-origin-001", "ed25519", "agent-origin")

	result, err := v.Negotiate(context.Background(), env, allFeatures)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Accepted {
		t.Fatalf("expected accept when all features present locally, got deny: %s", result.DenyReason)
	}
	if len(result.AgreedFeatures) != len(allFeatures) {
		t.Fatalf("expected %d agreed features, got %d", len(allFeatures), len(result.AgreedFeatures))
	}
}

// --- Signature Validation ---------------------------------------------------

func TestConformance_Signature_Valid(t *testing.T) {
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	v := baseVerifier(now)
	env := baseEnvelope(now)

	valid, err := v.VerifySignature(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if !valid {
		t.Fatal("expected valid signature for correctly signed envelope")
	}
}

func TestConformance_Signature_UnknownKeyID(t *testing.T) {
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	v := NewDefaultVerifier()
	v.WithClock(staticClock(now))
	// No keys registered
	env := baseEnvelope(now)

	valid, err := v.VerifySignature(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Fatal("expected signature failure for unknown key ID")
	}
}

func TestConformance_Signature_KeyAgentMismatch(t *testing.T) {
	// Key is registered to agent-other but envelope is from agent-origin
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	v := NewDefaultVerifier()
	v.WithClock(staticClock(now))
	v.RegisterKey(TrustedKey{
		KeyID:     "key-origin-001",
		AgentID:   "agent-other", // Different agent than envelope origin
		Algorithm: "ed25519",
		PublicKey: "base64-pubkey",
		Active:    true,
	})
	env := baseEnvelope(now)

	valid, err := v.VerifySignature(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Fatal("expected signature failure when key agent doesn't match envelope origin")
	}
}

func TestConformance_Signature_InactiveKey(t *testing.T) {
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	v := NewDefaultVerifier()
	v.WithClock(staticClock(now))
	v.RegisterKey(TrustedKey{
		KeyID:     "key-origin-001",
		AgentID:   "agent-origin",
		Algorithm: "ed25519",
		PublicKey: "base64-pubkey",
		Active:    false, // Revoked/inactive
	})
	env := baseEnvelope(now)

	valid, err := v.VerifySignature(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Fatal("expected signature failure for inactive key")
	}
}

func TestConformance_Signature_AlgorithmMismatch(t *testing.T) {
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	v := NewDefaultVerifier()
	v.WithClock(staticClock(now))
	v.RegisterKey(TrustedKey{
		KeyID:     "key-origin-001",
		AgentID:   "agent-origin",
		Algorithm: "rsa-sha256", // Different from signature's ed25519
		PublicKey: "base64-pubkey",
		Active:    true,
	})
	env := baseEnvelope(now)

	valid, err := v.VerifySignature(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Fatal("expected signature failure when algorithm doesn't match")
	}
}

func TestConformance_Signature_TamperedPayloadHash(t *testing.T) {
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	v := baseVerifier(now)
	env := baseEnvelope(now)
	// Tamper with payload hash after signing
	env.PayloadHash = "sha256:tampered-after-sign"

	valid, err := v.VerifySignature(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Fatal("expected signature failure for tampered payload hash")
	}
}

func TestConformance_Signature_TamperedEnvelopeID(t *testing.T) {
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	v := baseVerifier(now)
	env := baseEnvelope(now)
	// Tamper with envelope ID after signing
	env.EnvelopeID = "a2a-conform-tampered"

	valid, err := v.VerifySignature(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Fatal("expected signature failure for tampered envelope ID")
	}
}

func TestConformance_Signature_TamperedTargetAgent(t *testing.T) {
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	v := baseVerifier(now)
	env := baseEnvelope(now)
	// Tamper with target agent after signing
	env.TargetAgentID = "agent-malicious"

	valid, err := v.VerifySignature(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Fatal("expected signature failure for tampered target agent")
	}
}

func TestConformance_Signature_EmptyKeyID(t *testing.T) {
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	v := baseVerifier(now)
	env := baseEnvelope(now)
	env.Signature.KeyID = ""

	valid, err := v.VerifySignature(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Fatal("expected signature failure for empty key ID")
	}
}

func TestConformance_Signature_EmptyValue(t *testing.T) {
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	v := baseVerifier(now)
	env := baseEnvelope(now)
	env.Signature.Value = ""

	valid, err := v.VerifySignature(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Fatal("expected signature failure for empty signature value")
	}
}

// --- Envelope Completeness --------------------------------------------------

func TestConformance_Envelope_MissingEnvelopeID(t *testing.T) {
	// Empty EnvelopeID → signature won't match (hash changes)
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	v := baseVerifier(now)
	env := baseEnvelope(now)
	originalSig := env.Signature.Value

	// Clear EnvelopeID — hash will differ from what was signed
	env.EnvelopeID = ""
	hash := ComputeEnvelopeHash(env)
	if hash == originalSig {
		t.Fatal("expected hash to change when EnvelopeID is cleared")
	}

	valid, err := v.VerifySignature(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Fatal("expected signature failure for missing EnvelopeID")
	}
}

func TestConformance_Envelope_MissingOriginAgent(t *testing.T) {
	// Empty OriginAgentID → key.AgentID won't match
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	v := baseVerifier(now)
	env := baseEnvelope(now)
	env.OriginAgentID = ""

	valid, err := v.VerifySignature(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Fatal("expected signature failure for missing OriginAgentID (key agent mismatch)")
	}
}

func TestConformance_Envelope_MissingPayloadHash(t *testing.T) {
	// Empty PayloadHash → hash changes, signature invalid
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	v := baseVerifier(now)
	env := baseEnvelope(now)
	env.PayloadHash = ""

	valid, err := v.VerifySignature(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Fatal("expected signature failure for missing PayloadHash")
	}
}

func TestConformance_Envelope_MissingSignature(t *testing.T) {
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	v := baseVerifier(now)
	env := baseEnvelope(now)
	env.Signature = Signature{} // Zero value — no key, no sig

	valid, err := v.VerifySignature(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Fatal("expected signature failure for missing signature")
	}
}

// --- Expiry Handling --------------------------------------------------------

func TestConformance_Expiry_ExpiredEnvelope(t *testing.T) {
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	v := baseVerifier(now)
	env := baseEnvelope(now)
	// Set expiry to 1 hour in the past
	env.ExpiresAt = now.Add(-1 * time.Hour)
	SignEnvelope(env, "key-origin-001", "ed25519", "agent-origin")

	result, err := v.Negotiate(context.Background(), env, []Feature{FeatureEvidenceExport})
	if err != nil {
		t.Fatal(err)
	}
	if result.Accepted {
		t.Fatal("expected deny for expired envelope")
	}
	if result.DenyReason != DenyVersionIncompatible {
		t.Fatalf("expected VERSION_INCOMPATIBLE for expiry, got %s", result.DenyReason)
	}
	if !strings.Contains(result.DenyDetails, "expired") {
		t.Fatalf("expected deny details to mention 'expired', got: %s", result.DenyDetails)
	}
}

func TestConformance_Expiry_JustExpired(t *testing.T) {
	// Expires exactly 1 nanosecond before now
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	v := baseVerifier(now)
	env := baseEnvelope(now)
	env.ExpiresAt = now.Add(-1 * time.Nanosecond)
	SignEnvelope(env, "key-origin-001", "ed25519", "agent-origin")

	result, err := v.Negotiate(context.Background(), env, []Feature{FeatureEvidenceExport})
	if err != nil {
		t.Fatal(err)
	}
	if result.Accepted {
		t.Fatal("expected deny for envelope expired by 1ns")
	}
	if result.DenyReason != DenyVersionIncompatible {
		t.Fatalf("expected VERSION_INCOMPATIBLE, got %s", result.DenyReason)
	}
}

func TestConformance_Expiry_NotYetExpired(t *testing.T) {
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	v := baseVerifier(now)
	env := baseEnvelope(now)
	env.ExpiresAt = now.Add(1 * time.Nanosecond) // 1ns in the future
	SignEnvelope(env, "key-origin-001", "ed25519", "agent-origin")

	result, err := v.Negotiate(context.Background(), env, []Feature{FeatureEvidenceExport})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Accepted {
		t.Fatalf("expected accept for not-yet-expired envelope, got deny: %s", result.DenyReason)
	}
}

func TestConformance_Expiry_ZeroExpiresAt(t *testing.T) {
	// Zero ExpiresAt means no expiry → should pass
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	v := baseVerifier(now)
	env := baseEnvelope(now)
	env.ExpiresAt = time.Time{} // Zero value
	SignEnvelope(env, "key-origin-001", "ed25519", "agent-origin")

	result, err := v.Negotiate(context.Background(), env, []Feature{FeatureEvidenceExport})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Accepted {
		t.Fatalf("expected accept for zero ExpiresAt (no expiry), got deny: %s", result.DenyReason)
	}
}

// --- Policy Enforcement -----------------------------------------------------

func TestConformance_Policy_DenySpecificFeature(t *testing.T) {
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	v := baseVerifier(now)
	v.AddPolicyRule(PolicyRule{
		RuleID:         "deny-payments",
		OriginAgent:    "*",
		TargetAgent:    "*",
		DeniedFeatures: []Feature{FeatureAgentPayments},
		Action:         PolicyDeny,
	})

	env := baseEnvelope(now)
	env.RequiredFeatures = []Feature{FeatureAgentPayments}
	SignEnvelope(env, "key-origin-001", "ed25519", "agent-origin")

	result, err := v.Negotiate(context.Background(), env, []Feature{FeatureAgentPayments})
	if err != nil {
		t.Fatal(err)
	}
	if result.Accepted {
		t.Fatal("expected deny from policy rule")
	}
	if result.DenyReason != DenyPolicyViolation {
		t.Fatalf("expected POLICY_VIOLATION, got %s", result.DenyReason)
	}
	if !strings.Contains(result.DenyDetails, "deny-payments") {
		t.Fatalf("expected deny details to mention policy rule ID, got: %s", result.DenyDetails)
	}
}

func TestConformance_Policy_OriginAgentSpecific(t *testing.T) {
	// Policy targets specific origin agent
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	v := baseVerifier(now)
	v.AddPolicyRule(PolicyRule{
		RuleID:         "deny-origin-specific",
		OriginAgent:    "agent-origin",
		TargetAgent:    "*",
		DeniedFeatures: []Feature{FeatureTrustPropagation},
		Action:         PolicyDeny,
	})

	env := baseEnvelope(now)
	env.RequiredFeatures = []Feature{FeatureTrustPropagation}
	SignEnvelope(env, "key-origin-001", "ed25519", "agent-origin")

	result, err := v.Negotiate(context.Background(), env, []Feature{FeatureTrustPropagation})
	if err != nil {
		t.Fatal(err)
	}
	if result.Accepted {
		t.Fatal("expected deny from agent-specific policy")
	}
	if result.DenyReason != DenyPolicyViolation {
		t.Fatalf("expected POLICY_VIOLATION, got %s", result.DenyReason)
	}
}

func TestConformance_Policy_DoesNotMatchOtherOrigin(t *testing.T) {
	// Policy targets agent-malicious but envelope is from agent-origin → should pass
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	v := baseVerifier(now)
	v.AddPolicyRule(PolicyRule{
		RuleID:         "deny-malicious-only",
		OriginAgent:    "agent-malicious",
		TargetAgent:    "*",
		DeniedFeatures: []Feature{FeatureEvidenceExport},
		Action:         PolicyDeny,
	})

	env := baseEnvelope(now)
	env.RequiredFeatures = []Feature{FeatureEvidenceExport}
	SignEnvelope(env, "key-origin-001", "ed25519", "agent-origin")

	result, err := v.Negotiate(context.Background(), env, []Feature{FeatureEvidenceExport})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Accepted {
		t.Fatalf("expected accept (policy doesn't match this origin), got deny: %s", result.DenyReason)
	}
}

func TestConformance_Policy_TargetAgentSpecific(t *testing.T) {
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	v := baseVerifier(now)
	v.AddPolicyRule(PolicyRule{
		RuleID:         "deny-target-specific",
		OriginAgent:    "*",
		TargetAgent:    "agent-target",
		DeniedFeatures: []Feature{FeaturePeerVouching},
		Action:         PolicyDeny,
	})

	env := baseEnvelope(now)
	env.RequiredFeatures = []Feature{FeaturePeerVouching}
	SignEnvelope(env, "key-origin-001", "ed25519", "agent-origin")

	result, err := v.Negotiate(context.Background(), env, []Feature{FeaturePeerVouching})
	if err != nil {
		t.Fatal(err)
	}
	if result.Accepted {
		t.Fatal("expected deny from target-specific policy")
	}
	if result.DenyReason != DenyPolicyViolation {
		t.Fatalf("expected POLICY_VIOLATION, got %s", result.DenyReason)
	}
}

func TestConformance_Policy_AllowRuleDoesNotBlock(t *testing.T) {
	// ALLOW action should not cause deny
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	v := baseVerifier(now)
	v.AddPolicyRule(PolicyRule{
		RuleID:          "allow-everything",
		OriginAgent:     "*",
		TargetAgent:     "*",
		AllowedFeatures: []Feature{FeatureEvidenceExport},
		Action:          PolicyAllow,
	})

	env := baseEnvelope(now)
	env.RequiredFeatures = []Feature{FeatureEvidenceExport}
	SignEnvelope(env, "key-origin-001", "ed25519", "agent-origin")

	result, err := v.Negotiate(context.Background(), env, []Feature{FeatureEvidenceExport})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Accepted {
		t.Fatalf("expected accept (ALLOW rule should not block), got deny: %s", result.DenyReason)
	}
}

func TestConformance_Policy_DenyOnlyAffectsRequiredFeatures(t *testing.T) {
	// Policy denies DISPUTE_REPLAY but envelope only requires EVIDENCE_EXPORT → pass
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	v := baseVerifier(now)
	v.AddPolicyRule(PolicyRule{
		RuleID:         "deny-dispute-replay",
		OriginAgent:    "*",
		TargetAgent:    "*",
		DeniedFeatures: []Feature{FeatureDisputeReplay},
		Action:         PolicyDeny,
	})

	env := baseEnvelope(now)
	env.RequiredFeatures = []Feature{FeatureEvidenceExport}
	SignEnvelope(env, "key-origin-001", "ed25519", "agent-origin")

	result, err := v.Negotiate(context.Background(), env, []Feature{FeatureEvidenceExport})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Accepted {
		t.Fatalf("expected accept (denied feature not in required), got deny: %s", result.DenyReason)
	}
}

// --- Evaluation Order -------------------------------------------------------

func TestConformance_EvalOrder_ExpiryBeforeVersion(t *testing.T) {
	// Both expired AND wrong version — expiry checked first
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	v := baseVerifier(now)
	env := baseEnvelope(now)
	env.ExpiresAt = now.Add(-1 * time.Hour)
	env.SchemaVersion = SchemaVersion{Major: 99, Minor: 0, Patch: 0}
	SignEnvelope(env, "key-origin-001", "ed25519", "agent-origin")

	result, err := v.Negotiate(context.Background(), env, []Feature{FeatureEvidenceExport})
	if err != nil {
		t.Fatal(err)
	}
	if result.Accepted {
		t.Fatal("expected deny")
	}
	// Expiry is checked first → should mention "expired"
	if !strings.Contains(result.DenyDetails, "expired") {
		t.Fatalf("expected expiry to be detected first, got: %s", result.DenyDetails)
	}
}

func TestConformance_EvalOrder_VersionBeforePolicy(t *testing.T) {
	// Wrong version + policy violation — version checked before policy
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	v := baseVerifier(now)
	v.AddPolicyRule(PolicyRule{
		RuleID:         "deny-all",
		OriginAgent:    "*",
		TargetAgent:    "*",
		DeniedFeatures: []Feature{FeatureEvidenceExport},
		Action:         PolicyDeny,
	})
	env := baseEnvelope(now)
	env.SchemaVersion = SchemaVersion{Major: 5, Minor: 0, Patch: 0}
	SignEnvelope(env, "key-origin-001", "ed25519", "agent-origin")

	result, err := v.Negotiate(context.Background(), env, []Feature{FeatureEvidenceExport})
	if err != nil {
		t.Fatal(err)
	}
	if result.Accepted {
		t.Fatal("expected deny")
	}
	if result.DenyReason != DenyVersionIncompatible {
		t.Fatalf("expected VERSION_INCOMPATIBLE (checked before policy), got %s", result.DenyReason)
	}
}

func TestConformance_EvalOrder_PolicyBeforeFeature(t *testing.T) {
	// Policy denies a feature AND another required feature is missing locally
	// Policy is checked before feature negotiation
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	v := baseVerifier(now)
	v.AddPolicyRule(PolicyRule{
		RuleID:         "deny-payments",
		OriginAgent:    "*",
		TargetAgent:    "*",
		DeniedFeatures: []Feature{FeatureAgentPayments},
		Action:         PolicyDeny,
	})
	env := baseEnvelope(now)
	env.RequiredFeatures = []Feature{FeatureAgentPayments, FeatureDisputeReplay}
	SignEnvelope(env, "key-origin-001", "ed25519", "agent-origin")

	// Local doesn't have DISPUTE_REPLAY either, but policy should fire first
	result, err := v.Negotiate(context.Background(), env, []Feature{FeatureEvidenceExport})
	if err != nil {
		t.Fatal(err)
	}
	if result.Accepted {
		t.Fatal("expected deny")
	}
	if result.DenyReason != DenyPolicyViolation {
		t.Fatalf("expected POLICY_VIOLATION (checked before features), got %s", result.DenyReason)
	}
}

// --- Receipt & Metadata -----------------------------------------------------

func TestConformance_Receipt_AlwaysPresent(t *testing.T) {
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	v := baseVerifier(now)
	env := baseEnvelope(now)

	result, err := v.Negotiate(context.Background(), env, []Feature{FeatureEvidenceExport})
	if err != nil {
		t.Fatal(err)
	}
	if result.ReceiptID == "" {
		t.Fatal("expected ReceiptID to be set on accepted result")
	}
	if !strings.HasPrefix(result.ReceiptID, "a2a-neg:") {
		t.Fatalf("expected ReceiptID prefix 'a2a-neg:', got %s", result.ReceiptID)
	}
}

func TestConformance_Receipt_PresentOnDeny(t *testing.T) {
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	v := baseVerifier(now)
	env := baseEnvelope(now)
	env.SchemaVersion = SchemaVersion{Major: 99, Minor: 0, Patch: 0}
	SignEnvelope(env, "key-origin-001", "ed25519", "agent-origin")

	result, err := v.Negotiate(context.Background(), env, []Feature{FeatureEvidenceExport})
	if err != nil {
		t.Fatal(err)
	}
	if result.Accepted {
		t.Fatal("expected deny")
	}
	if result.ReceiptID == "" {
		t.Fatal("expected ReceiptID to be set even on deny")
	}
	if !strings.HasPrefix(result.ReceiptID, "a2a-neg:") {
		t.Fatalf("expected ReceiptID prefix 'a2a-neg:', got %s", result.ReceiptID)
	}
}

func TestConformance_Timestamp_MatchesClock(t *testing.T) {
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	v := baseVerifier(now)
	env := baseEnvelope(now)

	result, err := v.Negotiate(context.Background(), env, []Feature{FeatureEvidenceExport})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Timestamp.Equal(now) {
		t.Fatalf("expected timestamp %v, got %v", now, result.Timestamp)
	}
}

// --- Hash Determinism -------------------------------------------------------

func TestConformance_Hash_DeterministicAcrossFields(t *testing.T) {
	env1 := &Envelope{
		EnvelopeID:    "env-det-001",
		SchemaVersion: SchemaVersion{Major: 1, Minor: 2, Patch: 3},
		OriginAgentID: "agent-a",
		TargetAgentID: "agent-b",
		PayloadHash:   "sha256:abcdef123456",
	}
	env2 := &Envelope{
		EnvelopeID:    "env-det-001",
		SchemaVersion: SchemaVersion{Major: 1, Minor: 2, Patch: 3},
		OriginAgentID: "agent-a",
		TargetAgentID: "agent-b",
		PayloadHash:   "sha256:abcdef123456",
	}
	h1 := ComputeEnvelopeHash(env1)
	h2 := ComputeEnvelopeHash(env2)
	if h1 != h2 {
		t.Fatalf("identical envelopes should produce same hash: %s vs %s", h1, h2)
	}
}

func TestConformance_Hash_DiffersOnAnyFieldChange(t *testing.T) {
	base := &Envelope{
		EnvelopeID:    "env-hash-001",
		SchemaVersion: SchemaVersion{Major: 1, Minor: 0, Patch: 0},
		OriginAgentID: "agent-a",
		TargetAgentID: "agent-b",
		PayloadHash:   "sha256:original",
	}
	baseHash := ComputeEnvelopeHash(base)

	// Modify each field and verify hash changes
	mutations := []struct {
		name   string
		mutate func(e *Envelope)
	}{
		{"EnvelopeID", func(e *Envelope) { e.EnvelopeID = "different" }},
		{"Major", func(e *Envelope) { e.SchemaVersion.Major = 2 }},
		{"Minor", func(e *Envelope) { e.SchemaVersion.Minor = 1 }},
		{"Patch", func(e *Envelope) { e.SchemaVersion.Patch = 1 }},
		{"OriginAgentID", func(e *Envelope) { e.OriginAgentID = "agent-c" }},
		{"TargetAgentID", func(e *Envelope) { e.TargetAgentID = "agent-c" }},
		{"PayloadHash", func(e *Envelope) { e.PayloadHash = "sha256:modified" }},
	}

	for _, m := range mutations {
		t.Run(m.name, func(t *testing.T) {
			mutated := &Envelope{
				EnvelopeID:    base.EnvelopeID,
				SchemaVersion: base.SchemaVersion,
				OriginAgentID: base.OriginAgentID,
				TargetAgentID: base.TargetAgentID,
				PayloadHash:   base.PayloadHash,
			}
			m.mutate(mutated)
			mHash := ComputeEnvelopeHash(mutated)
			if mHash == baseHash {
				t.Fatalf("expected hash to change when %s is modified", m.name)
			}
		})
	}
}

func TestConformance_Hash_PrefixFormat(t *testing.T) {
	env := &Envelope{
		EnvelopeID:    "test",
		SchemaVersion: SchemaVersion{Major: 1, Minor: 0, Patch: 0},
		OriginAgentID: "a",
		TargetAgentID: "b",
		PayloadHash:   "payload",
	}
	h := ComputeEnvelopeHash(env)
	if !strings.HasPrefix(h, "sha256:") {
		t.Fatalf("expected hash prefix 'sha256:', got %s", h)
	}
	// SHA-256 hex encoding = 64 characters after prefix
	hexPart := strings.TrimPrefix(h, "sha256:")
	if len(hexPart) != 64 {
		t.Fatalf("expected 64 hex chars after prefix, got %d", len(hexPart))
	}
}

// --- DenyReason Constants ---------------------------------------------------

func TestConformance_DenyReasonValues(t *testing.T) {
	// Verify all 7 DenyReason constants have expected string values
	reasons := map[DenyReason]string{
		DenyVersionIncompatible: "VERSION_INCOMPATIBLE",
		DenyFeatureMissing:      "FEATURE_MISSING",
		DenyPolicyViolation:     "POLICY_VIOLATION",
		DenySignatureInvalid:    "SIGNATURE_INVALID",
		DenyAgentNotTrusted:     "AGENT_NOT_TRUSTED",
		DenyChallengeFailure:    "CHALLENGE_FAILURE",
		DenyVouchRevoked:        "VOUCH_REVOKED",
	}
	for constant, expected := range reasons {
		if string(constant) != expected {
			t.Errorf("DenyReason %q: expected %q", constant, expected)
		}
	}
}

// --- Feature Constants ------------------------------------------------------

func TestConformance_FeatureValues(t *testing.T) {
	// Verify all 9 Feature constants have expected string values
	features := map[Feature]string{
		FeatureMeteringReceipts:  "METERING_RECEIPTS",
		FeatureDisputeReplay:     "DISPUTE_REPLAY",
		FeatureProofGraphSync:    "PROOFGRAPH_SYNC",
		FeatureEvidenceExport:    "EVIDENCE_EXPORT",
		FeaturePolicyNegotiation: "POLICY_NEGOTIATION",
		FeatureAgentPayments:     "AGENT_PAYMENTS",
		FeatureIATPAuth:          "IATP_AUTH",
		FeaturePeerVouching:      "PEER_VOUCHING",
		FeatureTrustPropagation:  "TRUST_PROPAGATION",
	}
	for constant, expected := range features {
		if string(constant) != expected {
			t.Errorf("Feature %q: expected %q", constant, expected)
		}
	}
}

// --- SchemaVersion -----------------------------------------------------------

func TestConformance_SchemaVersion_String(t *testing.T) {
	cases := []struct {
		v    SchemaVersion
		want string
	}{
		{SchemaVersion{1, 0, 0}, "1.0.0"},
		{SchemaVersion{2, 5, 13}, "2.5.13"},
		{SchemaVersion{0, 0, 0}, "0.0.0"},
		{SchemaVersion{99, 99, 99}, "99.99.99"},
	}
	for _, tc := range cases {
		got := tc.v.String()
		if got != tc.want {
			t.Errorf("SchemaVersion%v.String() = %q, want %q", tc.v, got, tc.want)
		}
	}
}

func TestConformance_CurrentVersion(t *testing.T) {
	if CurrentVersion.Major != 1 || CurrentVersion.Minor != 0 || CurrentVersion.Patch != 0 {
		t.Fatalf("expected CurrentVersion 1.0.0, got %s", CurrentVersion.String())
	}
}
