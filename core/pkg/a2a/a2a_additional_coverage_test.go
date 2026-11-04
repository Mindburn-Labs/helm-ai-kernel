package a2a

import (
	"context"
	"testing"
)

// ── Envelope Hash Collision Resistance ──────────────────────

// ── SchemaVersion Comparison ────────────────────────────────

func TestSchemaVersion_StringZeroValue(t *testing.T) {
	v := SchemaVersion{}
	if v.String() != "0.0.0" {
		t.Errorf("zero SchemaVersion should be 0.0.0, got %s", v.String())
	}
}

func TestSchemaVersion_PatchDifference(t *testing.T) {
	a := SchemaVersion{1, 0, 0}
	b := SchemaVersion{1, 0, 1}
	if a.String() == b.String() {
		t.Error("different patch versions should produce different strings")
	}
}

// ── Feature Negotiation with All Feature Types ──────────────

func TestNegotiate_AllFeatureTypesOffered(t *testing.T) {
	v := NewDefaultVerifier()
	all := []Feature{
		FeatureMeteringReceipts, FeatureDisputeReplay, FeatureProofGraphSync,
		FeatureEvidenceExport, FeaturePolicyNegotiation, FeatureAgentPayments,
		FeatureIATPAuth, FeaturePeerVouching, FeatureTrustPropagation,
	}
	env := &Envelope{SchemaVersion: CurrentVersion, OfferedFeatures: all}
	result, _ := v.Negotiate(context.Background(), env, all)
	if !result.Accepted || len(result.AgreedFeatures) != len(all) {
		t.Errorf("expected all %d features agreed, got %d", len(all), len(result.AgreedFeatures))
	}
}

func TestNegotiate_PartialFeatureIntersection(t *testing.T) {
	v := NewDefaultVerifier()
	env := &Envelope{
		SchemaVersion:   CurrentVersion,
		OfferedFeatures: []Feature{FeatureEvidenceExport, FeatureIATPAuth},
	}
	result, _ := v.Negotiate(context.Background(), env, []Feature{FeatureIATPAuth, FeaturePeerVouching})
	if len(result.AgreedFeatures) != 1 || result.AgreedFeatures[0] != FeatureIATPAuth {
		t.Errorf("expected only IATP_AUTH agreed, got %v", result.AgreedFeatures)
	}
}

// ── IATP Concurrent Sessions ────────────────────────────────

// ── Vouching with Max Exposure Limits ───────────────────────

// ── Trust Propagation Diamond Pattern ───────────────────────
