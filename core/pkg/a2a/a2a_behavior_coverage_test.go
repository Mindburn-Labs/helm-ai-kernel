package a2a

import (
	"context"
	"testing"
	"time"
)

// ── Envelope Creation ────────────────────────────────────────

func TestSchemaVersion_String(t *testing.T) {
	v := SchemaVersion{Major: 2, Minor: 3, Patch: 4}
	if v.String() != "2.3.4" {
		t.Errorf("expected 2.3.4, got %s", v.String())
	}
}

// ── Feature Negotiation ──────────────────────────────────────

func TestNegotiate_RequiredFeatureMissing(t *testing.T) {
	v := NewDefaultVerifier()
	env := &Envelope{SchemaVersion: CurrentVersion, RequiredFeatures: []Feature{FeatureDisputeReplay}}
	result, err := v.Negotiate(context.Background(), env, []Feature{FeatureEvidenceExport})
	if err != nil || result.Accepted {
		t.Errorf("should deny when required feature missing")
	}
	if result.DenyReason != DenyFeatureMissing {
		t.Errorf("expected FEATURE_MISSING, got %s", result.DenyReason)
	}
}

func TestNegotiate_VersionMismatch(t *testing.T) {
	v := NewDefaultVerifier()
	env := &Envelope{SchemaVersion: SchemaVersion{Major: 99, Minor: 0, Patch: 0}}
	result, _ := v.Negotiate(context.Background(), env, nil)
	if result.Accepted {
		t.Error("should deny incompatible major version")
	}
}

func TestNegotiate_AllFeaturesAvailable(t *testing.T) {
	v := NewDefaultVerifier()
	env := &Envelope{
		SchemaVersion:    CurrentVersion,
		RequiredFeatures: []Feature{FeatureEvidenceExport},
		OfferedFeatures:  []Feature{FeatureEvidenceExport, FeatureProofGraphSync},
	}
	result, _ := v.Negotiate(context.Background(), env, []Feature{FeatureEvidenceExport, FeatureProofGraphSync})
	if !result.Accepted {
		t.Error("should accept when all required features available")
	}
	if len(result.AgreedFeatures) != 2 {
		t.Errorf("expected 2 agreed features, got %d", len(result.AgreedFeatures))
	}
}

func TestNegotiate_ExpiredEnvelope(t *testing.T) {
	past := time.Now().Add(-1 * time.Hour)
	v := NewDefaultVerifier()
	env := &Envelope{SchemaVersion: CurrentVersion, ExpiresAt: past}
	result, _ := v.Negotiate(context.Background(), env, nil)
	if result.Accepted {
		t.Error("should deny expired envelope")
	}
}

// ── IATP Session Management ─────────────────────────────────

// ── Vouching Edge Cases ──────────────────────────────────────

// ── Trust Propagation Paths ──────────────────────────────────
