package envelope

import (
	"context"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
)

// testEnvelope returns a valid, signed envelope for testing.
func testEnvelope() *contracts.AutonomyEnvelope {
	env := &contracts.AutonomyEnvelope{
		EnvelopeID:    "env-test-001",
		Version:       "1.0.0",
		FormatVersion: "1.0.0",
		ValidFrom:     time.Now().Add(-1 * time.Hour),
		ValidUntil:    time.Now().Add(24 * time.Hour),
		TenantID:      "tenant-alpha",
		JurisdictionScope: contracts.JurisdictionConstraint{
			AllowedJurisdictions:    []string{"US", "EU", "GB"},
			RegulatoryMode:          contracts.RegulatoryModeStrict,
			DataResidencyRegions:    []string{"us-east-1", "eu-west-1"},
			ProhibitedJurisdictions: []string{"RU", "KP"},
		},
		DataHandling: contracts.DataHandlingRules{
			MaxClassification: contracts.DataClassConfidential,
			RedactionPolicy:   "pii_only",
		},
		AllowedEffects: []contracts.EffectClassAllowlist{
			{EffectClass: "E0", Allowed: true},
			{EffectClass: "E1", Allowed: true, MaxPerRun: 100},
			{EffectClass: "E2", Allowed: true, MaxPerRun: 50},
			{EffectClass: "E3", Allowed: true, MaxPerRun: 10, RequiresApprovalAbove: 5},
			{EffectClass: "E4", Allowed: false},
		},
		Budgets: contracts.EnvelopeBudgets{
			CostCeilingCents:   10000, // $100
			TimeCeilingSeconds: 3600,  // 1 hour
			ToolCallCap:        500,
			BlastRadius:        contracts.BlastRadiusDataset,
		},
		RequiredEvidence: []contracts.EvidenceRequirement{
			{ActionClass: "E3", EvidenceType: contracts.EvidenceTypeReceipt, When: "after"},
			{ActionClass: "E4", EvidenceType: contracts.EvidenceTypeDualAttestation, When: "both"},
		},
		EscalationPolicy: contracts.EscalationRules{
			DefaultMode: contracts.EscalationModeAutonomous,
			EscalationTriggers: []contracts.EscalationTrigger{
				{
					Condition:      "effect.class == 'E4'",
					Action:         contracts.EscalationActionRequireApproval,
					Approvers:      []string{"security-team"},
					Quorum:         2,
					TimeoutSeconds: 300,
				},
			},
			JudgmentTaxonomy: []contracts.JudgmentClassification{
				{Category: "data_export", Classification: contracts.JudgmentRequired},
				{Category: "internal_query", Classification: contracts.JudgmentAutonomous},
			},
		},
	}

	// Sign the envelope
	_ = Sign(env, "kernel-test")
	return env
}

// --- Validator Tests ---

func TestValidateValidEnvelope(t *testing.T) {
	v := NewValidator()
	env := testEnvelope()

	result := v.Validate(env)
	if !result.Valid {
		t.Fatalf("expected valid envelope, got errors: %v", result.Errors)
	}
	if result.Hash == "" {
		t.Fatal("expected hash to be computed for valid envelope")
	}
}

func TestValidateRejectsExpiredEnvelope(t *testing.T) {
	v := NewValidator()
	env := testEnvelope()
	env.ValidUntil = time.Now().Add(-1 * time.Hour)
	_ = Sign(env, "kernel-test") // re-sign with new content

	result := v.Validate(env)
	if result.Valid {
		t.Fatal("expected expired envelope to be rejected")
	}
	found := false
	for _, e := range result.Errors {
		if e.Code == "EXPIRED" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected EXPIRED error, got: %v", result.Errors)
	}
}

func TestValidateRejectsMissingID(t *testing.T) {
	v := NewValidator()
	env := testEnvelope()
	env.EnvelopeID = ""

	result := v.Validate(env)
	if result.Valid {
		t.Fatal("expected envelope with missing ID to be rejected")
	}
}

func TestValidateRejectsJurisdictionConflict(t *testing.T) {
	v := NewValidator()
	env := testEnvelope()
	env.JurisdictionScope.ProhibitedJurisdictions = []string{"US"}
	_ = Sign(env, "kernel-test")

	result := v.Validate(env)
	if result.Valid {
		t.Fatal("expected jurisdiction conflict to be rejected")
	}
	found := false
	for _, e := range result.Errors {
		if e.Code == "CONFLICT" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected CONFLICT error, got: %v", result.Errors)
	}
}

func TestValidateRejectsDuplicateEffectClass(t *testing.T) {
	v := NewValidator()
	env := testEnvelope()
	env.AllowedEffects = append(env.AllowedEffects, contracts.EffectClassAllowlist{
		EffectClass: "E0", Allowed: true,
	})
	_ = Sign(env, "kernel-test")

	result := v.Validate(env)
	if result.Valid {
		t.Fatal("expected duplicate effect class to be rejected")
	}
}

func TestValidateRejectsTamperedHash(t *testing.T) {
	v := NewValidator()
	env := testEnvelope()
	env.Attestation.ContentHash = "sha256:deadbeef"

	result := v.Validate(env)
	if result.Valid {
		t.Fatal("expected tampered hash to be rejected")
	}
	found := false
	for _, e := range result.Errors {
		if e.Code == "HASH_MISMATCH" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected HASH_MISMATCH error, got: %v", result.Errors)
	}
}

func TestValidateRejectsInvalidBudgets(t *testing.T) {
	v := NewValidator()
	env := testEnvelope()
	env.Budgets.CostCeilingCents = 0
	env.Budgets.TimeCeilingSeconds = -1
	_ = Sign(env, "kernel-test")

	result := v.Validate(env)
	if result.Valid {
		t.Fatal("expected invalid budgets to be rejected")
	}
}

func TestContentHashDeterminism(t *testing.T) {
	env := testEnvelope()
	env.Attestation = contracts.EnvelopeAttestation{} // Clear attestation

	h1, err := ComputeContentHash(env)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := ComputeContentHash(env)
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Fatalf("content hash is not deterministic: %q != %q", h1, h2)
	}
}

// --- Gate Tests ---

func TestGateFailsClosedWithoutEnvelope(t *testing.T) {
	gate := NewEnvelopeGate()

	decision := gate.CheckEffect(context.Background(), &EffectRequest{
		EffectClass: "E0",
	})

	if decision.Allowed {
		t.Fatal("expected gate to deny without envelope")
	}
	if decision.Violation != "NO_ENVELOPE" {
		t.Fatalf("expected NO_ENVELOPE violation, got %q", decision.Violation)
	}
}

func TestGateAllowsWithinBounds(t *testing.T) {
	gate := NewEnvelopeGate()
	env := testEnvelope()

	result := gate.Bind(context.Background(), env)
	if !result.Valid {
		t.Fatalf("bind failed: %v", result.Errors)
	}

	decision := gate.CheckEffect(context.Background(), &EffectRequest{
		EffectClass:   "E1",
		Jurisdiction:  "US",
		DataClass:     contracts.DataClassInternal,
		EstimatedCost: 100,
	})

	if !decision.Allowed {
		t.Fatalf("expected effect to be allowed, got: %s", decision.Reason)
	}
}

func TestGateDeniesProhibitedJurisdiction(t *testing.T) {
	gate := NewEnvelopeGate()
	env := testEnvelope()
	gate.Bind(context.Background(), env)

	decision := gate.CheckEffect(context.Background(), &EffectRequest{
		EffectClass:  "E0",
		Jurisdiction: "RU",
	})

	if decision.Allowed {
		t.Fatal("expected denied for prohibited jurisdiction")
	}
	if decision.Violation != "JURISDICTION_DENIED" {
		t.Fatalf("expected JURISDICTION_DENIED, got %q", decision.Violation)
	}
}

func TestGateDeniesUnlistedJurisdiction(t *testing.T) {
	gate := NewEnvelopeGate()
	env := testEnvelope()
	gate.Bind(context.Background(), env)

	decision := gate.CheckEffect(context.Background(), &EffectRequest{
		EffectClass:  "E0",
		Jurisdiction: "JP", // Not in allowed list
	})

	if decision.Allowed {
		t.Fatal("expected denied for unlisted jurisdiction")
	}
}

func TestGateDeniesDisallowedEffectClass(t *testing.T) {
	gate := NewEnvelopeGate()
	env := testEnvelope()
	gate.Bind(context.Background(), env)

	decision := gate.CheckEffect(context.Background(), &EffectRequest{
		EffectClass: "E4", // Explicitly disallowed in test envelope
	})

	if decision.Allowed {
		t.Fatal("expected E4 to be denied")
	}
	if decision.Violation != "EFFECT_CLASS_DENIED" {
		t.Fatalf("expected EFFECT_CLASS_DENIED, got %q", decision.Violation)
	}
}

func TestGateEnforcesCostCeiling(t *testing.T) {
	gate := NewEnvelopeGate()
	env := testEnvelope()
	gate.Bind(context.Background(), env)

	// Spend up to near the ceiling
	for i := 0; i < 9; i++ {
		d := gate.CheckEffect(context.Background(), &EffectRequest{
			EffectClass:   "E1",
			EstimatedCost: 1000, // $10 each
		})
		if !d.Allowed {
			t.Fatalf("expected effect %d to be allowed", i)
		}
	}

	// This should push us over $100 ceiling
	d := gate.CheckEffect(context.Background(), &EffectRequest{
		EffectClass:   "E1",
		EstimatedCost: 2000, // $20 - would make total $110
	})

	if d.Allowed {
		t.Fatal("expected cost ceiling to block effect")
	}
	if d.Violation != "COST_CEILING_EXCEEDED" {
		t.Fatalf("expected COST_CEILING_EXCEEDED, got %q", d.Violation)
	}
}

func TestGateEnforcesToolCallCap(t *testing.T) {
	gate := NewEnvelopeGate()
	env := testEnvelope()
	env.Budgets.ToolCallCap = 3
	_ = Sign(env, "kernel-test")
	gate.Bind(context.Background(), env)

	for i := int64(0); i < 3; i++ {
		d := gate.CheckEffect(context.Background(), &EffectRequest{EffectClass: "E0"})
		if !d.Allowed {
			t.Fatalf("expected tool call %d to be allowed", i)
		}
	}

	d := gate.CheckEffect(context.Background(), &EffectRequest{EffectClass: "E0"})
	if d.Allowed {
		t.Fatal("expected tool call cap to block effect")
	}
	if d.Violation != "TOOL_CALL_CAP_EXCEEDED" {
		t.Fatalf("expected TOOL_CALL_CAP_EXCEEDED, got %q", d.Violation)
	}
}

func TestGateEnforcesTimeCeiling(t *testing.T) {
	now := time.Now()
	elapsed := int64(0)
	gate := NewEnvelopeGate().WithClock(func() time.Time {
		return now.Add(time.Duration(elapsed) * time.Second)
	})

	env := testEnvelope()
	env.Budgets.TimeCeilingSeconds = 60
	env.ValidUntil = now.Add(2 * time.Hour)
	_ = Sign(env, "kernel-test")
	gate.Bind(context.Background(), env)

	// Within time
	d := gate.CheckEffect(context.Background(), &EffectRequest{EffectClass: "E0"})
	if !d.Allowed {
		t.Fatal("expected effect within time ceiling")
	}

	// Advance past ceiling
	elapsed = 61
	d = gate.CheckEffect(context.Background(), &EffectRequest{EffectClass: "E0"})
	if d.Allowed {
		t.Fatal("expected time ceiling to block effect")
	}
	if d.Violation != "TIME_CEILING_EXCEEDED" {
		t.Fatalf("expected TIME_CEILING_EXCEEDED, got %q", d.Violation)
	}
}

func TestGateEnforcesMaxPerRun(t *testing.T) {
	gate := NewEnvelopeGate()
	env := testEnvelope()
	gate.Bind(context.Background(), env)

	// E3 has max_per_run: 10
	for i := 0; i < 5; i++ {
		d := gate.CheckEffect(context.Background(), &EffectRequest{EffectClass: "E3"})
		if !d.Allowed {
			t.Fatalf("expected E3 effect %d to be allowed", i)
		}
	}

	// Effect 6 should trigger escalation (requires_approval_above: 5)
	d := gate.CheckEffect(context.Background(), &EffectRequest{EffectClass: "E3"})
	if d.Allowed {
		t.Fatal("expected escalation required after threshold")
	}
	if d.Violation != "ESCALATION_REQUIRED" {
		t.Fatalf("expected ESCALATION_REQUIRED, got %q", d.Violation)
	}
}

func TestGateDeniesHighDataClassification(t *testing.T) {
	gate := NewEnvelopeGate()
	env := testEnvelope()
	gate.Bind(context.Background(), env)

	// Envelope allows up to confidential
	d := gate.CheckEffect(context.Background(), &EffectRequest{
		EffectClass: "E0",
		DataClass:   contracts.DataClassRestricted,
	})

	if d.Allowed {
		t.Fatal("expected restricted data classification to be denied")
	}
	if d.Violation != "DATA_CLASSIFICATION_EXCEEDED" {
		t.Fatalf("expected DATA_CLASSIFICATION_EXCEEDED, got %q", d.Violation)
	}
}

func TestGateDeniesExcessiveBlastRadius(t *testing.T) {
	gate := NewEnvelopeGate()
	env := testEnvelope()
	gate.Bind(context.Background(), env)

	// Envelope allows up to dataset
	d := gate.CheckEffect(context.Background(), &EffectRequest{
		EffectClass: "E1",
		BlastRadius: contracts.BlastRadiusSystemWide,
	})

	if d.Allowed {
		t.Fatal("expected system_wide blast radius to be denied")
	}
	if d.Violation != "BLAST_RADIUS_EXCEEDED" {
		t.Fatalf("expected BLAST_RADIUS_EXCEEDED, got %q", d.Violation)
	}
}

func TestGateUnbindReturnsToDenyAll(t *testing.T) {
	gate := NewEnvelopeGate()
	env := testEnvelope()
	gate.Bind(context.Background(), env)

	// Verify it works
	d := gate.CheckEffect(context.Background(), &EffectRequest{EffectClass: "E0"})
	if !d.Allowed {
		t.Fatal("expected allowed while bound")
	}

	// Unbind
	gate.Unbind()

	// Verify fail-closed
	d = gate.CheckEffect(context.Background(), &EffectRequest{EffectClass: "E0"})
	if d.Allowed {
		t.Fatal("expected denied after unbind")
	}
}

func TestGateSnapshotTracksState(t *testing.T) {
	gate := NewEnvelopeGate()
	env := testEnvelope()
	gate.Bind(context.Background(), env)

	gate.CheckEffect(context.Background(), &EffectRequest{
		EffectClass:   "E1",
		EstimatedCost: 500,
	})
	gate.CheckEffect(context.Background(), &EffectRequest{
		EffectClass:   "E2",
		EstimatedCost: 300,
	})

	snap := gate.Snapshot()
	if snap == nil {
		t.Fatal("expected snapshot")
	}
	if snap.ToolCallCount != 2 {
		t.Fatalf("expected 2 tool calls, got %d", snap.ToolCallCount)
	}
	if snap.CostAccumulated != 800 {
		t.Fatalf("expected 800 cents accumulated, got %d", snap.CostAccumulated)
	}
	if snap.EffectCounts["E1"] != 1 {
		t.Fatalf("expected 1 E1 effect, got %d", snap.EffectCounts["E1"])
	}
	if snap.EffectCounts["E2"] != 1 {
		t.Fatalf("expected 1 E2 effect, got %d", snap.EffectCounts["E2"])
	}
}

func TestGateRejectsExpiredEnvelopeAtRuntime(t *testing.T) {
	now := time.Now()
	expired := false
	gate := NewEnvelopeGate().WithClock(func() time.Time {
		if expired {
			return now.Add(25 * time.Hour)
		}
		return now
	})

	env := testEnvelope()
	env.ValidUntil = now.Add(24 * time.Hour)
	_ = Sign(env, "kernel-test")
	gate.Bind(context.Background(), env)

	// Within validity
	d := gate.CheckEffect(context.Background(), &EffectRequest{EffectClass: "E0"})
	if !d.Allowed {
		t.Fatal("expected allowed within validity")
	}

	// Expire envelope
	expired = true
	d = gate.CheckEffect(context.Background(), &EffectRequest{EffectClass: "E0"})
	if d.Allowed {
		t.Fatal("expected denied after expiry")
	}
	if d.Violation != "ENVELOPE_EXPIRED" {
		t.Fatalf("expected ENVELOPE_EXPIRED, got %q", d.Violation)
	}
}

func TestGateBindRejectsInvalidEnvelope(t *testing.T) {
	gate := NewEnvelopeGate()
	env := &contracts.AutonomyEnvelope{} // Empty → invalid

	result := gate.Bind(context.Background(), env)
	if result.Valid {
		t.Fatal("expected bind to reject invalid envelope")
	}

	// Gate should still be unbound
	if gate.IsBound() {
		t.Fatal("expected gate to remain unbound after failed bind")
	}
}
