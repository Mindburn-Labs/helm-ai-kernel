package envelope

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

var envelopeClock = func() time.Time { return time.Date(2026, 4, 12, 0, 0, 0, 0, time.UTC) }

func stressEnvelope() *contracts.AutonomyEnvelope {
	env := &contracts.AutonomyEnvelope{
		EnvelopeID:    "env-stress-001",
		Version:       "1.0.0",
		FormatVersion: "1.0.0",
		ValidFrom:     envelopeClock().Add(-1 * time.Hour),
		ValidUntil:    envelopeClock().Add(24 * time.Hour),
		TenantID:      "tenant-stress",
		JurisdictionScope: contracts.JurisdictionConstraint{
			AllowedJurisdictions: []string{"US", "EU"},
			RegulatoryMode:       contracts.RegulatoryModeStrict,
		},
		DataHandling: contracts.DataHandlingRules{
			MaxClassification: contracts.DataClassConfidential,
			RedactionPolicy:   "pii_only",
		},
		AllowedEffects: []contracts.EffectClassAllowlist{
			{EffectClass: "E0", Allowed: true},
			{EffectClass: "E1", Allowed: true, MaxPerRun: 100},
			{EffectClass: "E2", Allowed: true, MaxPerRun: 50},
		},
		Budgets: contracts.EnvelopeBudgets{
			CostCeilingCents:   50000,
			TimeCeilingSeconds: 7200,
			ToolCallCap:        1000,
			BlastRadius:        contracts.BlastRadiusDataset,
		},
		RequiredEvidence: []contracts.EvidenceRequirement{
			{ActionClass: "E2", EvidenceType: contracts.EvidenceTypeReceipt, When: "after"},
		},
		EscalationPolicy: contracts.EscalationRules{
			DefaultMode: contracts.EscalationModeAutonomous,
		},
	}
	_ = Sign(env, "stress-signer")
	return env
}

// --- Validator All Error Paths ---

func TestStress_Validator_NilEnvelope(t *testing.T) {
	v := NewValidator().WithClock(envelopeClock)
	r := v.Validate(nil)
	if r.Valid {
		t.Fatal("expected invalid for nil envelope")
	}
}

func TestStress_Validator_MissingEnvelopeID(t *testing.T) {
	v := NewValidator().WithClock(envelopeClock)
	env := stressEnvelope()
	env.EnvelopeID = ""
	r := v.Validate(env)
	if r.Valid {
		t.Fatal("expected invalid for missing envelope_id")
	}
}

func TestStress_Validator_MissingVersion(t *testing.T) {
	v := NewValidator().WithClock(envelopeClock)
	env := stressEnvelope()
	env.Version = ""
	r := v.Validate(env)
	if r.Valid {
		t.Fatal("expected invalid for missing version")
	}
}

func TestStress_Validator_UnsupportedFormatVersion(t *testing.T) {
	v := NewValidator().WithClock(envelopeClock)
	env := stressEnvelope()
	env.FormatVersion = "2.0.0"
	_ = Sign(env, "s")
	r := v.Validate(env)
	if r.Valid {
		t.Fatal("expected invalid for unsupported format version")
	}
}

func TestStress_Validator_ExpiredEnvelope(t *testing.T) {
	v := NewValidator().WithClock(envelopeClock)
	env := stressEnvelope()
	env.ValidUntil = envelopeClock().Add(-1 * time.Hour)
	_ = Sign(env, "s")
	r := v.Validate(env)
	if r.Valid {
		t.Fatal("expected invalid for expired envelope")
	}
}

func TestStress_Validator_InvalidWindow(t *testing.T) {
	v := NewValidator().WithClock(envelopeClock)
	env := stressEnvelope()
	env.ValidFrom = envelopeClock().Add(2 * time.Hour)
	env.ValidUntil = envelopeClock().Add(1 * time.Hour)
	_ = Sign(env, "s")
	r := v.Validate(env)
	hasWindowErr := false
	for _, e := range r.Errors {
		if e.Code == "INVALID_WINDOW" {
			hasWindowErr = true
		}
	}
	if !hasWindowErr {
		t.Fatal("expected INVALID_WINDOW error")
	}
}

func TestStress_Validator_NoJurisdictions(t *testing.T) {
	v := NewValidator().WithClock(envelopeClock)
	env := stressEnvelope()
	env.JurisdictionScope.AllowedJurisdictions = nil
	_ = Sign(env, "s")
	r := v.Validate(env)
	if r.Valid {
		t.Fatal("expected invalid with no jurisdictions")
	}
}

func TestStress_Validator_InvalidRegulatoryMode(t *testing.T) {
	v := NewValidator().WithClock(envelopeClock)
	env := stressEnvelope()
	env.JurisdictionScope.RegulatoryMode = "INVALID"
	_ = Sign(env, "s")
	r := v.Validate(env)
	if r.Valid {
		t.Fatal("expected invalid for bad regulatory mode")
	}
}

func TestStress_Validator_InvalidDataClassification(t *testing.T) {
	v := NewValidator().WithClock(envelopeClock)
	env := stressEnvelope()
	env.DataHandling.MaxClassification = "UNKNOWN"
	_ = Sign(env, "s")
	r := v.Validate(env)
	if r.Valid {
		t.Fatal("expected invalid for unknown data classification")
	}
}

func TestStress_Validator_NoAllowedEffects(t *testing.T) {
	v := NewValidator().WithClock(envelopeClock)
	env := stressEnvelope()
	env.AllowedEffects = nil
	_ = Sign(env, "s")
	r := v.Validate(env)
	if r.Valid {
		t.Fatal("expected invalid with no allowed effects")
	}
}

func TestStress_Validator_HashMismatch(t *testing.T) {
	v := NewValidator().WithClock(envelopeClock)
	env := stressEnvelope()
	env.Attestation.ContentHash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	r := v.Validate(env)
	if r.Valid {
		t.Fatal("expected invalid for hash mismatch")
	}
}

func TestStress_Validator_ValidEnvelope(t *testing.T) {
	v := NewValidator().WithClock(envelopeClock)
	env := stressEnvelope()
	r := v.Validate(env)
	if !r.Valid {
		t.Fatalf("expected valid, got errors: %v", r.Errors)
	}
}

// --- Gate 100 Operations ---

func TestStress_Gate_100Operations(t *testing.T) {
	gate := NewEnvelopeGate().WithClock(envelopeClock)
	env := stressEnvelope()
	gate.Bind(context.Background(), env)
	for i := 0; i < 100; i++ {
		d := gate.CheckEffect(context.Background(), &EffectRequest{EffectClass: "E0"})
		if !d.Allowed {
			t.Fatalf("effect %d denied: %s", i, d.Reason)
		}
	}
	snap := gate.Snapshot()
	if snap.ToolCallCount != 100 {
		t.Fatalf("expected 100 tool calls, got %d", snap.ToolCallCount)
	}
}

func TestStress_Gate_FailClosedNoEnvelope(t *testing.T) {
	gate := NewEnvelopeGate()
	d := gate.CheckEffect(context.Background(), &EffectRequest{EffectClass: "E0"})
	if d.Allowed {
		t.Fatal("expected deny without envelope")
	}
}

func TestStress_Gate_BindUnbindBind(t *testing.T) {
	gate := NewEnvelopeGate().WithClock(envelopeClock)
	env := stressEnvelope()
	gate.Bind(context.Background(), env)
	gate.Unbind()
	if gate.IsBound() {
		t.Fatal("expected unbound after unbind")
	}
	gate.Bind(context.Background(), env)
	if !gate.IsBound() {
		t.Fatal("expected bound after rebind")
	}
}

func TestStress_Gate_CostAccumulation(t *testing.T) {
	gate := NewEnvelopeGate().WithClock(envelopeClock)
	env := stressEnvelope()
	gate.Bind(context.Background(), env)
	for i := 0; i < 50; i++ {
		gate.CheckEffect(context.Background(), &EffectRequest{EffectClass: "E0", EstimatedCost: 100})
	}
	snap := gate.Snapshot()
	if snap.CostAccumulated != 5000 {
		t.Fatalf("expected 5000 cents, got %d", snap.CostAccumulated)
	}
}

func TestStress_Gate_ActiveEnvelopeInfo(t *testing.T) {
	gate := NewEnvelopeGate().WithClock(envelopeClock)
	env := stressEnvelope()
	gate.Bind(context.Background(), env)
	id, ver := gate.ActiveEnvelope()
	if id != "env-stress-001" || ver != "1.0.0" {
		t.Fatalf("unexpected active envelope: %s %s", id, ver)
	}
}

func TestStress_Gate_ActiveEnvelopeUnbound(t *testing.T) {
	gate := NewEnvelopeGate()
	id, ver := gate.ActiveEnvelope()
	if id != "" || ver != "" {
		t.Fatal("expected empty when unbound")
	}
}

func TestStress_Gate_SnapshotNilWhenUnbound(t *testing.T) {
	gate := NewEnvelopeGate()
	if gate.Snapshot() != nil {
		t.Fatal("expected nil snapshot when unbound")
	}
}

// --- Monitor 50 Violations ---

func TestStress_Monitor_50Violations(t *testing.T) {
	mon := NewEnvelopeMonitor().WithClock(envelopeClock)
	for i := 0; i < 50; i++ {
		mon.Watch(&MonitoredEnvelope{
			EnvelopeID: fmt.Sprintf("env-%d", i),
			ValidUntil: envelopeClock().Add(-time.Hour),
			BudgetMax:  100,
			BudgetUsed: 0,
		})
	}
	violations := mon.Check()
	if len(violations) != 50 {
		t.Fatalf("expected 50 violations, got %d", len(violations))
	}
}

func TestStress_Monitor_BudgetViolation(t *testing.T) {
	mon := NewEnvelopeMonitor().WithClock(envelopeClock)
	mon.Watch(&MonitoredEnvelope{
		EnvelopeID: "budget-env",
		ValidUntil: envelopeClock().Add(24 * time.Hour),
		BudgetMax:  100,
	})
	err := mon.RecordUsage("budget-env", 150)
	if err == nil {
		t.Fatal("expected budget error")
	}
}

func TestStress_Monitor_RecordUsageUnknown(t *testing.T) {
	mon := NewEnvelopeMonitor()
	err := mon.RecordUsage("ghost", 10)
	if err == nil {
		t.Fatal("expected error for unknown envelope")
	}
}

func TestStress_Monitor_IsActive(t *testing.T) {
	mon := NewEnvelopeMonitor().WithClock(envelopeClock)
	mon.Watch(&MonitoredEnvelope{
		EnvelopeID: "active-env",
		ValidUntil: envelopeClock().Add(24 * time.Hour),
		BudgetMax:  100,
	})
	if !mon.IsActive("active-env") {
		t.Fatal("expected active")
	}
}

func TestStress_Monitor_IsActiveUnknown(t *testing.T) {
	mon := NewEnvelopeMonitor()
	if mon.IsActive("ghost") {
		t.Fatal("expected inactive for unknown")
	}
}

func TestStress_Monitor_AutoPauseCallback(t *testing.T) {
	mon := NewEnvelopeMonitor().WithClock(envelopeClock)
	paused := false
	mon.OnPause(func(envID, reason string) { paused = true })
	mon.Watch(&MonitoredEnvelope{
		EnvelopeID: "pause-env",
		ValidUntil: envelopeClock().Add(-time.Hour),
		BudgetMax:  100,
	})
	mon.Check()
	if !paused {
		t.Fatal("expected auto-pause callback invoked")
	}
}

func TestStress_Monitor_DeactivateAfterViolation(t *testing.T) {
	mon := NewEnvelopeMonitor().WithClock(envelopeClock)
	mon.Watch(&MonitoredEnvelope{
		EnvelopeID: "deact-env",
		ValidUntil: envelopeClock().Add(-time.Hour),
		BudgetMax:  100,
	})
	mon.Check()
	if mon.IsActive("deact-env") {
		t.Fatal("expected deactivated after violation")
	}
}

func TestStress_Monitor_ViolationsAccumulate(t *testing.T) {
	mon := NewEnvelopeMonitor().WithClock(envelopeClock)
	for i := 0; i < 10; i++ {
		mon.Watch(&MonitoredEnvelope{
			EnvelopeID: fmt.Sprintf("acc-%d", i),
			ValidUntil: envelopeClock().Add(-time.Hour),
			BudgetMax:  100,
		})
	}
	mon.Check()
	all := mon.Violations()
	if len(all) != 10 {
		t.Fatalf("expected 10 violations, got %d", len(all))
	}
}

// --- Concurrent Operations ---

func TestStress_Concurrent_GateCheckEffect(t *testing.T) {
	gate := NewEnvelopeGate().WithClock(envelopeClock)
	env := stressEnvelope()
	gate.Bind(context.Background(), env)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			gate.CheckEffect(context.Background(), &EffectRequest{EffectClass: "E0"})
		}()
	}
	wg.Wait()
}

func TestStress_Concurrent_MonitorWatch(t *testing.T) {
	mon := NewEnvelopeMonitor().WithClock(envelopeClock)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			mon.Watch(&MonitoredEnvelope{
				EnvelopeID: fmt.Sprintf("cw-%d", id),
				ValidUntil: envelopeClock().Add(24 * time.Hour),
				BudgetMax:  100,
			})
		}(i)
	}
	wg.Wait()
}
