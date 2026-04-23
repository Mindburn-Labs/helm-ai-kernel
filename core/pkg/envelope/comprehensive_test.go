package envelope

import (
	"context"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
)

func TestValidatorRejectsNilEnvelope(t *testing.T) {
	v := NewValidator()
	result := v.Validate(nil)
	if result.Valid {
		t.Fatal("nil envelope should be invalid")
	}
}

func TestValidatorRejectsUnsupportedFormatVersion(t *testing.T) {
	v := NewValidator()
	env := testEnvelope()
	env.FormatVersion = "99.0.0"
	_ = Sign(env, "test")
	result := v.Validate(env)
	if result.Valid {
		t.Fatal("unsupported format version should be rejected")
	}
}

func TestValidatorRejectsEmptyAllowedEffects(t *testing.T) {
	v := NewValidator()
	env := testEnvelope()
	env.AllowedEffects = nil
	_ = Sign(env, "test")
	result := v.Validate(env)
	if result.Valid {
		t.Fatal("empty allowed effects should be rejected")
	}
}

func TestValidatorRejectsInvalidDataClassification(t *testing.T) {
	v := NewValidator()
	env := testEnvelope()
	env.DataHandling.MaxClassification = "top_secret"
	_ = Sign(env, "test")
	result := v.Validate(env)
	if result.Valid {
		t.Fatal("invalid data classification should be rejected")
	}
}

func TestValidatorRejectsInvalidEscalationMode(t *testing.T) {
	v := NewValidator()
	env := testEnvelope()
	env.EscalationPolicy.DefaultMode = "yolo"
	_ = Sign(env, "test")
	result := v.Validate(env)
	if result.Valid {
		t.Fatal("invalid escalation mode should be rejected")
	}
}

func TestComputeContentHashPrefix(t *testing.T) {
	env := testEnvelope()
	hash, err := ComputeContentHash(env)
	if err != nil || len(hash) < 10 || hash[:7] != "sha256:" {
		t.Fatalf("expected sha256 prefixed hash, got %q, err=%v", hash, err)
	}
}

func TestSignSetsAttestationFields(t *testing.T) {
	env := testEnvelope()
	env.Attestation = contracts.EnvelopeAttestation{}
	err := Sign(env, "signer-1")
	if err != nil || env.Attestation.ContentHash == "" || env.Attestation.SignerID != "signer-1" {
		t.Fatalf("sign should populate attestation fields, err=%v", err)
	}
}

func TestGateIsBoundAfterBind(t *testing.T) {
	g := NewEnvelopeGate()
	if g.IsBound() {
		t.Fatal("gate should not be bound initially")
	}
	g.Bind(context.Background(), testEnvelope())
	if !g.IsBound() {
		t.Fatal("gate should be bound after successful bind")
	}
}

func TestGateActiveEnvelopeReturnsIDAndVersion(t *testing.T) {
	g := NewEnvelopeGate()
	id, ver := g.ActiveEnvelope()
	if id != "" || ver != "" {
		t.Fatal("unbound gate should return empty envelope info")
	}
	g.Bind(context.Background(), testEnvelope())
	id, ver = g.ActiveEnvelope()
	if id != "env-test-001" || ver != "1.0.0" {
		t.Fatalf("expected env-test-001/1.0.0, got %s/%s", id, ver)
	}
}

func TestGateSnapshotNilWhenUnbound(t *testing.T) {
	g := NewEnvelopeGate()
	if g.Snapshot() != nil {
		t.Fatal("snapshot should be nil when unbound")
	}
}

func TestGateDeniesUnknownEffectClass(t *testing.T) {
	g := NewEnvelopeGate()
	g.Bind(context.Background(), testEnvelope())
	d := g.CheckEffect(context.Background(), &EffectRequest{EffectClass: "E99"})
	if d.Allowed {
		t.Fatal("unknown effect class should be denied")
	}
}

func TestGateAllowsEmptyJurisdiction(t *testing.T) {
	g := NewEnvelopeGate()
	g.Bind(context.Background(), testEnvelope())
	d := g.CheckEffect(context.Background(), &EffectRequest{EffectClass: "E0", Jurisdiction: ""})
	if !d.Allowed {
		t.Fatal("empty jurisdiction should skip jurisdiction check")
	}
}

// --- Monitor Tests ---

func TestMonitorWatchAndIsActive(t *testing.T) {
	m := NewEnvelopeMonitor()
	m.Watch(&MonitoredEnvelope{EnvelopeID: "e1", BudgetMax: 100, ValidUntil: time.Now().Add(time.Hour)})
	if !m.IsActive("e1") {
		t.Fatal("watched envelope should be active")
	}
}

func TestMonitorRecordUsageBudgetExceeded(t *testing.T) {
	m := NewEnvelopeMonitor()
	m.Watch(&MonitoredEnvelope{EnvelopeID: "e1", BudgetMax: 10})
	err := m.RecordUsage("e1", 15)
	if err == nil {
		t.Fatal("expected budget exceeded error")
	}
	if m.IsActive("e1") {
		t.Fatal("envelope should be auto-paused after budget violation")
	}
}

func TestMonitorCheckDetectsExpiry(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	m := NewEnvelopeMonitor().WithClock(func() time.Time { return time.Now() })
	m.Watch(&MonitoredEnvelope{EnvelopeID: "e1", BudgetMax: 100, ValidUntil: past})
	violations := m.Check()
	if len(violations) == 0 || violations[0].Type != ViolationExpired {
		t.Fatal("expected expired violation")
	}
}

func TestMonitorViolationsReturnsAll(t *testing.T) {
	m := NewEnvelopeMonitor()
	m.Watch(&MonitoredEnvelope{EnvelopeID: "e1", BudgetMax: 5})
	m.RecordUsage("e1", 10)
	vs := m.Violations()
	if len(vs) != 1 || vs[0].EnvelopeID != "e1" {
		t.Fatal("expected one violation for e1")
	}
}

func TestMonitorOnPauseCallback(t *testing.T) {
	m := NewEnvelopeMonitor()
	called := false
	m.OnPause(func(id, reason string) { called = true })
	m.Watch(&MonitoredEnvelope{EnvelopeID: "e1", BudgetMax: 1})
	m.RecordUsage("e1", 5)
	if !called {
		t.Fatal("onPause callback should have been invoked")
	}
}
