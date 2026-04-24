package envelope

import (
	"encoding/json"
	"testing"
	"time"
)

func TestFinal_ViolationTypeConstants(t *testing.T) {
	types := []ViolationType{ViolationExpired, ViolationBudget, ViolationScope, ViolationJurisdiction, ViolationEffect}
	if len(types) != 5 {
		t.Fatal("expected 5 violation types")
	}
}

func TestFinal_ValidationErrorString(t *testing.T) {
	e := ValidationError{Field: "budget", Code: "INVALID", Message: "too low"}
	s := e.Error()
	if s == "" {
		t.Fatal("error string should not be empty")
	}
}

func TestFinal_ValidationResultJSONRoundTrip(t *testing.T) {
	vr := ValidationResult{Valid: true, Hash: "sha256:abc"}
	data, _ := json.Marshal(vr)
	var got ValidationResult
	json.Unmarshal(data, &got)
	if !got.Valid || got.Hash != "sha256:abc" {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_EffectRequestJSONRoundTrip(t *testing.T) {
	er := EffectRequest{EffectClass: "E1", EffectType: "DATA_WRITE", Jurisdiction: "US"}
	data, _ := json.Marshal(er)
	var got EffectRequest
	json.Unmarshal(data, &got)
	if got.EffectClass != "E1" || got.Jurisdiction != "US" {
		t.Fatal("round-trip")
	}
}

func TestFinal_GateDecisionJSONRoundTrip(t *testing.T) {
	gd := GateDecision{Allowed: true, Reason: "within bounds"}
	data, _ := json.Marshal(gd)
	var got GateDecision
	json.Unmarshal(data, &got)
	if !got.Allowed {
		t.Fatal("gate decision round-trip")
	}
}

func TestFinal_NewEnvelopeGate(t *testing.T) {
	g := NewEnvelopeGate()
	if g == nil {
		t.Fatal("nil gate")
	}
}

func TestFinal_GateNotBoundByDefault(t *testing.T) {
	g := NewEnvelopeGate()
	if g.IsBound() {
		t.Fatal("should not be bound")
	}
}

func TestFinal_CheckEffectDeniedWhenUnbound(t *testing.T) {
	g := NewEnvelopeGate()
	d := g.CheckEffect(nil, &EffectRequest{EffectClass: "E1"})
	if d.Allowed {
		t.Fatal("should deny when unbound")
	}
	if d.Violation != "NO_ENVELOPE" {
		t.Fatal("wrong violation")
	}
}

func TestFinal_ActiveEnvelopeEmpty(t *testing.T) {
	g := NewEnvelopeGate()
	id, ver := g.ActiveEnvelope()
	if id != "" || ver != "" {
		t.Fatal("should be empty when unbound")
	}
}

func TestFinal_Unbind(t *testing.T) {
	g := NewEnvelopeGate()
	g.Unbind()
	if g.IsBound() {
		t.Fatal("should be unbound")
	}
}

func TestFinal_SnapshotNilWhenUnbound(t *testing.T) {
	g := NewEnvelopeGate()
	if g.Snapshot() != nil {
		t.Fatal("should be nil when unbound")
	}
}

func TestFinal_GateSnapshotJSONRoundTrip(t *testing.T) {
	gs := GateSnapshot{EnvelopeID: "e1", ToolCallCount: 5, CostAccumulated: 100}
	data, _ := json.Marshal(gs)
	var got GateSnapshot
	json.Unmarshal(data, &got)
	if got.EnvelopeID != "e1" || got.ToolCallCount != 5 {
		t.Fatal("snapshot round-trip")
	}
}

func TestFinal_NewValidator(t *testing.T) {
	v := NewValidator()
	if v == nil {
		t.Fatal("nil validator")
	}
}

func TestFinal_ValidateNilEnvelope(t *testing.T) {
	v := NewValidator()
	r := v.Validate(nil)
	if r.Valid {
		t.Fatal("nil should be invalid")
	}
}

func TestFinal_WithClockGate(t *testing.T) {
	fixed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	g := NewEnvelopeGate().WithClock(func() time.Time { return fixed })
	if g == nil {
		t.Fatal("nil after WithClock")
	}
}

func TestFinal_WithClockValidator(t *testing.T) {
	fixed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	v := NewValidator().WithClock(func() time.Time { return fixed })
	if v == nil {
		t.Fatal("nil after WithClock")
	}
}

func TestFinal_ViolationJSONRoundTrip(t *testing.T) {
	v := Violation{ViolationID: "v1", Type: ViolationBudget, Description: "over budget"}
	data, _ := json.Marshal(v)
	var got Violation
	json.Unmarshal(data, &got)
	if got.ViolationID != "v1" || got.Type != ViolationBudget {
		t.Fatal("violation round-trip")
	}
}

func TestFinal_NewEnvelopeMonitor(t *testing.T) {
	m := NewEnvelopeMonitor()
	if m == nil {
		t.Fatal("nil monitor")
	}
}

func TestFinal_MonitorWatch(t *testing.T) {
	m := NewEnvelopeMonitor()
	m.Watch(&MonitoredEnvelope{EnvelopeID: "e1", BudgetMax: 100})
	if !m.IsActive("e1") {
		t.Fatal("should be active")
	}
}

func TestFinal_MonitorIsActiveUnknown(t *testing.T) {
	m := NewEnvelopeMonitor()
	if m.IsActive("nope") {
		t.Fatal("unknown should not be active")
	}
}

func TestFinal_MonitorRecordUsage(t *testing.T) {
	m := NewEnvelopeMonitor()
	m.Watch(&MonitoredEnvelope{EnvelopeID: "e1", BudgetMax: 100})
	err := m.RecordUsage("e1", 50)
	if err != nil {
		t.Fatal(err)
	}
}

func TestFinal_MonitorRecordUsageExceeded(t *testing.T) {
	m := NewEnvelopeMonitor()
	m.Watch(&MonitoredEnvelope{EnvelopeID: "e1", BudgetMax: 10})
	err := m.RecordUsage("e1", 20)
	if err == nil {
		t.Fatal("should error on exceeded")
	}
}

func TestFinal_MonitorRecordUsageUnknown(t *testing.T) {
	m := NewEnvelopeMonitor()
	err := m.RecordUsage("nope", 10)
	if err == nil {
		t.Fatal("should error")
	}
}

func TestFinal_MonitorCheckExpired(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	m := NewEnvelopeMonitor()
	m.Watch(&MonitoredEnvelope{EnvelopeID: "e1", ValidUntil: past, BudgetMax: 100})
	violations := m.Check()
	if len(violations) == 0 {
		t.Fatal("should detect expiry")
	}
}

func TestFinal_MonitorOnPause(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	m := NewEnvelopeMonitor()
	paused := false
	m.OnPause(func(id, reason string) { paused = true })
	m.Watch(&MonitoredEnvelope{EnvelopeID: "e1", ValidUntil: past, BudgetMax: 100})
	m.Check()
	if !paused {
		t.Fatal("onPause should be called")
	}
}

func TestFinal_MonitorViolationsEmpty(t *testing.T) {
	m := NewEnvelopeMonitor()
	if len(m.Violations()) != 0 {
		t.Fatal("should be empty")
	}
}

func TestFinal_MonitorDeactivatesOnViolation(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	m := NewEnvelopeMonitor()
	m.Watch(&MonitoredEnvelope{EnvelopeID: "e1", ValidUntil: past, BudgetMax: 100})
	m.Check()
	if m.IsActive("e1") {
		t.Fatal("should be deactivated after violation")
	}
}

func TestFinal_MonitorWithClock(t *testing.T) {
	fixed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	m := NewEnvelopeMonitor().WithClock(func() time.Time { return fixed })
	if m == nil {
		t.Fatal("nil after WithClock")
	}
}

func TestFinal_DataClassificationOrder(t *testing.T) {
	if dataClassificationOrder["public"] >= dataClassificationOrder["restricted"] {
		t.Fatal("public should be lower than restricted")
	}
}

func TestFinal_BlastRadiusOrder(t *testing.T) {
	if blastRadiusOrder["single_record"] >= blastRadiusOrder["system_wide"] {
		t.Fatal("single_record should be lower")
	}
}

func TestFinal_MonitoredEnvelopeFields(t *testing.T) {
	me := MonitoredEnvelope{EnvelopeID: "e1", BudgetMax: 100, BudgetUsed: 50, Active: true}
	if me.EnvelopeID != "e1" || me.BudgetMax != 100 {
		t.Fatal("field check")
	}
}

func TestFinal_ValidationErrorFields(t *testing.T) {
	ve := ValidationError{Field: "f", Code: "c", Message: "m"}
	if ve.Field != "f" || ve.Code != "c" || ve.Message != "m" {
		t.Fatal("field check")
	}
}
