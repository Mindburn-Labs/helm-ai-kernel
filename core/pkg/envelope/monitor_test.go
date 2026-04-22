package envelope

import (
	"testing"
	"time"
)

func TestEnvelopeMonitorWatch(t *testing.T) {
	m := NewEnvelopeMonitor()
	m.Watch(&MonitoredEnvelope{EnvelopeID: "e1", BudgetMax: 100.0})

	if !m.IsActive("e1") {
		t.Fatal("expected active")
	}
}

func TestEnvelopeMonitorBudgetViolation(t *testing.T) {
	m := NewEnvelopeMonitor()
	m.Watch(&MonitoredEnvelope{EnvelopeID: "e1", BudgetMax: 10.0})

	err := m.RecordUsage("e1", 15.0)
	if err == nil {
		t.Fatal("expected budget exceeded")
	}

	if m.IsActive("e1") {
		t.Fatal("expected auto-paused")
	}
}

func TestEnvelopeMonitorExpiryViolation(t *testing.T) {
	now := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	m := NewEnvelopeMonitor().WithClock(func() time.Time { return now })

	m.Watch(&MonitoredEnvelope{
		EnvelopeID: "e1",
		ValidUntil: now.Add(-time.Hour), // already expired
		BudgetMax:  100.0,
	})

	violations := m.Check()
	if len(violations) == 0 {
		t.Fatal("expected expiry violation")
	}
	if violations[0].Type != ViolationExpired {
		t.Fatalf("expected EXPIRED, got %s", violations[0].Type)
	}
}

func TestEnvelopeMonitorOnPauseCallback(t *testing.T) {
	m := NewEnvelopeMonitor()
	var paused string
	m.OnPause(func(envID, reason string) { paused = envID })

	m.Watch(&MonitoredEnvelope{EnvelopeID: "e1", BudgetMax: 5.0})
	m.RecordUsage("e1", 10.0)

	if paused != "e1" {
		t.Fatal("expected onPause callback")
	}
}

func TestEnvelopeMonitorNotMonitored(t *testing.T) {
	m := NewEnvelopeMonitor()
	err := m.RecordUsage("nonexistent", 1.0)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestEnvelopeMonitorViolationsHistory(t *testing.T) {
	m := NewEnvelopeMonitor()
	m.Watch(&MonitoredEnvelope{EnvelopeID: "e1", BudgetMax: 1.0})
	m.RecordUsage("e1", 5.0)

	v := m.Violations()
	if len(v) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(v))
	}
	if !v[0].AutoPaused {
		t.Fatal("expected auto-paused")
	}
}
