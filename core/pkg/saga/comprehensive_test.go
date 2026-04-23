package saga

import (
	"context"
	"errors"
	"testing"
	"time"
)

func compClock() func() time.Time {
	t := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	return func() time.Time { return t }
}

// ── Registry ──

func TestRegistry_RegisterEmpty(t *testing.T) {
	r := NewReversibilityRegistry()
	if err := r.Register(ActionRegistration{}); err == nil {
		t.Fatal("expected error for empty action ID")
	}
}

func TestRegistry_RegisterAndLookup(t *testing.T) {
	r := NewReversibilityRegistry()
	r.Register(ActionRegistration{ActionID: "send-email", Reversible: true, CompensatingID: "undo-email"})
	reg, ok := r.Lookup("send-email")
	if !ok || reg.CompensatingID != "undo-email" {
		t.Fatal("expected to find registered action")
	}
}

func TestRegistry_LookupMissing(t *testing.T) {
	r := NewReversibilityRegistry()
	_, ok := r.Lookup("nonexistent")
	if ok {
		t.Fatal("expected not found")
	}
}

func TestRegistry_IsReversible(t *testing.T) {
	r := NewReversibilityRegistry()
	r.Register(ActionRegistration{ActionID: "a1", Reversible: true})
	r.Register(ActionRegistration{ActionID: "a2", Reversible: false})
	if !r.IsReversible("a1") {
		t.Fatal("a1 should be reversible")
	}
	if r.IsReversible("a2") {
		t.Fatal("a2 should not be reversible")
	}
}

func TestRegistry_ListActions(t *testing.T) {
	r := NewReversibilityRegistry()
	r.Register(ActionRegistration{ActionID: "x"})
	r.Register(ActionRegistration{ActionID: "y"})
	ids := r.ListActions()
	if len(ids) != 2 {
		t.Fatalf("expected 2 actions, got %d", len(ids))
	}
}

// ── Orchestrator ──

func TestOrchestrator_SuccessfulRun(t *testing.T) {
	reg := NewReversibilityRegistry()
	o := NewSagaOrchestrator(reg)
	o.WithClock(compClock())

	run := &SagaRun{RunID: "r1", Steps: []SagaStep{
		{StepID: "s1", Action: "create"},
		{StepID: "s2", Action: "publish"},
	}}
	err := o.Execute(context.Background(), run, func(_ context.Context, s *SagaStep) error {
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != SagaCompleted {
		t.Fatalf("expected COMPLETED, got %s", run.Status)
	}
}

func TestOrchestrator_StepFailureTriggersCompensation(t *testing.T) {
	reg := NewReversibilityRegistry()
	o := NewSagaOrchestrator(reg)
	o.WithClock(compClock())

	run := &SagaRun{RunID: "r2", Steps: []SagaStep{
		{StepID: "s1", Action: "create", CompAction: "undo-create"},
		{StepID: "s2", Action: "fail-me"},
	}}
	err := o.Execute(context.Background(), run, func(_ context.Context, s *SagaStep) error {
		if s.Action == "fail-me" {
			return errors.New("boom")
		}
		return nil
	})
	if err == nil {
		t.Fatal("expected error from failed step")
	}
	if run.Status != SagaCompensated {
		t.Fatalf("expected COMPENSATED, got %s", run.Status)
	}
}

func TestOrchestrator_CompensationFailureMarksFailed(t *testing.T) {
	reg := NewReversibilityRegistry()
	o := NewSagaOrchestrator(reg)

	run := &SagaRun{RunID: "r3", Steps: []SagaStep{
		{StepID: "s1", Action: "create", CompAction: "undo-create"},
		{StepID: "s2", Action: "explode"},
	}}
	err := o.Execute(context.Background(), run, func(_ context.Context, s *SagaStep) error {
		if s.Action == "explode" {
			return errors.New("step fail")
		}
		if s.Action == "undo-create" {
			return errors.New("comp fail")
		}
		return nil
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if run.Status != SagaFailed {
		t.Fatalf("expected FAILED, got %s", run.Status)
	}
}

func TestOrchestrator_GetRun(t *testing.T) {
	reg := NewReversibilityRegistry()
	o := NewSagaOrchestrator(reg)
	run := &SagaRun{RunID: "r4", Steps: []SagaStep{{StepID: "s1", Action: "noop"}}}
	o.Execute(context.Background(), run, func(_ context.Context, _ *SagaStep) error { return nil })

	got, ok := o.GetRun("r4")
	if !ok || got.RunID != "r4" {
		t.Fatal("expected to find run r4")
	}
}

func TestOrchestrator_GetRunNotFound(t *testing.T) {
	o := NewSagaOrchestrator(NewReversibilityRegistry())
	_, ok := o.GetRun("missing")
	if ok {
		t.Fatal("expected not found")
	}
}

func TestOrchestrator_ContentHashSet(t *testing.T) {
	o := NewSagaOrchestrator(NewReversibilityRegistry())
	run := &SagaRun{RunID: "r5", Steps: []SagaStep{{StepID: "s1", Action: "a"}}}
	o.Execute(context.Background(), run, func(_ context.Context, _ *SagaStep) error { return nil })
	if run.ContentHash == "" {
		t.Fatal("expected non-empty content hash after execution")
	}
}

func TestOrchestrator_EmptySteps(t *testing.T) {
	o := NewSagaOrchestrator(NewReversibilityRegistry())
	run := &SagaRun{RunID: "r6", Steps: []SagaStep{}}
	err := o.Execute(context.Background(), run, func(_ context.Context, _ *SagaStep) error { return nil })
	if err != nil {
		t.Fatal("empty steps should succeed")
	}
	if run.Status != SagaCompleted {
		t.Fatalf("expected COMPLETED, got %s", run.Status)
	}
}

func TestOrchestrator_FirstStepFailsNoCompensation(t *testing.T) {
	o := NewSagaOrchestrator(NewReversibilityRegistry())
	run := &SagaRun{RunID: "r7", Steps: []SagaStep{
		{StepID: "s1", Action: "fail"},
	}}
	err := o.Execute(context.Background(), run, func(_ context.Context, _ *SagaStep) error {
		return errors.New("immediate fail")
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if run.Status != SagaCompensated {
		t.Fatalf("expected COMPENSATED (nothing to compensate), got %s", run.Status)
	}
}
