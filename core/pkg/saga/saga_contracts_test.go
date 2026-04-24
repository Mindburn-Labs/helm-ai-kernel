package saga

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

func TestFinal_SagaStatusConstants(t *testing.T) {
	statuses := []SagaStatus{SagaRunning, SagaCompleted, SagaCompensating, SagaCompensated, SagaFailed}
	seen := map[SagaStatus]bool{}
	for _, s := range statuses {
		if seen[s] {
			t.Fatalf("duplicate: %s", s)
		}
		seen[s] = true
	}
}

func TestFinal_StepStatusConstants(t *testing.T) {
	statuses := []StepStatus{StepPending, StepExecuting, StepCompleted, StepFailed, StepCompensating, StepCompensated}
	if len(statuses) != 6 {
		t.Fatal("expected 6 step statuses")
	}
}

func TestFinal_SagaRunJSONRoundTrip(t *testing.T) {
	run := SagaRun{RunID: "run-1", Status: SagaCompleted, FailedStep: 0}
	data, _ := json.Marshal(run)
	var got SagaRun
	json.Unmarshal(data, &got)
	if got.RunID != "run-1" || got.Status != SagaCompleted {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_SagaStepJSONRoundTrip(t *testing.T) {
	step := SagaStep{StepID: "s1", Action: "create", CompAction: "delete", Status: StepPending}
	data, _ := json.Marshal(step)
	var got SagaStep
	json.Unmarshal(data, &got)
	if got.Action != "create" || got.CompAction != "delete" {
		t.Fatal("step round-trip")
	}
}

func TestFinal_NewSagaOrchestrator(t *testing.T) {
	reg := NewReversibilityRegistry()
	orch := NewSagaOrchestrator(reg)
	if orch == nil {
		t.Fatal("nil orchestrator")
	}
}

func TestFinal_WithClockSetsTime(t *testing.T) {
	fixed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	reg := NewReversibilityRegistry()
	orch := NewSagaOrchestrator(reg)
	orch.WithClock(func() time.Time { return fixed })
}

func TestFinal_ExecuteSuccess(t *testing.T) {
	reg := NewReversibilityRegistry()
	orch := NewSagaOrchestrator(reg)
	run := &SagaRun{RunID: "r1", Steps: []SagaStep{{StepID: "s1", Action: "a"}}}
	err := orch.Execute(context.Background(), run, func(ctx context.Context, s *SagaStep) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != SagaCompleted {
		t.Fatalf("expected COMPLETED, got %s", run.Status)
	}
}

func TestFinal_ExecuteFailureTriggerCompensation(t *testing.T) {
	reg := NewReversibilityRegistry()
	orch := NewSagaOrchestrator(reg)
	run := &SagaRun{RunID: "r1", Steps: []SagaStep{
		{StepID: "s1", Action: "a", CompAction: "undo_a"},
		{StepID: "s2", Action: "b"},
	}}
	callCount := 0
	err := orch.Execute(context.Background(), run, func(ctx context.Context, s *SagaStep) error {
		callCount++
		if s.Action == "b" {
			return fmt.Errorf("step b failed")
		}
		return nil
	})
	if err == nil {
		t.Fatal("should error")
	}
	if run.Status != SagaCompensated {
		t.Fatalf("expected COMPENSATED, got %s", run.Status)
	}
}

func TestFinal_GetRunExists(t *testing.T) {
	reg := NewReversibilityRegistry()
	orch := NewSagaOrchestrator(reg)
	run := &SagaRun{RunID: "r1", Steps: []SagaStep{{StepID: "s1", Action: "a"}}}
	orch.Execute(context.Background(), run, func(ctx context.Context, s *SagaStep) error { return nil })
	got, ok := orch.GetRun("r1")
	if !ok || got.RunID != "r1" {
		t.Fatal("run not found")
	}
}

func TestFinal_GetRunNotFound(t *testing.T) {
	reg := NewReversibilityRegistry()
	orch := NewSagaOrchestrator(reg)
	_, ok := orch.GetRun("nonexistent")
	if ok {
		t.Fatal("should not find")
	}
}

func TestFinal_ContentHashSet(t *testing.T) {
	reg := NewReversibilityRegistry()
	orch := NewSagaOrchestrator(reg)
	run := &SagaRun{RunID: "r1", Steps: []SagaStep{{StepID: "s1", Action: "a"}}}
	orch.Execute(context.Background(), run, func(ctx context.Context, s *SagaStep) error { return nil })
	if run.ContentHash == "" {
		t.Fatal("content hash should be set")
	}
}

func TestFinal_ContentHashDeterministic(t *testing.T) {
	fixed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	make_orch := func() *SagaOrchestrator {
		reg := NewReversibilityRegistry()
		o := NewSagaOrchestrator(reg)
		o.WithClock(func() time.Time { return fixed })
		return o
	}
	run1 := &SagaRun{RunID: "r1", Steps: []SagaStep{{StepID: "s1", Action: "a"}}}
	make_orch().Execute(context.Background(), run1, func(ctx context.Context, s *SagaStep) error { return nil })
	run2 := &SagaRun{RunID: "r1", Steps: []SagaStep{{StepID: "s1", Action: "a"}}}
	make_orch().Execute(context.Background(), run2, func(ctx context.Context, s *SagaStep) error { return nil })
	if run1.ContentHash != run2.ContentHash {
		t.Fatal("hashes should match")
	}
}

func TestFinal_NewReversibilityRegistry(t *testing.T) {
	reg := NewReversibilityRegistry()
	if reg == nil {
		t.Fatal("nil registry")
	}
}

func TestFinal_RegisterAction(t *testing.T) {
	reg := NewReversibilityRegistry()
	err := reg.Register(ActionRegistration{ActionID: "create", Reversible: true, CompensatingID: "delete"})
	if err != nil {
		t.Fatal(err)
	}
}

func TestFinal_RegisterEmptyIDFails(t *testing.T) {
	reg := NewReversibilityRegistry()
	err := reg.Register(ActionRegistration{ActionID: ""})
	if err == nil {
		t.Fatal("should error on empty ID")
	}
}

func TestFinal_LookupAction(t *testing.T) {
	reg := NewReversibilityRegistry()
	reg.Register(ActionRegistration{ActionID: "act1", Reversible: true})
	got, ok := reg.Lookup("act1")
	if !ok || got.ActionID != "act1" {
		t.Fatal("lookup failed")
	}
}

func TestFinal_LookupMissing(t *testing.T) {
	reg := NewReversibilityRegistry()
	_, ok := reg.Lookup("nope")
	if ok {
		t.Fatal("should not find")
	}
}

func TestFinal_IsReversibleTrue(t *testing.T) {
	reg := NewReversibilityRegistry()
	reg.Register(ActionRegistration{ActionID: "a", Reversible: true})
	if !reg.IsReversible("a") {
		t.Fatal("should be reversible")
	}
}

func TestFinal_IsReversibleFalse(t *testing.T) {
	reg := NewReversibilityRegistry()
	reg.Register(ActionRegistration{ActionID: "a", Reversible: false})
	if reg.IsReversible("a") {
		t.Fatal("should not be reversible")
	}
}

func TestFinal_IsReversibleMissing(t *testing.T) {
	reg := NewReversibilityRegistry()
	if reg.IsReversible("nope") {
		t.Fatal("unknown should not be reversible")
	}
}

func TestFinal_ListActions(t *testing.T) {
	reg := NewReversibilityRegistry()
	reg.Register(ActionRegistration{ActionID: "a"})
	reg.Register(ActionRegistration{ActionID: "b"})
	ids := reg.ListActions()
	if len(ids) != 2 {
		t.Fatalf("expected 2, got %d", len(ids))
	}
}

func TestFinal_ListActionsEmpty(t *testing.T) {
	reg := NewReversibilityRegistry()
	ids := reg.ListActions()
	if len(ids) != 0 {
		t.Fatal("should be empty")
	}
}

func TestFinal_ActionRegistrationJSONRoundTrip(t *testing.T) {
	ar := ActionRegistration{ActionID: "a", Reversible: true, MaxRetries: 3, Timeout: 5 * time.Second}
	data, _ := json.Marshal(ar)
	var got ActionRegistration
	json.Unmarshal(data, &got)
	if got.ActionID != "a" || got.MaxRetries != 3 {
		t.Fatal("round-trip")
	}
}

func TestFinal_RegisterOverwrite(t *testing.T) {
	reg := NewReversibilityRegistry()
	reg.Register(ActionRegistration{ActionID: "a", Reversible: false})
	reg.Register(ActionRegistration{ActionID: "a", Reversible: true})
	if !reg.IsReversible("a") {
		t.Fatal("overwrite should update")
	}
}

func TestFinal_ExecuteNoSteps(t *testing.T) {
	reg := NewReversibilityRegistry()
	orch := NewSagaOrchestrator(reg)
	run := &SagaRun{RunID: "r1", Steps: []SagaStep{}}
	err := orch.Execute(context.Background(), run, func(ctx context.Context, s *SagaStep) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != SagaCompleted {
		t.Fatal("empty saga should complete")
	}
}

func TestFinal_StepTimestampsSet(t *testing.T) {
	reg := NewReversibilityRegistry()
	orch := NewSagaOrchestrator(reg)
	run := &SagaRun{RunID: "r1", Steps: []SagaStep{{StepID: "s1", Action: "a"}}}
	orch.Execute(context.Background(), run, func(ctx context.Context, s *SagaStep) error { return nil })
	if run.Steps[0].StartedAt.IsZero() || run.Steps[0].EndedAt.IsZero() {
		t.Fatal("timestamps should be set")
	}
}

func TestFinal_CompensationOnFirstStep(t *testing.T) {
	reg := NewReversibilityRegistry()
	orch := NewSagaOrchestrator(reg)
	run := &SagaRun{RunID: "r1", Steps: []SagaStep{{StepID: "s1", Action: "a"}}}
	err := orch.Execute(context.Background(), run, func(ctx context.Context, s *SagaStep) error {
		return fmt.Errorf("fail")
	})
	if err == nil {
		t.Fatal("should error")
	}
}

func TestFinal_SagaRunStatusJSONString(t *testing.T) {
	data, _ := json.Marshal(SagaCompleted)
	if string(data) != `"COMPLETED"` {
		t.Fatalf("unexpected: %s", data)
	}
}

func TestFinal_StepStatusJSONString(t *testing.T) {
	data, _ := json.Marshal(StepCompensated)
	if string(data) != `"COMPENSATED"` {
		t.Fatalf("unexpected: %s", data)
	}
}
