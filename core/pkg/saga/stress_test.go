package saga

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

var sagaClock = func() time.Time { return time.Date(2026, 4, 12, 0, 0, 0, 0, time.UTC) }

func make20StepRun(id string) *SagaRun {
	steps := make([]SagaStep, 20)
	for i := range steps {
		steps[i] = SagaStep{
			StepID:     fmt.Sprintf("step-%d", i),
			Action:     fmt.Sprintf("action-%d", i),
			CompAction: fmt.Sprintf("comp-%d", i),
		}
	}
	return &SagaRun{RunID: id, Steps: steps}
}

func successExecutor(_ context.Context, _ *SagaStep) error { return nil }

// --- 20-Step Saga ---

func TestStress_Saga_20StepSuccess(t *testing.T) {
	reg := NewReversibilityRegistry()
	orch := NewSagaOrchestrator(reg)
	orch.WithClock(sagaClock)
	run := make20StepRun("saga-20")
	err := orch.Execute(context.Background(), run, successExecutor)
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != SagaCompleted {
		t.Fatalf("expected COMPLETED, got %s", run.Status)
	}
}

func TestStress_Saga_20StepContentHash(t *testing.T) {
	reg := NewReversibilityRegistry()
	orch := NewSagaOrchestrator(reg)
	orch.WithClock(sagaClock)
	run := make20StepRun("saga-hash")
	orch.Execute(context.Background(), run, successExecutor)
	if run.ContentHash == "" {
		t.Fatal("expected content hash to be set")
	}
}

// --- Fail at Each Step Position (20 tests) ---

func TestStress_Saga_FailAtStep0(t *testing.T) { testSagaFailAt(t, 0) }
func TestStress_Saga_FailAtStep1(t *testing.T) { testSagaFailAt(t, 1) }
func TestStress_Saga_FailAtStep2(t *testing.T) { testSagaFailAt(t, 2) }
func TestStress_Saga_FailAtStep3(t *testing.T) { testSagaFailAt(t, 3) }
func TestStress_Saga_FailAtStep4(t *testing.T) { testSagaFailAt(t, 4) }
func TestStress_Saga_FailAtStep5(t *testing.T) { testSagaFailAt(t, 5) }
func TestStress_Saga_FailAtStep6(t *testing.T) { testSagaFailAt(t, 6) }
func TestStress_Saga_FailAtStep7(t *testing.T) { testSagaFailAt(t, 7) }
func TestStress_Saga_FailAtStep8(t *testing.T) { testSagaFailAt(t, 8) }
func TestStress_Saga_FailAtStep9(t *testing.T) { testSagaFailAt(t, 9) }
func TestStress_Saga_FailAtStep10(t *testing.T) { testSagaFailAt(t, 10) }
func TestStress_Saga_FailAtStep11(t *testing.T) { testSagaFailAt(t, 11) }
func TestStress_Saga_FailAtStep12(t *testing.T) { testSagaFailAt(t, 12) }
func TestStress_Saga_FailAtStep13(t *testing.T) { testSagaFailAt(t, 13) }
func TestStress_Saga_FailAtStep14(t *testing.T) { testSagaFailAt(t, 14) }
func TestStress_Saga_FailAtStep15(t *testing.T) { testSagaFailAt(t, 15) }
func TestStress_Saga_FailAtStep16(t *testing.T) { testSagaFailAt(t, 16) }
func TestStress_Saga_FailAtStep17(t *testing.T) { testSagaFailAt(t, 17) }
func TestStress_Saga_FailAtStep18(t *testing.T) { testSagaFailAt(t, 18) }
func TestStress_Saga_FailAtStep19(t *testing.T) { testSagaFailAt(t, 19) }

func testSagaFailAt(t *testing.T, failIdx int) {
	t.Helper()
	reg := NewReversibilityRegistry()
	orch := NewSagaOrchestrator(reg)
	orch.WithClock(sagaClock)
	run := make20StepRun(fmt.Sprintf("fail-at-%d", failIdx))
	executor := func(_ context.Context, step *SagaStep) error {
		if step.StepID == fmt.Sprintf("step-%d", failIdx) {
			return fmt.Errorf("fail at step %d", failIdx)
		}
		return nil
	}
	err := orch.Execute(context.Background(), run, executor)
	if err == nil {
		t.Fatal("expected error")
	}
	if run.FailedStep != failIdx {
		t.Fatalf("expected failed step %d, got %d", failIdx, run.FailedStep)
	}
	if run.Status != SagaCompensated {
		t.Fatalf("expected COMPENSATED, got %s", run.Status)
	}
}

// --- Compensation Failure at Each Position ---

func TestStress_Saga_CompFailStep0(t *testing.T) { testSagaCompFail(t, 0) }
func TestStress_Saga_CompFailStep3(t *testing.T) { testSagaCompFail(t, 3) }
func TestStress_Saga_CompFailStep9(t *testing.T) { testSagaCompFail(t, 9) }

func testSagaCompFail(t *testing.T, compFailIdx int) {
	t.Helper()
	reg := NewReversibilityRegistry()
	orch := NewSagaOrchestrator(reg)
	orch.WithClock(sagaClock)
	run := make20StepRun(fmt.Sprintf("comp-fail-%d", compFailIdx))
	// Fail at step 10, compensation fails at compFailIdx
	executor := func(_ context.Context, step *SagaStep) error {
		if step.StepID == "step-10" {
			return fmt.Errorf("fail at step 10")
		}
		if step.StepID == fmt.Sprintf("step-%d-comp", compFailIdx) {
			return fmt.Errorf("compensation failed at %d", compFailIdx)
		}
		return nil
	}
	err := orch.Execute(context.Background(), run, executor)
	if err == nil {
		t.Fatal("expected error")
	}
	if run.Status != SagaFailed {
		t.Fatalf("expected FAILED (compensation failure), got %s", run.Status)
	}
}

// --- Concurrent Sagas 30 Goroutines ---

func TestStress_Concurrent_Sagas_30Goroutines(t *testing.T) {
	reg := NewReversibilityRegistry()
	orch := NewSagaOrchestrator(reg)
	orch.WithClock(sagaClock)
	var wg sync.WaitGroup
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			run := &SagaRun{
				RunID: fmt.Sprintf("conc-%d", id),
				Steps: []SagaStep{
					{StepID: "s1", Action: "a1", CompAction: "c1"},
					{StepID: "s2", Action: "a2", CompAction: "c2"},
				},
			}
			orch.Execute(context.Background(), run, successExecutor)
		}(i)
	}
	wg.Wait()
}

func TestStress_Concurrent_GetRun(t *testing.T) {
	reg := NewReversibilityRegistry()
	orch := NewSagaOrchestrator(reg)
	orch.WithClock(sagaClock)
	run := &SagaRun{RunID: "get-run", Steps: []SagaStep{{StepID: "s1", Action: "a1"}}}
	orch.Execute(context.Background(), run, successExecutor)
	var wg sync.WaitGroup
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, ok := orch.GetRun("get-run")
			if !ok || r == nil {
				t.Error("expected to find run")
			}
		}()
	}
	wg.Wait()
}

// --- Registry with 100 Actions ---

func TestStress_Registry_100Actions(t *testing.T) {
	reg := NewReversibilityRegistry()
	for i := 0; i < 100; i++ {
		err := reg.Register(ActionRegistration{
			ActionID:       fmt.Sprintf("action-%d", i),
			Reversible:     i%2 == 0,
			CompensatingID: fmt.Sprintf("comp-%d", i),
			MaxRetries:     3,
			Timeout:        time.Second,
		})
		if err != nil {
			t.Fatalf("register %d: %v", i, err)
		}
	}
	actions := reg.ListActions()
	if len(actions) != 100 {
		t.Fatalf("expected 100 actions, got %d", len(actions))
	}
}

func TestStress_Registry_Lookup(t *testing.T) {
	reg := NewReversibilityRegistry()
	reg.Register(ActionRegistration{ActionID: "a1", Reversible: true, CompensatingID: "c1"})
	action, ok := reg.Lookup("a1")
	if !ok || action.ActionID != "a1" {
		t.Fatal("expected to find action a1")
	}
}

func TestStress_Registry_LookupMissing(t *testing.T) {
	reg := NewReversibilityRegistry()
	_, ok := reg.Lookup("ghost")
	if ok {
		t.Fatal("expected not found")
	}
}

func TestStress_Registry_IsReversible(t *testing.T) {
	reg := NewReversibilityRegistry()
	reg.Register(ActionRegistration{ActionID: "rev", Reversible: true})
	reg.Register(ActionRegistration{ActionID: "irrev", Reversible: false})
	if !reg.IsReversible("rev") {
		t.Fatal("expected reversible")
	}
	if reg.IsReversible("irrev") {
		t.Fatal("expected not reversible")
	}
}

func TestStress_Registry_EmptyActionIDRejected(t *testing.T) {
	reg := NewReversibilityRegistry()
	err := reg.Register(ActionRegistration{})
	if err == nil {
		t.Fatal("expected error for empty action ID")
	}
}

func TestStress_Saga_GetRunNotFound(t *testing.T) {
	reg := NewReversibilityRegistry()
	orch := NewSagaOrchestrator(reg)
	_, ok := orch.GetRun("ghost")
	if ok {
		t.Fatal("expected not found")
	}
}

func TestStress_Saga_StepStatusTracking(t *testing.T) {
	reg := NewReversibilityRegistry()
	orch := NewSagaOrchestrator(reg)
	orch.WithClock(sagaClock)
	run := &SagaRun{
		RunID: "status-track",
		Steps: []SagaStep{{StepID: "s1", Action: "a1"}},
	}
	orch.Execute(context.Background(), run, successExecutor)
	if run.Steps[0].Status != StepCompleted {
		t.Fatalf("expected COMPLETED, got %s", run.Steps[0].Status)
	}
}

func TestStress_Saga_CompletedAtSet(t *testing.T) {
	reg := NewReversibilityRegistry()
	orch := NewSagaOrchestrator(reg)
	orch.WithClock(sagaClock)
	run := &SagaRun{RunID: "time-check", Steps: []SagaStep{{StepID: "s1", Action: "a1"}}}
	orch.Execute(context.Background(), run, successExecutor)
	if run.CompletedAt.IsZero() {
		t.Fatal("expected completed time to be set")
	}
}

func TestStress_Saga_FailedStepErrorMessage(t *testing.T) {
	reg := NewReversibilityRegistry()
	orch := NewSagaOrchestrator(reg)
	orch.WithClock(sagaClock)
	run := &SagaRun{RunID: "err-msg", Steps: []SagaStep{{StepID: "s1", Action: "a1", CompAction: "c1"}}}
	err := orch.Execute(context.Background(), run, func(_ context.Context, _ *SagaStep) error {
		return fmt.Errorf("boom")
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if run.Error == "" {
		t.Fatal("expected error message on run")
	}
}

func TestStress_Registry_Overwrite(t *testing.T) {
	reg := NewReversibilityRegistry()
	reg.Register(ActionRegistration{ActionID: "a1", Reversible: true})
	reg.Register(ActionRegistration{ActionID: "a1", Reversible: false})
	if reg.IsReversible("a1") {
		t.Fatal("expected overwritten to non-reversible")
	}
}

func TestStress_Registry_ConcurrentRegister(t *testing.T) {
	reg := NewReversibilityRegistry()
	var wg sync.WaitGroup
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			reg.Register(ActionRegistration{ActionID: fmt.Sprintf("ca-%d", id), Reversible: true})
		}(i)
	}
	wg.Wait()
	if len(reg.ListActions()) != 30 {
		t.Fatalf("expected 30 actions, got %d", len(reg.ListActions()))
	}
}

func TestStress_Saga_SingleStepSuccess(t *testing.T) {
	reg := NewReversibilityRegistry()
	orch := NewSagaOrchestrator(reg)
	orch.WithClock(sagaClock)
	run := &SagaRun{RunID: "single", Steps: []SagaStep{{StepID: "s1", Action: "a1"}}}
	err := orch.Execute(context.Background(), run, successExecutor)
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != SagaCompleted {
		t.Fatalf("expected COMPLETED, got %s", run.Status)
	}
}

func TestStress_Saga_StartedAtSet(t *testing.T) {
	reg := NewReversibilityRegistry()
	orch := NewSagaOrchestrator(reg)
	orch.WithClock(sagaClock)
	run := &SagaRun{RunID: "started-at", Steps: []SagaStep{{StepID: "s1", Action: "a1"}}}
	orch.Execute(context.Background(), run, successExecutor)
	if run.StartedAt.IsZero() {
		t.Fatal("expected started_at to be set")
	}
}
