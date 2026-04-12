package saga

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

func fixedClock() func() time.Time {
	t := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	return func() time.Time {
		t = t.Add(time.Second)
		return t
	}
}

func TestSagaOrchestrator_HappyPath(t *testing.T) {
	reg := NewReversibilityRegistry()
	orch := NewSagaOrchestrator(reg)
	orch.WithClock(fixedClock())

	run := &SagaRun{
		RunID: "run-happy",
		Steps: []SagaStep{
			{StepID: "s1", Action: "create", CompAction: "delete"},
			{StepID: "s2", Action: "deploy", CompAction: "undeploy"},
			{StepID: "s3", Action: "notify", CompAction: ""},
		},
	}

	executor := func(ctx context.Context, step *SagaStep) error {
		return nil
	}

	err := orch.Execute(context.Background(), run, executor)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if run.Status != SagaCompleted {
		t.Errorf("expected status COMPLETED, got %s", run.Status)
	}

	for i, step := range run.Steps {
		if step.Status != StepCompleted {
			t.Errorf("step %d: expected status COMPLETED, got %s", i, step.Status)
		}
	}

	if run.ContentHash == "" {
		t.Error("expected content hash to be set")
	}
	if !strings.HasPrefix(run.ContentHash, "sha256:") {
		t.Errorf("expected hash prefix sha256:, got %s", run.ContentHash)
	}
}

func TestSagaOrchestrator_FailureAndCompensation(t *testing.T) {
	reg := NewReversibilityRegistry()
	orch := NewSagaOrchestrator(reg)
	orch.WithClock(fixedClock())

	var compensated []string

	run := &SagaRun{
		RunID: "run-fail",
		Steps: []SagaStep{
			{StepID: "s1", Action: "create", CompAction: "delete"},
			{StepID: "s2", Action: "deploy", CompAction: "undeploy"},
			{StepID: "s3", Action: "notify", CompAction: "unnotify"},
		},
	}

	executor := func(ctx context.Context, step *SagaStep) error {
		// Forward step s3 fails
		if step.Action == "notify" {
			return fmt.Errorf("notification service down")
		}
		// Track compensations
		if strings.HasSuffix(step.StepID, "-comp") {
			compensated = append(compensated, step.Action)
		}
		return nil
	}

	err := orch.Execute(context.Background(), run, executor)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if run.Status != SagaCompensated {
		t.Errorf("expected status COMPENSATED, got %s", run.Status)
	}

	if run.FailedStep != 2 {
		t.Errorf("expected failed step index 2, got %d", run.FailedStep)
	}

	// Steps 0 and 1 completed then compensated; step 2 failed
	if run.Steps[0].Status != StepCompensated {
		t.Errorf("step 0: expected COMPENSATED, got %s", run.Steps[0].Status)
	}
	if run.Steps[1].Status != StepCompensated {
		t.Errorf("step 1: expected COMPENSATED, got %s", run.Steps[1].Status)
	}
	if run.Steps[2].Status != StepFailed {
		t.Errorf("step 2: expected FAILED, got %s", run.Steps[2].Status)
	}

	// Compensations should run in reverse: undeploy before delete
	if len(compensated) != 2 {
		t.Fatalf("expected 2 compensations, got %d", len(compensated))
	}
	if compensated[0] != "undeploy" {
		t.Errorf("expected first compensation 'undeploy', got %s", compensated[0])
	}
	if compensated[1] != "delete" {
		t.Errorf("expected second compensation 'delete', got %s", compensated[1])
	}
}

func TestSagaOrchestrator_CompensationFailure(t *testing.T) {
	reg := NewReversibilityRegistry()
	orch := NewSagaOrchestrator(reg)
	orch.WithClock(fixedClock())

	run := &SagaRun{
		RunID: "run-compfail",
		Steps: []SagaStep{
			{StepID: "s1", Action: "create", CompAction: "delete"},
			{StepID: "s2", Action: "deploy", CompAction: "undeploy"},
		},
	}

	executor := func(ctx context.Context, step *SagaStep) error {
		if step.Action == "deploy" && !strings.HasSuffix(step.StepID, "-comp") {
			return fmt.Errorf("deploy failed")
		}
		// Compensation of step s1 also fails
		if step.Action == "delete" {
			return fmt.Errorf("cannot delete")
		}
		return nil
	}

	err := orch.Execute(context.Background(), run, executor)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if run.Status != SagaFailed {
		t.Errorf("expected status FAILED, got %s", run.Status)
	}

	if !strings.Contains(run.Error, "compensation failed") {
		t.Errorf("expected error to mention compensation failure, got: %s", run.Error)
	}
}

func TestSagaOrchestrator_EmptyRun(t *testing.T) {
	reg := NewReversibilityRegistry()
	orch := NewSagaOrchestrator(reg)
	orch.WithClock(fixedClock())

	run := &SagaRun{
		RunID: "run-empty",
		Steps: []SagaStep{},
	}

	err := orch.Execute(context.Background(), run, func(ctx context.Context, step *SagaStep) error {
		t.Fatal("executor should not be called for empty run")
		return nil
	})

	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if run.Status != SagaCompleted {
		t.Errorf("expected status COMPLETED, got %s", run.Status)
	}
}

func TestSagaOrchestrator_SingleStepFailure(t *testing.T) {
	reg := NewReversibilityRegistry()
	orch := NewSagaOrchestrator(reg)
	orch.WithClock(fixedClock())

	run := &SagaRun{
		RunID: "run-single",
		Steps: []SagaStep{
			{StepID: "s1", Action: "create", CompAction: "delete"},
		},
	}

	executor := func(ctx context.Context, step *SagaStep) error {
		if step.Action == "create" && !strings.HasSuffix(step.StepID, "-comp") {
			return fmt.Errorf("creation failed")
		}
		return nil
	}

	err := orch.Execute(context.Background(), run, executor)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	// First step failed — no prior completed steps to compensate
	if run.Status != SagaCompensated {
		t.Errorf("expected status COMPENSATED, got %s", run.Status)
	}

	if run.Steps[0].Status != StepFailed {
		t.Errorf("step 0: expected FAILED, got %s", run.Steps[0].Status)
	}
}

func TestSagaOrchestrator_ContentHash(t *testing.T) {
	reg := NewReversibilityRegistry()
	orch := NewSagaOrchestrator(reg)
	orch.WithClock(fixedClock())

	run := &SagaRun{
		RunID: "run-hash",
		Steps: []SagaStep{
			{StepID: "s1", Action: "act1", CompAction: "comp1"},
		},
	}

	err := orch.Execute(context.Background(), run, func(ctx context.Context, step *SagaStep) error {
		return nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if run.ContentHash == "" {
		t.Fatal("expected content hash to be set")
	}
	if !strings.HasPrefix(run.ContentHash, "sha256:") {
		t.Errorf("expected sha256: prefix, got %s", run.ContentHash)
	}
	// SHA-256 hex is 64 chars + "sha256:" prefix = 71 chars
	if len(run.ContentHash) != 71 {
		t.Errorf("expected hash length 71, got %d", len(run.ContentHash))
	}
}

func TestSagaOrchestrator_GetRun(t *testing.T) {
	reg := NewReversibilityRegistry()
	orch := NewSagaOrchestrator(reg)
	orch.WithClock(fixedClock())

	run := &SagaRun{
		RunID: "run-get",
		Steps: []SagaStep{
			{StepID: "s1", Action: "act1"},
		},
	}

	// Before execution — not found
	if _, ok := orch.GetRun("run-get"); ok {
		t.Error("expected run not found before execution")
	}

	err := orch.Execute(context.Background(), run, func(ctx context.Context, step *SagaStep) error {
		return nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// After execution — found
	got, ok := orch.GetRun("run-get")
	if !ok {
		t.Fatal("expected run to be found after execution")
	}
	if got.RunID != "run-get" {
		t.Errorf("expected RunID 'run-get', got %s", got.RunID)
	}
	if got.Status != SagaCompleted {
		t.Errorf("expected COMPLETED, got %s", got.Status)
	}

	// Unknown run — not found
	if _, ok := orch.GetRun("nonexistent"); ok {
		t.Error("expected nonexistent run not found")
	}
}
