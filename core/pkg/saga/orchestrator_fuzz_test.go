package saga

import (
	"context"
	"fmt"
	"testing"
)

// FuzzSagaExecution fuzzes saga step execution ordering.
// Invariants:
//   - Must never panic
//   - Status must be COMPLETED, COMPENSATED, or FAILED
//   - ContentHash must be non-empty on completion
func FuzzSagaExecution(f *testing.F) {
	f.Add(3, 1, true)  // 3 steps, fail at step 1, compensation succeeds
	f.Add(1, 0, true)  // 1 step, fail at step 0
	f.Add(5, 3, false) // 5 steps, fail at step 3, compensation fails
	f.Add(0, 0, true)  // 0 steps
	f.Add(10, 9, true) // 10 steps, fail at last

	registry := NewReversibilityRegistry()

	f.Fuzz(func(t *testing.T, numSteps, failAt int, compSucceeds bool) {
		// Clamp inputs to reasonable ranges
		if numSteps < 0 {
			numSteps = 0
		}
		if numSteps > 20 {
			numSteps = 20
		}
		if failAt < -1 {
			failAt = -1 // -1 means no failure
		}
		if failAt >= numSteps {
			failAt = -1
		}

		steps := make([]SagaStep, numSteps)
		for i := range steps {
			steps[i] = SagaStep{
				StepID:     fmt.Sprintf("step-%d", i),
				Action:     fmt.Sprintf("action-%d", i),
				CompAction: fmt.Sprintf("comp-%d", i),
			}
		}

		run := &SagaRun{
			RunID: fmt.Sprintf("fuzz-run-%d-%d", numSteps, failAt),
			Steps: steps,
		}

		orch := NewSagaOrchestrator(registry)

		executor := func(_ context.Context, step *SagaStep) error {
			// Fail at the designated step
			if step.Action == fmt.Sprintf("action-%d", failAt) {
				return fmt.Errorf("simulated failure at step %d", failAt)
			}
			// Fail compensation if configured
			if !compSucceeds && step.StepID != "" && len(step.StepID) > 5 && step.StepID[len(step.StepID)-5:] == "-comp" {
				return fmt.Errorf("compensation failed")
			}
			return nil
		}

		_ = orch.Execute(context.Background(), run, executor)

		// Status must be terminal
		switch run.Status {
		case SagaCompleted, SagaCompensated, SagaFailed:
			// valid terminal states
		default:
			if numSteps > 0 {
				t.Fatalf("non-terminal status: %s", run.Status)
			}
		}

		// ContentHash should be set for completed runs
		if run.Status == SagaCompleted || run.Status == SagaCompensated || run.Status == SagaFailed {
			if run.ContentHash == "" {
				t.Fatal("missing content hash on terminal run")
			}
		}
	})
}
