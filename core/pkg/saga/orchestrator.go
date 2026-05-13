// Package saga implements multi-step transactional workflows with compensating
// actions for HELM governed execution.
//
// Per HELM 2030 Spec: every side-effecting workflow must be reversible.
// The SagaOrchestrator executes steps forward and, on failure, runs
// compensating actions in reverse order to restore system invariants.
package saga

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
)

// SagaStatus tracks the lifecycle of a saga run.
type SagaStatus string

const (
	SagaRunning      SagaStatus = "RUNNING"
	SagaCompleted    SagaStatus = "COMPLETED"
	SagaCompensating SagaStatus = "COMPENSATING"
	SagaCompensated  SagaStatus = "COMPENSATED"
	SagaFailed       SagaStatus = "FAILED"
)

// StepStatus tracks individual step lifecycle.
type StepStatus string

const (
	StepPending      StepStatus = "PENDING"
	StepExecuting    StepStatus = "EXECUTING"
	StepCompleted    StepStatus = "COMPLETED"
	StepFailed       StepStatus = "FAILED"
	StepCompensating StepStatus = "COMPENSATING"
	StepCompensated  StepStatus = "COMPENSATED"
)

// SagaRun represents a multi-step transactional workflow.
type SagaRun struct {
	RunID       string     `json:"run_id"`
	Steps       []SagaStep `json:"steps"`
	Status      SagaStatus `json:"status"`
	StartedAt   time.Time  `json:"started_at"`
	CompletedAt time.Time  `json:"completed_at,omitempty"`
	FailedStep  int        `json:"failed_step,omitempty"` // index of the step that failed
	Error       string     `json:"error,omitempty"`
	ContentHash string     `json:"content_hash"`
}

// SagaStep is one step in a saga.
type SagaStep struct {
	StepID     string     `json:"step_id"`
	Action     string     `json:"action"`      // forward action name
	CompAction string     `json:"comp_action"` // compensating action name
	Status     StepStatus `json:"status"`
	StartedAt  time.Time  `json:"started_at,omitempty"`
	EndedAt    time.Time  `json:"ended_at,omitempty"`
	Error      string     `json:"error,omitempty"`
	ReceiptID  string     `json:"receipt_id,omitempty"` // linked receipt
}

// StepExecutor is called for each forward or compensating step.
type StepExecutor func(ctx context.Context, step *SagaStep) error

// SagaOrchestrator manages multi-step transactional workflows with compensating actions.
type SagaOrchestrator struct {
	mu       sync.Mutex
	runs     map[string]*SagaRun
	registry *ReversibilityRegistry
	clock    func() time.Time
}

// NewSagaOrchestrator creates a new orchestrator backed by the given registry.
func NewSagaOrchestrator(registry *ReversibilityRegistry) *SagaOrchestrator {
	return &SagaOrchestrator{
		runs:     make(map[string]*SagaRun),
		registry: registry,
		clock:    func() time.Time { return time.Now() },
	}
}

// WithClock injects a deterministic clock for testing.
func (o *SagaOrchestrator) WithClock(clock func() time.Time) {
	o.clock = clock
}

// Execute runs a saga forward. On any step failure, compensates in reverse order.
// The executor is called once per forward step and once per compensating step.
func (o *SagaOrchestrator) Execute(ctx context.Context, run *SagaRun, executor StepExecutor) error {
	o.mu.Lock()
	run.Status = SagaRunning
	run.StartedAt = o.clock()
	o.runs[run.RunID] = run
	o.mu.Unlock()

	// Forward execution
	for i := range run.Steps {
		step := &run.Steps[i]
		step.Status = StepExecuting
		step.StartedAt = o.clock()

		if err := executor(ctx, step); err != nil {
			step.Status = StepFailed
			step.EndedAt = o.clock()
			step.Error = err.Error()
			run.FailedStep = i
			run.Error = fmt.Sprintf("step %s failed: %v", step.StepID, err)

			// Compensate completed steps in reverse order
			compErr := o.compensate(ctx, run, i-1, executor)
			if compErr != nil {
				run.Status = SagaFailed
				run.Error += fmt.Sprintf("; compensation failed: %v", compErr)
			} else {
				run.Status = SagaCompensated
			}
			run.CompletedAt = o.clock()
			o.computeHash(run)
			return fmt.Errorf("saga %s: %s", run.RunID, run.Error)
		}

		step.Status = StepCompleted
		step.EndedAt = o.clock()
	}

	run.Status = SagaCompleted
	run.CompletedAt = o.clock()
	o.computeHash(run)
	return nil
}

// compensate runs compensating actions in reverse order from fromStep down to 0.
func (o *SagaOrchestrator) compensate(ctx context.Context, run *SagaRun, fromStep int, executor StepExecutor) error {
	run.Status = SagaCompensating
	var firstErr error

	for i := fromStep; i >= 0; i-- {
		step := &run.Steps[i]
		if step.Status != StepCompleted {
			continue // only compensate completed steps
		}
		if step.CompAction == "" {
			continue // no compensating action registered
		}

		step.Status = StepCompensating
		// Create a temporary compensation step for the executor
		compStep := &SagaStep{
			StepID:    step.StepID + "-comp",
			Action:    step.CompAction,
			Status:    StepExecuting,
			StartedAt: o.clock(),
		}

		if err := executor(ctx, compStep); err != nil {
			step.Error = fmt.Sprintf("compensation failed: %v", err)
			step.EndedAt = o.clock()
			if firstErr == nil {
				firstErr = fmt.Errorf("compensation of step %s failed: %w", step.StepID, err)
			}
		} else {
			step.Status = StepCompensated
			step.EndedAt = o.clock()
		}
	}

	return firstErr
}

// GetRun returns the current state of a saga run.
func (o *SagaOrchestrator) GetRun(runID string) (*SagaRun, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	run, ok := o.runs[runID]
	return run, ok
}

// computeHash computes a JCS content hash for the saga run.
func (o *SagaOrchestrator) computeHash(run *SagaRun) {
	data, err := canonicalize.JCS(run)
	if err != nil {
		return
	}
	h := sha256.Sum256(data)
	run.ContentHash = "sha256:" + hex.EncodeToString(h[:])
}
