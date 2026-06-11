package skills

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// Evaluator runs skills in sandbox/canary mode and reports results.
type Evaluator struct {
	// sandboxFn and canaryFn allow injection of custom evaluation logic for testing.
	sandboxFn        func(ctx context.Context, skill *Skill) (*EvalResult, error)
	canaryFn         func(ctx context.Context, skill *Skill, sampleSize int) (*EvalResult, error)
	sandboxBackendID string
	canaryBackendID  string
}

// NewEvaluator creates a new Evaluator.
func NewEvaluator() *Evaluator {
	return &Evaluator{}
}

// WithSandboxFunc sets a custom sandbox evaluation function.
func (e *Evaluator) WithSandboxFunc(fn func(ctx context.Context, skill *Skill) (*EvalResult, error)) *Evaluator {
	e.sandboxFn = fn
	if e.sandboxBackendID == "" {
		e.sandboxBackendID = "custom-sandbox-evaluator"
	}
	return e
}

// WithCanaryFunc sets a custom canary evaluation function.
func (e *Evaluator) WithCanaryFunc(fn func(ctx context.Context, skill *Skill, sampleSize int) (*EvalResult, error)) *Evaluator {
	e.canaryFn = fn
	if e.canaryBackendID == "" {
		e.canaryBackendID = "custom-canary-evaluator"
	}
	return e
}

// WithSandboxBackendID records the identity of the sandbox evaluation backend.
func (e *Evaluator) WithSandboxBackendID(backendID string) *Evaluator {
	e.sandboxBackendID = backendID
	return e
}

// WithCanaryBackendID records the identity of the canary evaluation backend.
func (e *Evaluator) WithCanaryBackendID(backendID string) *Evaluator {
	e.canaryBackendID = backendID
	return e
}

// EvalSandbox runs a skill in isolated sandbox mode.
// Returns pass/fail with score and error count.
func (e *Evaluator) EvalSandbox(ctx context.Context, skill *Skill) (*EvalResult, error) {
	if e.sandboxFn != nil {
		result, err := e.sandboxFn(ctx, skill)
		return normalizeEvalResult(result, skill, PromotionC0Sandbox, e.sandboxBackendID), err
	}
	return &EvalResult{
		EvalID:      uuid.New().String(),
		SkillID:     skill.SkillID,
		Level:       PromotionC0Sandbox,
		BackendID:   "missing-sandbox-evaluator",
		Passed:      false,
		Score:       0,
		ErrorCount:  1,
		SampleSize:  0,
		Duration:    0,
		Details:     "sandbox evaluator backend not configured (non-certifying)",
		CompletedAt: time.Now(),
	}, nil
}

// EvalCanary runs a skill against production-like signal streams.
// Returns pass/fail with metrics.
func (e *Evaluator) EvalCanary(ctx context.Context, skill *Skill, sampleSize int) (*EvalResult, error) {
	if e.canaryFn != nil {
		result, err := e.canaryFn(ctx, skill, sampleSize)
		return normalizeEvalResult(result, skill, PromotionC2Canary, e.canaryBackendID), err
	}
	return &EvalResult{
		EvalID:      uuid.New().String(),
		SkillID:     skill.SkillID,
		Level:       PromotionC2Canary,
		BackendID:   "missing-canary-evaluator",
		Passed:      false,
		Score:       0,
		ErrorCount:  1,
		SampleSize:  sampleSize,
		Duration:    0,
		Details:     "canary evaluator backend not configured (non-certifying)",
		CompletedAt: time.Now(),
	}, nil
}

func normalizeEvalResult(result *EvalResult, skill *Skill, level PromotionLevel, backendID string) *EvalResult {
	if result == nil {
		return &EvalResult{
			EvalID:      uuid.New().String(),
			SkillID:     skill.SkillID,
			Level:       level,
			BackendID:   backendID,
			Passed:      false,
			Score:       0,
			ErrorCount:  1,
			Details:     "evaluator returned nil result (non-certifying)",
			CompletedAt: time.Now(),
		}
	}
	if result.EvalID == "" {
		result.EvalID = uuid.New().String()
	}
	if result.SkillID == "" {
		result.SkillID = skill.SkillID
	}
	if result.Level == "" {
		result.Level = level
	}
	if result.BackendID == "" {
		result.BackendID = backendID
	}
	if result.CompletedAt.IsZero() {
		result.CompletedAt = time.Now()
	}
	return result
}
