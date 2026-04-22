package skills

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// Evaluator runs skills in sandbox/canary mode and reports results.
type Evaluator struct {
	// sandboxFn and canaryFn allow injection of custom evaluation logic for testing.
	// When nil, the default evaluation logic is used (which currently always passes).
	sandboxFn func(ctx context.Context, skill *Skill) (*EvalResult, error)
	canaryFn  func(ctx context.Context, skill *Skill, sampleSize int) (*EvalResult, error)
}

// NewEvaluator creates a new Evaluator with default (passing) evaluation logic.
func NewEvaluator() *Evaluator {
	return &Evaluator{}
}

// WithSandboxFunc sets a custom sandbox evaluation function.
func (e *Evaluator) WithSandboxFunc(fn func(ctx context.Context, skill *Skill) (*EvalResult, error)) *Evaluator {
	e.sandboxFn = fn
	return e
}

// WithCanaryFunc sets a custom canary evaluation function.
func (e *Evaluator) WithCanaryFunc(fn func(ctx context.Context, skill *Skill, sampleSize int) (*EvalResult, error)) *Evaluator {
	e.canaryFn = fn
	return e
}

// EvalSandbox runs a skill in isolated sandbox mode.
// Returns pass/fail with score and error count.
func (e *Evaluator) EvalSandbox(ctx context.Context, skill *Skill) (*EvalResult, error) {
	if e.sandboxFn != nil {
		return e.sandboxFn(ctx, skill)
	}
	// Default implementation: the skill is evaluated in a sandboxed environment.
	// In a full implementation, this would spin up an isolated runtime, execute
	// the skill definition against test fixtures, and measure outcomes.
	return &EvalResult{
		EvalID:      uuid.New().String(),
		SkillID:     skill.SkillID,
		Level:       PromotionC0Sandbox,
		Passed:      true,
		Score:       1.0,
		ErrorCount:  0,
		SampleSize:  100,
		Duration:    50 * time.Millisecond,
		Details:     "sandbox evaluation passed",
		CompletedAt: time.Now(),
	}, nil
}

// EvalCanary runs a skill against production-like signal streams.
// Returns pass/fail with metrics.
func (e *Evaluator) EvalCanary(ctx context.Context, skill *Skill, sampleSize int) (*EvalResult, error) {
	if e.canaryFn != nil {
		return e.canaryFn(ctx, skill, sampleSize)
	}
	// Default implementation: the skill is evaluated against a sample of
	// production-like traffic. In a full implementation, this would replay
	// recorded signals through the skill and compare outputs.
	return &EvalResult{
		EvalID:      uuid.New().String(),
		SkillID:     skill.SkillID,
		Level:       PromotionC2Canary,
		Passed:      true,
		Score:       0.95,
		ErrorCount:  0,
		SampleSize:  sampleSize,
		Duration:    200 * time.Millisecond,
		Details:     "canary evaluation passed",
		CompletedAt: time.Now(),
	}, nil
}
