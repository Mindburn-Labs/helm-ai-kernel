package intentcompiler

import (
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// DecompositionStrategy breaks a raw task description into atomic PlanSteps and edges.
type DecompositionStrategy interface {
	Decompose(rawStep string) ([]contracts.PlanStep, []contracts.Edge, error)
}

// StaticDecomposer uses rule-based pattern matching to decompose tasks.
type StaticDecomposer struct {
	idCounter atomic.Int64
}

// NewStaticDecomposer creates a new rule-based decomposer.
func NewStaticDecomposer() *StaticDecomposer {
	return &StaticDecomposer{}
}

func (d *StaticDecomposer) nextID() string {
	n := d.idCounter.Add(1)
	return fmt.Sprintf("step-%d", n)
}

// ResetCounter resets the ID counter (useful for testing).
func (d *StaticDecomposer) ResetCounter() {
	d.idCounter.Store(0)
}

// Decompose breaks a raw task into steps. For structured input (already a step
// description), returns a single step. For compound tasks, decomposes into parts.
func (d *StaticDecomposer) Decompose(rawStep string) ([]contracts.PlanStep, []contracts.Edge, error) {
	lower := strings.ToLower(rawStep)

	// Pattern: "build and deploy X" → build step + deploy step
	if strings.Contains(lower, "build") && strings.Contains(lower, "deploy") {
		return d.decomposeBuildAndDeploy(rawStep)
	}

	// Pattern: "test and deploy X" → test step + deploy step
	if strings.Contains(lower, "test") && strings.Contains(lower, "deploy") {
		return d.decomposeTestAndDeploy(rawStep)
	}

	// Single-step: classify the effect type from the description.
	step := contracts.PlanStep{
		ID:          d.nextID(),
		Description: rawStep,
		EffectType:  classifyEffect(lower),
	}
	return []contracts.PlanStep{step}, nil, nil
}

// DecomposeStructured creates a PlanStep from explicit parameters.
func (d *StaticDecomposer) DecomposeStructured(id, description, effectType string, params map[string]any) contracts.PlanStep {
	if id == "" {
		id = d.nextID()
	}
	return contracts.PlanStep{
		ID:          id,
		Description: description,
		EffectType:  effectType,
		Params:      params,
	}
}

func (d *StaticDecomposer) decomposeBuildAndDeploy(raw string) ([]contracts.PlanStep, []contracts.Edge, error) {
	buildID := d.nextID()
	deployID := d.nextID()

	steps := []contracts.PlanStep{
		{
			ID:          buildID,
			Description: "Build: " + raw,
			EffectType:  "EXECUTE",
			Assumptions: []string{"Build environment available"},
		},
		{
			ID:          deployID,
			Description: "Deploy: " + raw,
			EffectType:  "SOFTWARE_PUBLISH",
			Assumptions: []string{"Build succeeded"},
		},
	}

	edges := []contracts.Edge{
		{From: buildID, To: deployID, Type: "requires"},
	}

	return steps, edges, nil
}

func (d *StaticDecomposer) decomposeTestAndDeploy(raw string) ([]contracts.PlanStep, []contracts.Edge, error) {
	testID := d.nextID()
	deployID := d.nextID()

	steps := []contracts.PlanStep{
		{
			ID:          testID,
			Description: "Test: " + raw,
			EffectType:  "EXECUTE",
			Assumptions: []string{"Test environment available"},
		},
		{
			ID:          deployID,
			Description: "Deploy: " + raw,
			EffectType:  "SOFTWARE_PUBLISH",
			Assumptions: []string{"Tests passed"},
		},
	}

	edges := []contracts.Edge{
		{From: testID, To: deployID, Type: "requires"},
	}

	return steps, edges, nil
}

// classifyEffect maps a natural-language description to an effect type.
func classifyEffect(lower string) string {
	switch {
	case strings.Contains(lower, "read") || strings.Contains(lower, "fetch") || strings.Contains(lower, "get"):
		return "READ"
	case strings.Contains(lower, "write") || strings.Contains(lower, "create") || strings.Contains(lower, "save"):
		return "WRITE"
	case strings.Contains(lower, "delete") || strings.Contains(lower, "remove") || strings.Contains(lower, "destroy"):
		return "INFRA_DESTROY"
	case strings.Contains(lower, "deploy") || strings.Contains(lower, "publish"):
		return "SOFTWARE_PUBLISH"
	case strings.Contains(lower, "build") || strings.Contains(lower, "compile") || strings.Contains(lower, "run") || strings.Contains(lower, "test") || strings.Contains(lower, "execute"):
		return "EXECUTE"
	case strings.Contains(lower, "send") || strings.Contains(lower, "call") || strings.Contains(lower, "api") || strings.Contains(lower, "request"):
		return "NETWORK"
	case strings.Contains(lower, "commit") || strings.Contains(lower, "push") || strings.Contains(lower, "git"):
		return "WRITE"
	default:
		return "EXECUTE"
	}
}
