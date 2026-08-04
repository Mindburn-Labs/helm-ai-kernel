package contracts

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// WorkflowDef defines a process.
type WorkflowDef struct {
	ID         string         `json:"id"`
	WorkflowID string         `json:"workflow_id,omitempty"` // Optional correlation ID
	Steps      []WorkflowStep `json:"steps"`
}

// WorkflowDefinition is a type alias retained for schema/doc compatibility.
// New code should use WorkflowDef directly.
type WorkflowDefinition = WorkflowDef

// WorkflowStep represents a step in a workflow.
type WorkflowStep struct {
	StepID          string            `json:"step_id"`
	Name            string            `json:"name"`
	Action          string            `json:"action"`
	Type            string            `json:"type"` // "EFFECT", "DECISION", "WAIT", "VERIFY"
	DependsOn       []string          `json:"depends_on,omitempty"`
	InputBindings   map[string]string `json:"input_bindings,omitempty"`
	Effect          *Effect           `json:"effect,omitempty"`
	Verification    *Verification     `json:"verification,omitempty"`
	Timeout         time.Duration     `json:"timeout,omitempty"`
	Condition       string            `json:"condition,omitempty"`
	HasCompensation bool              `json:"has_compensation"`
}

// Validate checks that the workflow is executable as a deterministic DAG.
func (workflow WorkflowDef) Validate() error {
	_, err := WorkflowLayers(workflow)
	return err
}

// WorkflowLayers returns topological execution layers in declaration order.
// Legacy workflows without explicit dependencies remain sequential.
func WorkflowLayers(workflow WorkflowDef) ([][]WorkflowStep, error) {
	if strings.TrimSpace(workflow.ID) == "" {
		return nil, fmt.Errorf("workflow id is required")
	}
	if workflow.ID != strings.TrimSpace(workflow.ID) {
		return nil, fmt.Errorf("workflow id %q is not canonical", workflow.ID)
	}
	if len(workflow.Steps) == 0 {
		return nil, fmt.Errorf("workflow %q has no steps", workflow.ID)
	}

	stepIndex := make(map[string]int, len(workflow.Steps))
	for i, step := range workflow.Steps {
		if strings.TrimSpace(step.StepID) == "" {
			return nil, fmt.Errorf("workflow %q step %d has no step id", workflow.ID, i)
		}
		if step.StepID != strings.TrimSpace(step.StepID) {
			return nil, fmt.Errorf("workflow %q step id %q is not canonical", workflow.ID, step.StepID)
		}
		if _, exists := stepIndex[step.StepID]; exists {
			return nil, fmt.Errorf("workflow %q has duplicate step id %q", workflow.ID, step.StepID)
		}
		if !validStepType(step.Type) {
			return nil, fmt.Errorf("workflow %q step %q has unknown type %q", workflow.ID, step.StepID, step.Type)
		}
		if step.Timeout < 0 {
			return nil, fmt.Errorf("workflow %q step %q has negative timeout", workflow.ID, step.StepID)
		}
		if step.Type == StepTypeEffect && step.Effect == nil {
			return nil, fmt.Errorf("workflow %q effect step %q has no effect", workflow.ID, step.StepID)
		}
		if step.Type == StepTypeVerification && step.Verification == nil {
			return nil, fmt.Errorf("workflow %q verification step %q has no verification", workflow.ID, step.StepID)
		}
		stepIndex[step.StepID] = i
	}

	indegree := make([]int, len(workflow.Steps))
	dependents := make([][]int, len(workflow.Steps))
	explicitGraph := false
	for i, step := range workflow.Steps {
		dependencies, explicit, err := workflowStepDependencies(step)
		if err != nil {
			return nil, fmt.Errorf("workflow %q step %q: %w", workflow.ID, step.StepID, err)
		}
		explicitGraph = explicitGraph || explicit
		for _, dependencyID := range dependencies {
			dependencyIndex, exists := stepIndex[dependencyID]
			if !exists {
				return nil, fmt.Errorf("workflow %q step %q depends on unknown step %q", workflow.ID, step.StepID, dependencyID)
			}
			if dependencyIndex == i {
				return nil, fmt.Errorf("workflow %q step %q depends on itself", workflow.ID, step.StepID)
			}
			indegree[i]++
			dependents[dependencyIndex] = append(dependents[dependencyIndex], i)
		}
	}

	if !explicitGraph {
		layers := make([][]WorkflowStep, len(workflow.Steps))
		for i, step := range workflow.Steps {
			layers[i] = []WorkflowStep{step}
		}
		return layers, nil
	}

	layers := make([][]WorkflowStep, 0, len(workflow.Steps))
	done := make([]bool, len(workflow.Steps))
	processed := 0
	for processed < len(workflow.Steps) {
		ready := make([]int, 0)
		for i := range workflow.Steps {
			if !done[i] && indegree[i] == 0 {
				ready = append(ready, i)
			}
		}
		if len(ready) == 0 {
			cycle := make([]string, 0, len(workflow.Steps)-processed)
			for i, step := range workflow.Steps {
				if !done[i] {
					cycle = append(cycle, step.StepID)
				}
			}
			return nil, fmt.Errorf("workflow %q contains a dependency cycle among steps %v", workflow.ID, cycle)
		}

		layer := make([]WorkflowStep, len(ready))
		for i, stepIndex := range ready {
			done[stepIndex] = true
			processed++
			layer[i] = workflow.Steps[stepIndex]
		}
		for _, stepIndex := range ready {
			for _, dependent := range dependents[stepIndex] {
				indegree[dependent]--
			}
		}
		layers = append(layers, layer)
	}

	return layers, nil
}

func validStepType(stepType string) bool {
	switch stepType {
	case StepTypeEffect, StepTypeDecision, StepTypeWait, StepTypeVerification:
		return true
	default:
		return false
	}
}

func workflowStepDependencies(step WorkflowStep) ([]string, bool, error) {
	explicit := len(step.DependsOn) > 0 || len(step.InputBindings) > 0
	dependencies := make([]string, 0, len(step.DependsOn)+len(step.InputBindings))
	seen := make(map[string]bool, cap(dependencies))
	for _, dependencyID := range step.DependsOn {
		if strings.TrimSpace(dependencyID) == "" {
			return nil, explicit, fmt.Errorf("depends_on contains an empty step id")
		}
		if dependencyID != strings.TrimSpace(dependencyID) {
			return nil, explicit, fmt.Errorf("depends_on step id %q is not canonical", dependencyID)
		}
		if seen[dependencyID] {
			return nil, explicit, fmt.Errorf("depends_on contains duplicate step %q", dependencyID)
		}
		seen[dependencyID] = true
		dependencies = append(dependencies, dependencyID)
	}

	inputNames := make([]string, 0, len(step.InputBindings))
	for inputName := range step.InputBindings {
		inputNames = append(inputNames, inputName)
	}
	sort.Strings(inputNames)
	for _, inputName := range inputNames {
		if strings.TrimSpace(inputName) == "" {
			return nil, explicit, fmt.Errorf("input_bindings contains an empty input name")
		}
		if inputName != strings.TrimSpace(inputName) {
			return nil, explicit, fmt.Errorf("input name %q is not canonical", inputName)
		}
		dependencyID := step.InputBindings[inputName]
		if strings.TrimSpace(dependencyID) == "" {
			return nil, explicit, fmt.Errorf("input binding %q has an empty source step id", inputName)
		}
		if dependencyID != strings.TrimSpace(dependencyID) {
			return nil, explicit, fmt.Errorf("input binding %q source step id %q is not canonical", inputName, dependencyID)
		}
		if !seen[dependencyID] {
			seen[dependencyID] = true
			dependencies = append(dependencies, dependencyID)
		}
	}

	return dependencies, explicit, nil
}

// Verification represents verification requirements for a step.
type Verification struct {
	Type      string  `json:"type"`
	Effect    *Effect `json:"effect,omitempty"`
	Assertion string  `json:"assertion,omitempty"`
}

// Step type constants.
const (
	StepTypeEffect       = "EFFECT"
	StepTypeDecision     = "DECISION"
	StepTypeWait         = "WAIT"
	StepTypeVerification = "VERIFY"

	EffectTypeCallTool             = "CALL_TOOL"
	EffectTypeGeneric              = "GENERIC"
	EffectTypeCreateObligation     = "CREATE_OBLIGATION"
	EffectTypeRequestClarification = "REQUEST_CLARIFICATION"
)

// Effect represents a side-effect to be executed.
//
//nolint:govet // fieldalignment: struct layout is human-readable
type Effect struct {
	EffectID       string         `json:"effect_id"`
	EffectType     string         `json:"type"`
	Params         map[string]any `json:"params"`
	Example        string         `json:"example,omitempty"`
	DecisionID     string         `json:"decision_id,omitempty"`
	IdempotencyKey string         `json:"idempotency_key,omitempty"`
	Compensation   *Effect        `json:"compensation,omitempty"`
	Irreversible   bool           `json:"irreversible,omitempty"`
	ArgsHash       string         `json:"args_hash,omitempty"`   // SHA-256 of JCS-canonicalized args
	OutputHash     string         `json:"output_hash,omitempty"` // SHA-256 of JCS-canonicalized output
	Taint          []string       `json:"taint,omitempty"`       // ClawGuard-style taint labels bound to this effect
}

// Result represents the outcome of an effect execution.
//
//nolint:govet // fieldalignment: struct layout is human-readable
type Result struct {
	Success bool           `json:"success"`
	Output  map[string]any `json:"output,omitempty"`
	Error   string         `json:"error,omitempty"`
}

// ClarificationPayload structure for REQUEST_CLARIFICATION effects.
type ClarificationPayload struct {
	Question string   `json:"question"`
	Context  []string `json:"context,omitempty"`
}
