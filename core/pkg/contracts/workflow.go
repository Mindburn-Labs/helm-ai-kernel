package contracts

import "time"

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
	StepID          string        `json:"step_id"`
	Name            string        `json:"name"`
	Action          string        `json:"action"`
	Type            string        `json:"type"` // "EFFECT", "DECISION", "WAIT", "VERIFY"
	Effect          *Effect       `json:"effect,omitempty"`
	Verification    *Verification `json:"verification,omitempty"`
	Timeout         time.Duration `json:"timeout,omitempty"`
	Condition       string        `json:"condition,omitempty"`
	HasCompensation bool          `json:"has_compensation"`
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
