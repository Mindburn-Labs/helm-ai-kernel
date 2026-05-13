// Package effectgraph evaluates entire PlanSpec DAGs through the Guardian
// in a single pass, producing per-node verdicts before any execution begins.
//
// This bridges the Intent Compiler (which produces DAGs) and the Sandbox Broker
// (which executes approved steps). The evaluator ensures that no step runs
// without an explicit policy decision, and that deny verdicts cascade through
// dependencies.
package effectgraph

import (
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/sandbox"
)

// ExecutionProfile binds a policy decision to a specific sandbox configuration.
type ExecutionProfile struct {
	// Backend is the execution backend: "docker", "wasi", "native".
	Backend string `json:"backend"`

	// ProfileName identifies the sandbox profile.
	ProfileName string `json:"profile_name"`

	// NetworkPolicy restricts network access.
	NetworkPolicy *sandbox.NetworkPolicy `json:"network_policy,omitempty"`

	// Limits constrains resource consumption.
	Limits *sandbox.ResourceLimits `json:"limits,omitempty"`
}

// NodeVerdict is the evaluation result for a single DAG node.
type NodeVerdict struct {
	// StepID identifies the plan step.
	StepID string `json:"step_id"`

	// Decision is the Guardian's policy verdict.
	Decision *contracts.DecisionRecord `json:"decision"`

	// Intent is the signed execution intent (nil if DENY or ESCALATE).
	Intent *contracts.AuthorizedExecutionIntent `json:"intent,omitempty"`

	// Profile is the assigned execution profile (nil if DENY).
	Profile *ExecutionProfile `json:"profile,omitempty"`

	// BlockedBy lists step IDs whose DENY verdict caused this step to be blocked.
	BlockedBy []string `json:"blocked_by,omitempty"`
}

// EvaluationRequest is the input to the graph evaluator.
type EvaluationRequest struct {
	// Plan is the PlanSpec with DAG to evaluate.
	Plan *contracts.PlanSpec

	// Envelope is the autonomy envelope bounding the evaluation.
	Envelope *contracts.AutonomyEnvelope

	// Actor is the principal ID requesting evaluation.
	Actor string
}

// EvaluationResult is the output of the graph evaluator.
type EvaluationResult struct {
	// Verdicts maps step ID to its verdict.
	Verdicts map[string]*NodeVerdict `json:"verdicts"`

	// AllowedSteps lists step IDs that are approved for execution.
	AllowedSteps []string `json:"allowed_steps"`

	// BlockedSteps lists step IDs blocked by upstream DENY verdicts.
	BlockedSteps []string `json:"blocked_steps"`

	// EscalateSteps lists step IDs requiring human approval.
	EscalateSteps []string `json:"escalate_steps"`

	// DeniedSteps lists step IDs directly denied by policy.
	DeniedSteps []string `json:"denied_steps"`

	// GraphHash is a deterministic SHA-256 hash over all verdicts.
	GraphHash string `json:"graph_hash"`

	// TruthSummary aggregates unknowns and blocking questions across all steps.
	TruthSummary *contracts.TruthAnnotation `json:"truth_summary,omitempty"`
}
