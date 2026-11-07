package governance

import (
	"context"
	"sync"
	"time"
)

// PolicyDecisionPoint (PDP) is the single stable API surface for policy decisions.
// Per HELM Normative Addendum Section 3.1:
// - HELM MUST expose exactly one stable PDP interface
// - If multiple engines are used, the PDP adapter MUST merge into one canonical decision trace
// - The kernel only consumes this stable interface
type PolicyDecisionPoint interface {
	// Evaluate processes a PDPRequest and returns a deterministic PDPResponse.
	// Given identical PDPRequest and policy_version, response MUST be identical.
	Evaluate(ctx context.Context, req PDPRequest) (*PDPResponse, error)

	// PolicyVersion returns the current content-addressed policy bundle version.
	PolicyVersion() string
}

// PDPRequest per Section 3.3 - minimum required inputs for policy decision.
type PDPRequest struct {
	RequestID string `json:"request_id"`

	Effect EffectDescriptor `json:"effect"`

	Subject SubjectDescriptor `json:"subject"`

	Context ContextDescriptor `json:"context"`

	ObligationsContext ObligationsContext `json:"obligations_context"`
}

// EffectDescriptor describes the effect being requested.
type EffectDescriptor struct {
	EffectID          string `json:"effect_id"`
	EffectType        string `json:"effect_type"`
	EffectPayloadHash string `json:"effect_payload_hash"`
	IdempotencyKey    string `json:"idempotency_key"`
}

// SubjectDescriptor describes the actor requesting the effect.
type SubjectDescriptor struct {
	ActorID     string      `json:"actor_id"`
	ActorType   string      `json:"actor_type"` // human, operator, agent, service
	AuthContext AuthContext `json:"auth_context"`
}

// AuthContext contains authentication claims and roles.
type AuthContext struct {
	Claims    map[string]string `json:"claims,omitempty"`
	Roles     []string          `json:"roles,omitempty"`
	SessionID string            `json:"session_id,omitempty"`
}

// ContextDescriptor provides execution context for the decision.
type ContextDescriptor struct {
	ModeID                  string         `json:"mode_id"`
	LoopID                  string         `json:"loop_id,omitempty"`
	Jurisdiction            string         `json:"jurisdiction"`
	EnvironmentSnapshotHash string         `json:"environment_snapshot_hash"`
	PhenotypeHash           string         `json:"phenotype_hash"`
	EventCursor             string         `json:"event_cursor,omitempty"`
	Time                    TimeDescriptor `json:"time"`
}

// TimeDescriptor specifies time context for decisions.
type TimeDescriptor struct {
	DecisionTimeSource string    `json:"decision_time_source"` // committed_at or observed_at
	Timestamp          time.Time `json:"timestamp"`
}

// ObligationsContext describes pre-existing obligations affecting the decision.
type ObligationsContext struct {
	RequiredApprovals []ApprovalRequirement `json:"required_approvals,omitempty"`
	RequiredEvidence  []EvidenceRequirement `json:"required_evidence,omitempty"`
}

// ApprovalRequirement specifies an approval constraint.
type ApprovalRequirement struct {
	ApprovalType string `json:"approval_type"`
	Threshold    int    `json:"threshold"`
}

// EvidenceRequirement specifies an evidence constraint.
type EvidenceRequirement struct {
	EvidenceType     string `json:"evidence_type"`
	IssuerConstraint string `json:"issuer_constraint,omitempty"`
}

// PDPResponse per Section 3.4 - minimum required outputs from policy decision.
type PDPResponse struct {
	Decision      Decision            `json:"decision"`
	DecisionID    string              `json:"decision_id"`
	PolicyVersion string              `json:"policy_version"`
	Constraints   DecisionConstraints `json:"constraints"`
	Trace         DecisionTrace       `json:"trace"`
	IssuedAt      time.Time           `json:"issued_at"`
	ExpiresAt     time.Time           `json:"expires_at,omitempty"`
}

// Decision represents the policy outcome.
type Decision string

const (
	DecisionAllow           Decision = "ALLOW"
	DecisionDeny            Decision = "DENY"
	DecisionRequireApproval Decision = "REQUIRE_APPROVAL" // Legacy, maps to canonical ESCALATE
	DecisionRequireEvidence Decision = "REQUIRE_EVIDENCE"
	DecisionDefer           Decision = "DEFER" // Legacy, maps to canonical ESCALATE
)

// DecisionConstraints per Section 3.4 - constraints on allowed effects.
type DecisionConstraints struct {
	EnvelopeConstraints   *EnvelopeConstraints   `json:"envelope_constraints,omitempty"`
	RequiredApprovals     []ApprovalConstraint   `json:"required_approvals,omitempty"`
	RequiredEvidence      []EvidenceConstraint   `json:"required_evidence,omitempty"`
	CompensationsRequired []CompensationRequired `json:"compensations_required,omitempty"`
}

// EnvelopeConstraints defines effect type and limit constraints.
type EnvelopeConstraints struct {
	AllowedEffectTypes []string               `json:"allowed_effect_types,omitempty"`
	Limits             map[string]EffectLimit `json:"limits,omitempty"`
}

// EffectLimit defines rate/value limits per effect type.
type EffectLimit struct {
	MaxValue      float64 `json:"max_value,omitempty"`
	MaxCount      int     `json:"max_count,omitempty"`
	WindowSeconds int     `json:"window_seconds,omitempty"`
}

// ApprovalConstraint specifies approval requirements.
type ApprovalConstraint struct {
	ApprovalType  string   `json:"approval_type"`
	ApproverRoles []string `json:"approver_roles,omitempty"`
	Threshold     int      `json:"threshold"`
}

// EvidenceConstraint specifies evidence requirements.
type EvidenceConstraint struct {
	EvidenceType     string   `json:"evidence_type"`
	IssuerAllowlist  []string `json:"issuer_allowlist,omitempty"`
	MinCorroboration int      `json:"min_corroboration,omitempty"`
}

// CompensationRequired specifies compensation requirements.
type CompensationRequired struct {
	CompensationType string `json:"compensation_type"`
	TriggerCondition string `json:"trigger_condition"`
}

// DecisionTrace per Section 3.4 - reproducible trace for audit.
type DecisionTrace struct {
	EvaluationGraphHash string            `json:"evaluation_graph_hash"`
	RulesFired          []string          `json:"rules_fired"`
	InputsHashes        map[string]string `json:"inputs_hashes"`
	EngineSubtraces     []EngineSubtrace  `json:"engine_subtraces,omitempty"`
}

// EngineSubtrace for multi-engine PDP setups.
type EngineSubtrace struct {
	EngineID            string   `json:"engine_id"`
	SubDecision         string   `json:"sub_decision"`
	EvidenceContributed []string `json:"evidence_contributed,omitempty"`
}

// FactOracle provides access to the OrgFactGraph.
type FactOracle interface {
	GetFact(subject, predicate string) (interface{}, error)
}

// CELPolicyDecisionPoint implements PDP using CEL policy evaluation.
type CELPolicyDecisionPoint struct {
	evaluator     *CELPolicyEvaluator
	oracle        FactOracle
	policyVersion string
	mu            sync.RWMutex
}

// --- Helpers ---
