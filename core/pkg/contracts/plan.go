package contracts

import (
	"encoding/json"
	"time"
)

// PlanSpec represents an execution plan as a contract.
// It matches schemas/orchestration/PlanSpec.v2.json
type PlanSpec struct {
	ID          string    `json:"id"`
	Version     string    `json:"version"`
	Name        string    `json:"name,omitempty"`
	GenericDesc string    `json:"description,omitempty"` // "description"
	Hash        string    `json:"hash"`
	CreatedAt   time.Time `json:"created_at,omitempty"`
	Lineage     *Lineage  `json:"lineage,omitempty"`

	// DAG Structure
	DAG *DAG `json:"dag"`

	// Legacy Support (deprecated in schema, but present)
	Steps []PlanStep `json:"steps,omitempty"`

	Parallelism       *Parallelism       `json:"parallelism,omitempty"`
	ArtifactRefs      []PlanArtifactRef  `json:"artifact_refs,omitempty"`
	PolicyConstraints *PolicyConstraints `json:"policy_constraints,omitempty"`

	// Truth Discipline — plan-level epistemic metadata.
	Truth       *TruthAnnotation `json:"truth,omitempty"`
	Transaction *PlanTransaction `json:"transaction,omitempty"`
}

// PlanTransaction records the read/write and verification contract for a plan.
type PlanTransaction struct {
	PlanTransactionID            string          `json:"plan_transaction_id,omitempty"`
	PlanHash                     string          `json:"plan_hash,omitempty"`
	ReadSet                      []string        `json:"read_set,omitempty"`
	WriteSet                     []string        `json:"write_set,omitempty"`
	AssumptionSet                []string        `json:"assumption_set,omitempty"`
	VersionDependencies          []string        `json:"version_dependencies,omitempty"`
	VerificationObligations      []string        `json:"verification_obligations,omitempty"`
	ConflictPolicy               string          `json:"conflict_policy,omitempty"`
	RollbackPolicy               json.RawMessage `json:"rollback_policy,omitempty"`
	RollbackOrCompensationPolicy string          `json:"rollback_or_compensation_policy,omitempty"`
	ApprovalState                string          `json:"approval_state,omitempty"`
	HumanReviewState             string          `json:"human_review_state,omitempty"`
	TransactionHash              string          `json:"transaction_hash,omitempty"`
}

// PlanArtifactRef points to external resources in a plan.
type PlanArtifactRef struct {
	Rel  string `json:"rel"`
	Hash string `json:"hash"`
	URI  string `json:"uri,omitempty"`
}

// DAG represents the Directed Acyclic Graph of steps.
type DAG struct {
	Nodes       []PlanStep `json:"nodes"`
	Edges       []Edge     `json:"edges"`
	EntryPoints []string   `json:"entry_points,omitempty"`
	ExitPoints  []string   `json:"exit_points,omitempty"`
}

// PlanStep represents a single node in the execution graph.
type PlanStep struct {
	ID                 string         `json:"id"`
	Description        string         `json:"description,omitempty"`
	EffectType         string         `json:"effect_type"`
	Params             map[string]any `json:"params,omitempty"`
	Dependencies       []string       `json:"dependencies,omitempty"` // Legacy
	RequiredTools      []string       `json:"required_tools,omitempty"`
	Assumptions        []string       `json:"assumptions,omitempty"`
	AcceptanceCriteria []string       `json:"acceptance_criteria"`
	CheckpointBefore   bool           `json:"checkpoint_before,omitempty"`
	CheckpointAfter    bool           `json:"checkpoint_after,omitempty"`
	RollbackOnFailure  bool           `json:"rollback_on_failure,omitempty"`

	// Truth Discipline — epistemic metadata per HitCC discipline.
	Justification     string    `json:"justification,omitempty"`
	FactSet           []FactRef `json:"fact_set,omitempty"`
	Unknowns          []Unknown `json:"unknowns,omitempty"`
	Confidence        float64   `json:"confidence,omitempty"`
	EvidenceRefs      []string  `json:"evidence_refs,omitempty"`
	BlockingQuestions []string  `json:"blocking_questions,omitempty"`

	// Execution Binding — sandbox profile assignment.
	RequestedBackend string `json:"requested_backend,omitempty"` // "docker", "wasi", "native"
	RequestedProfile string `json:"requested_profile,omitempty"` // sandbox profile name
}

// Edge represents a dependency between steps.
type Edge struct {
	From string `json:"from"`
	To   string `json:"to"`
	Type string `json:"type"` // requires, soft_requires, blocks
}

// Lineage tracks provenance.
type Lineage struct {
	RootCause string `json:"root_cause,omitempty"`
}

// Parallelism defines execution concurrency.
type Parallelism struct {
	MaxConcurrent int    `json:"max_concurrent,omitempty"`
	Strategy      string `json:"strategy,omitempty"` // sequential, parallel, adaptive
}

// PolicyConstraints defines requirements for execution.
type PolicyConstraints struct {
	RequiredApprovals  []string `json:"required_approvals,omitempty"`
	AllowedEffectTypes []string `json:"allowed_effect_types,omitempty"`
	MaxRetries         int      `json:"max_retries,omitempty"`
	TimeoutSeconds     int      `json:"timeout_seconds,omitempty"`
}
