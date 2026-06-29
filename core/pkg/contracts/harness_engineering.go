package contracts

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// HarnessTrace is the hash-linkable trace of context, permissions, verifier
// outputs, state updates, and receipt refs that influenced an execution.
type HarnessTrace struct {
	TraceID               string    `json:"trace_id"`
	PlanHash              string    `json:"plan_hash"`
	ContextRefs           []string  `json:"context_refs,omitempty"`
	MemoryReads           []string  `json:"memory_reads,omitempty"`
	MemoryWrites          []string  `json:"memory_writes,omitempty"`
	ToolSchemaHashes      []string  `json:"tool_schema_hashes,omitempty"`
	PermissionRequests    []string  `json:"permission_requests,omitempty"`
	SandboxGrantHash      string    `json:"sandbox_grant_hash,omitempty"`
	MCPApprovalRef        string    `json:"mcp_approval_ref,omitempty"`
	ConnectorContractHash string    `json:"connector_contract_hash,omitempty"`
	PolicyHash            string    `json:"policy_hash"`
	CPIOutputHash         string    `json:"cpi_output_hash,omitempty"`
	VerifierOutputs       []string  `json:"verifier_outputs,omitempty"`
	HumanInterventions    []string  `json:"human_interventions,omitempty"`
	StateUpdates          []string  `json:"state_updates,omitempty"`
	ReceiptRefs           []string  `json:"receipt_refs"`
	CreatedAt             time.Time `json:"created_at,omitempty"`
	TraceHash             string    `json:"trace_hash,omitempty"`
}

// HarnessChangeContract controls mutation of the harness itself: connectors,
// tool schemas, grants, policy overlays, verifiers, evidence templates, and
// routing rules.
type HarnessChangeContract struct {
	ChangeContractID       string          `json:"change_contract_id"`
	ComponentModified      string          `json:"component_modified"`
	FailureModeTargeted    string          `json:"failure_mode_targeted"`
	PredictedImprovement   string          `json:"predicted_improvement"`
	InvariantsPreserved    []string        `json:"invariants_preserved"`
	SafetyProperties       []string        `json:"safety_properties"`
	RegressionSuiteRefs    []string        `json:"regression_suite_refs"`
	SimulationEvidenceRefs []string        `json:"simulation_evidence_refs,omitempty"`
	CanaryScope            json.RawMessage `json:"canary_scope,omitempty"`
	RollbackPlan           json.RawMessage `json:"rollback_plan"`
	ApprovalRequired       bool            `json:"approval_required"`
	ActivationReceiptRef   string          `json:"activation_receipt_ref,omitempty"`
	CreatedAt              time.Time       `json:"created_at,omitempty"`
	ContractHash           string          `json:"contract_hash,omitempty"`
}

// GroundedActionRef binds a GUI/computer-use action to visual, DOM, and
// accessibility evidence before an actuator can perform it.
type GroundedActionRef struct {
	GroundedActionID     string    `json:"grounded_action_id"`
	ScreenshotHash       string    `json:"screenshot_hash"`
	DOMOrAXSnapshotHash  string    `json:"dom_or_ax_snapshot_hash"`
	TargetRef            string    `json:"target_ref"`
	BBoxOrElementID      string    `json:"bbox_or_element_id"`
	ActionType           string    `json:"action_type"`
	Precondition         string    `json:"precondition"`
	Postcondition        string    `json:"postcondition"`
	PostconditionRef     string    `json:"postcondition_ref"`
	ProofGraphNodeRef    string    `json:"proof_graph_node_ref"`
	VerificationScopeRef string    `json:"verification_scope_ref"`
	PolicyHash           string    `json:"policy_hash"`
	SandboxGrantHash     string    `json:"sandbox_grant_hash,omitempty"`
	CreatedAt            time.Time `json:"created_at,omitempty"`
	GroundingHash        string    `json:"grounding_hash,omitempty"`
}

// GUIActionReceipt is the receipt shape for grounded GUI/computer-use actions.
type GUIActionReceipt struct {
	ReceiptID             string    `json:"receipt_id"`
	GroundedActionRef     string    `json:"grounded_action_ref"`
	ScreenshotHash        string    `json:"screenshot_hash"`
	DOMOrAXSnapshotHash   string    `json:"dom_or_ax_snapshot_hash"`
	TargetRef             string    `json:"target_ref"`
	BBoxOrElementID       string    `json:"bbox_or_element_id"`
	ActionType            string    `json:"action_type"`
	Precondition          string    `json:"precondition"`
	Postcondition         string    `json:"postcondition"`
	PostconditionRef      string    `json:"postcondition_ref"`
	PostconditionVerified bool      `json:"postcondition_verified"`
	ProofGraphNodeRef     string    `json:"proof_graph_node_ref"`
	VerificationScopeRef  string    `json:"verification_scope_ref"`
	PolicyHash            string    `json:"policy_hash"`
	SandboxGrantHash      string    `json:"sandbox_grant_hash,omitempty"`
	CreatedAt             time.Time `json:"created_at,omitempty"`
	ReceiptHash           string    `json:"receipt_hash,omitempty"`
}

func (s VerificationScope) Validate() error {
	if strings.TrimSpace(s.VerificationScopeID) == "" {
		return fmt.Errorf("verification_scope_id is required")
	}
	if !isSHA256Ref(s.SubjectHash) {
		return fmt.Errorf("subject_hash must be sha256-prefixed")
	}
	if s.RiskClass != "" && !isHarnessRiskClass(s.RiskClass) {
		return fmt.Errorf("invalid risk_class %q", s.RiskClass)
	}
	if len(nonEmptyStrings(s.ChecksPerformed)) == 0 {
		return fmt.Errorf("checks_performed is required")
	}
	if !isSHA256Ref(s.VerifierHash) {
		return fmt.Errorf("verifier_hash must be sha256-prefixed")
	}
	if !isSHA256Ref(s.PolicyHash) {
		return fmt.Errorf("policy_hash must be sha256-prefixed")
	}
	if s.CreatedAt.IsZero() {
		return fmt.Errorf("created_at is required")
	}
	return nil
}

func (s VerificationScope) Seal() (VerificationScope, error) {
	if err := s.Validate(); err != nil {
		return VerificationScope{}, err
	}
	s.ScopeHash = ""
	hash, err := hashJCS(s)
	if err != nil {
		return VerificationScope{}, err
	}
	s.ScopeHash = hash
	return s, nil
}

func (t PlanTransaction) Validate() error {
	if strings.TrimSpace(t.PlanTransactionID) == "" {
		return fmt.Errorf("plan_transaction_id is required")
	}
	if !isSHA256Ref(t.PlanHash) {
		return fmt.Errorf("plan_hash must be sha256-prefixed")
	}
	if len(nonEmptyStrings(t.ReadSet)) == 0 {
		return fmt.Errorf("read_set is required")
	}
	if len(nonEmptyStrings(t.WriteSet)) == 0 {
		return fmt.Errorf("write_set is required")
	}
	if len(nonEmptyStrings(t.AssumptionSet)) == 0 {
		return fmt.Errorf("assumption_set is required")
	}
	if len(nonEmptyStrings(t.VerificationObligations)) == 0 {
		return fmt.Errorf("verification_obligations is required")
	}
	switch t.ConflictPolicy {
	case "deny", "escalate", "last_writer_forbidden":
	default:
		return fmt.Errorf("invalid conflict_policy %q", t.ConflictPolicy)
	}
	switch t.ApprovalState {
	case "", "none", "required", "approved", "denied", "expired":
	default:
		return fmt.Errorf("invalid approval_state %q", t.ApprovalState)
	}
	if len(t.RollbackPolicy) > 0 && !json.Valid(t.RollbackPolicy) {
		return fmt.Errorf("rollback_policy must be valid JSON")
	}
	return nil
}

func (t PlanTransaction) Seal() (PlanTransaction, error) {
	if err := t.Validate(); err != nil {
		return PlanTransaction{}, err
	}
	t.TransactionHash = ""
	hash, err := hashJCS(t)
	if err != nil {
		return PlanTransaction{}, err
	}
	t.TransactionHash = hash
	return t, nil
}

func (t HarnessTrace) Validate() error {
	if strings.TrimSpace(t.TraceID) == "" {
		return fmt.Errorf("trace_id is required")
	}
	if !isSHA256Ref(t.PlanHash) {
		return fmt.Errorf("plan_hash must be sha256-prefixed")
	}
	if !isSHA256Ref(t.PolicyHash) {
		return fmt.Errorf("policy_hash must be sha256-prefixed")
	}
	if len(nonEmptyStrings(t.ReceiptRefs)) == 0 {
		return fmt.Errorf("receipt_refs is required")
	}
	if t.CreatedAt.IsZero() {
		return fmt.Errorf("created_at is required")
	}
	for _, hash := range append(append([]string{}, t.ToolSchemaHashes...), t.SandboxGrantHash, t.ConnectorContractHash, t.CPIOutputHash) {
		if hash != "" && !isSHA256Ref(hash) {
			return fmt.Errorf("hash reference %q must be sha256-prefixed", hash)
		}
	}
	return nil
}

func (t HarnessTrace) Seal() (HarnessTrace, error) {
	if err := t.Validate(); err != nil {
		return HarnessTrace{}, err
	}
	t.TraceHash = ""
	hash, err := hashJCS(t)
	if err != nil {
		return HarnessTrace{}, err
	}
	t.TraceHash = hash
	return t, nil
}

func (c HarnessChangeContract) Validate() error {
	if strings.TrimSpace(c.ChangeContractID) == "" {
		return fmt.Errorf("change_contract_id is required")
	}
	switch c.ComponentModified {
	case "connector_contract", "tool_schema", "sandbox_grant", "mcp_approval", "policy_overlay", "verifier", "evidence_template", "routing_rule":
	default:
		return fmt.Errorf("invalid component_modified %q", c.ComponentModified)
	}
	if strings.TrimSpace(c.FailureModeTargeted) == "" || strings.TrimSpace(c.PredictedImprovement) == "" {
		return fmt.Errorf("failure_mode_targeted and predicted_improvement are required")
	}
	if len(nonEmptyStrings(c.InvariantsPreserved)) == 0 || len(nonEmptyStrings(c.SafetyProperties)) == 0 {
		return fmt.Errorf("invariants_preserved and safety_properties are required")
	}
	if len(nonEmptyStrings(c.RegressionSuiteRefs)) == 0 {
		return fmt.Errorf("regression_suite_refs is required")
	}
	if !c.ApprovalRequired && strings.TrimSpace(c.ActivationReceiptRef) == "" {
		return fmt.Errorf("activation_receipt_ref is required when approval_required=false")
	}
	if len(c.CanaryScope) > 0 && !json.Valid(c.CanaryScope) {
		return fmt.Errorf("canary_scope must be valid JSON")
	}
	if len(bytes.TrimSpace(c.RollbackPlan)) == 0 || !json.Valid(c.RollbackPlan) {
		return fmt.Errorf("rollback_plan must be valid JSON")
	}
	if c.CreatedAt.IsZero() {
		return fmt.Errorf("created_at is required")
	}
	return nil
}

func (c HarnessChangeContract) Seal() (HarnessChangeContract, error) {
	if err := c.Validate(); err != nil {
		return HarnessChangeContract{}, err
	}
	c.ContractHash = ""
	hash, err := hashJCS(c)
	if err != nil {
		return HarnessChangeContract{}, err
	}
	c.ContractHash = hash
	return c, nil
}

func (a GroundedActionRef) Validate() error {
	if strings.TrimSpace(a.GroundedActionID) == "" {
		return fmt.Errorf("grounded_action_id is required")
	}
	if !isSHA256Ref(a.ScreenshotHash) || !isSHA256Ref(a.DOMOrAXSnapshotHash) || !isSHA256Ref(a.PolicyHash) {
		return fmt.Errorf("screenshot_hash, dom_or_ax_snapshot_hash, and policy_hash must be sha256-prefixed")
	}
	if strings.TrimSpace(a.TargetRef) == "" || strings.TrimSpace(a.BBoxOrElementID) == "" {
		return fmt.Errorf("target_ref and bbox_or_element_id are required")
	}
	if !isGUIActionType(a.ActionType) {
		return fmt.Errorf("invalid action_type %q", a.ActionType)
	}
	if strings.TrimSpace(a.Precondition) == "" || strings.TrimSpace(a.Postcondition) == "" || strings.TrimSpace(a.PostconditionRef) == "" {
		return fmt.Errorf("precondition, postcondition, and postcondition_ref are required")
	}
	if strings.TrimSpace(a.ProofGraphNodeRef) == "" {
		return fmt.Errorf("proof_graph_node_ref is required")
	}
	if strings.TrimSpace(a.VerificationScopeRef) == "" {
		return fmt.Errorf("verification_scope_ref is required")
	}
	if a.SandboxGrantHash != "" && !isSHA256Ref(a.SandboxGrantHash) {
		return fmt.Errorf("sandbox_grant_hash must be sha256-prefixed")
	}
	if a.CreatedAt.IsZero() {
		return fmt.Errorf("created_at is required")
	}
	return nil
}

func (a GroundedActionRef) Seal() (GroundedActionRef, error) {
	if err := a.Validate(); err != nil {
		return GroundedActionRef{}, err
	}
	a.GroundingHash = ""
	hash, err := hashJCS(a)
	if err != nil {
		return GroundedActionRef{}, err
	}
	a.GroundingHash = hash
	return a, nil
}

func (r GUIActionReceipt) Validate() error {
	if strings.TrimSpace(r.ReceiptID) == "" || strings.TrimSpace(r.GroundedActionRef) == "" {
		return fmt.Errorf("receipt_id and grounded_action_ref are required")
	}
	ref := GroundedActionRef{
		GroundedActionID:     r.GroundedActionRef,
		ScreenshotHash:       r.ScreenshotHash,
		DOMOrAXSnapshotHash:  r.DOMOrAXSnapshotHash,
		TargetRef:            r.TargetRef,
		BBoxOrElementID:      r.BBoxOrElementID,
		ActionType:           r.ActionType,
		Precondition:         r.Precondition,
		Postcondition:        r.Postcondition,
		PostconditionRef:     r.PostconditionRef,
		ProofGraphNodeRef:    r.ProofGraphNodeRef,
		VerificationScopeRef: r.VerificationScopeRef,
		PolicyHash:           r.PolicyHash,
		SandboxGrantHash:     r.SandboxGrantHash,
		CreatedAt:            r.CreatedAt,
	}
	if err := ref.Validate(); err != nil {
		return err
	}
	if !r.PostconditionVerified {
		return fmt.Errorf("postcondition must be verified")
	}
	return nil
}

func (r GUIActionReceipt) Seal() (GUIActionReceipt, error) {
	if err := r.Validate(); err != nil {
		return GUIActionReceipt{}, err
	}
	r.ReceiptHash = ""
	hash, err := hashJCS(r)
	if err != nil {
		return GUIActionReceipt{}, err
	}
	r.ReceiptHash = hash
	return r, nil
}

func isSHA256Ref(value string) bool {
	return strings.HasPrefix(strings.TrimSpace(value), "sha256:")
}

func isHarnessRiskClass(value string) bool {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "T0", "T1", "T2", "T3":
		return true
	default:
		return false
	}
}

func isGUIActionType(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "click", "type", "select", "submit", "navigate":
		return true
	default:
		return false
	}
}

func nonEmptyStrings(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			out = append(out, value)
		}
	}
	return out
}
