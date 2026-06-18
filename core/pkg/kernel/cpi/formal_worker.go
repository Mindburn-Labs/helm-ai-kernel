package cpi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

const (
	ProofInvariantNoIrreversibleBeforeApproval = "no_irreversible_before_approval"
	ProofToolchainDeterministicV0              = "deterministic-plan-invariant-v0"
)

type ProofStatus string

const (
	ProofStatusProved          ProofStatus = "PROVED"
	ProofStatusRefuted         ProofStatus = "REFUTED"
	ProofStatusUnknown         ProofStatus = "UNKNOWN"
	ProofStatusBudgetExhausted ProofStatus = "BUDGET_EXHAUSTED"
	ProofStatusToolchainError  ProofStatus = "TOOLCHAIN_ERROR"
)

type ProofObligation struct {
	ObligationID       string        `json:"obligation_id"`
	SourceKind         string        `json:"source_kind"`
	Invariant          string        `json:"invariant"`
	CanonicalInputHash string        `json:"canonical_input_hash"`
	RiskClass          string        `json:"risk_class"`
	AllowedToolchain   []string      `json:"allowed_toolchain"`
	Budget             ProofBudget   `json:"budget,omitempty"`
	EvidenceRefs       []string      `json:"evidence_refs,omitempty"`
	Plan               ProofPlanView `json:"plan,omitempty"`
}

type ProofBudget struct {
	MaxNodes int `json:"max_nodes,omitempty"`
}

type ProofPlanView struct {
	Nodes []ProofPlanNode `json:"nodes,omitempty"`
}

type ProofPlanNode struct {
	NodeID             string `json:"node_id"`
	SideEffect         bool   `json:"side_effect,omitempty"`
	EffectClass        string `json:"effect_class,omitempty"`
	ApprovalCheckpoint bool   `json:"approval_checkpoint,omitempty"`
}

type ProofResult struct {
	ObligationID          string      `json:"obligation_id"`
	Status                ProofStatus `json:"status"`
	ProofArtifactHash     string      `json:"proof_artifact_hash"`
	VerifierLogHash       string      `json:"verifier_log_hash"`
	ToolchainDigest       string      `json:"toolchain_digest"`
	ProofSearchMerkleRoot string      `json:"proof_search_merkle_root"`
	AcceptedNodes         []string    `json:"accepted_nodes,omitempty"`
	FailedNodesSummary    []string    `json:"failed_nodes_summary,omitempty"`
	ResultHash            string      `json:"result_hash"`
}

type FormalVerifier interface {
	Verify(context.Context, ProofObligation) (ProofResult, error)
}

type DeterministicFormalVerifier struct {
	ToolchainDigest string
}

func (o ProofObligation) Validate() error {
	if strings.TrimSpace(o.ObligationID) == "" {
		return fmt.Errorf("%w: obligation_id is required", ErrInvalidInput)
	}
	if !validProofSourceKind(o.SourceKind) {
		return fmt.Errorf("%w: invalid source_kind %q", ErrInvalidInput, o.SourceKind)
	}
	if strings.TrimSpace(o.Invariant) == "" {
		return fmt.Errorf("%w: invariant is required", ErrInvalidInput)
	}
	if !isProofSHA256Ref(o.CanonicalInputHash) {
		return fmt.Errorf("%w: canonical_input_hash must be sha256:<64 hex chars>", ErrInvalidInput)
	}
	if !validProofRiskClass(o.RiskClass) {
		return fmt.Errorf("%w: invalid risk_class %q", ErrInvalidInput, o.RiskClass)
	}
	if len(nonEmptyProofStrings(o.AllowedToolchain)) == 0 {
		return fmt.Errorf("%w: allowed_toolchain is required", ErrInvalidInput)
	}
	if o.Budget.MaxNodes < 0 {
		return fmt.Errorf("%w: max_nodes cannot be negative", ErrInvalidInput)
	}
	for i, node := range o.Plan.Nodes {
		if strings.TrimSpace(node.NodeID) == "" {
			return fmt.Errorf("%w: plan.nodes[%d].node_id is required", ErrInvalidInput, i)
		}
	}
	return nil
}

func (v DeterministicFormalVerifier) Verify(ctx context.Context, obligation ProofObligation) (ProofResult, error) {
	if err := ctx.Err(); err != nil {
		return ProofResult{}, err
	}
	if err := obligation.Validate(); err != nil {
		return ProofResult{}, err
	}

	result := ProofResult{
		ObligationID:      obligation.ObligationID,
		Status:            ProofStatusUnknown,
		ProofArtifactHash: formalHashJSON(obligation),
		ToolchainDigest:   v.digest(),
	}
	if !containsProofString(obligation.AllowedToolchain, ProofToolchainDeterministicV0) {
		result.Status = ProofStatusToolchainError
		result.FailedNodesSummary = []string{"allowed_toolchain does not permit deterministic-plan-invariant-v0"}
		return result.seal(), nil
	}
	if obligation.Budget.MaxNodes > 0 && len(obligation.Plan.Nodes) > obligation.Budget.MaxNodes {
		result.Status = ProofStatusBudgetExhausted
		result.FailedNodesSummary = []string{"plan node count exceeds budget.max_nodes"}
		return result.seal(), nil
	}
	if obligation.Invariant != ProofInvariantNoIrreversibleBeforeApproval {
		result.FailedNodesSummary = []string{"unsupported invariant: " + obligation.Invariant}
		return result.seal(), nil
	}
	if len(obligation.Plan.Nodes) == 0 {
		result.FailedNodesSummary = []string{"plan has no nodes"}
		return result.seal(), nil
	}

	approvalSeen := false
	for _, node := range obligation.Plan.Nodes {
		if node.ApprovalCheckpoint {
			approvalSeen = true
			result.AcceptedNodes = append(result.AcceptedNodes, node.NodeID)
			continue
		}
		if node.SideEffect && isIrreversibleProofEffect(node.EffectClass) && !approvalSeen {
			result.Status = ProofStatusRefuted
			result.FailedNodesSummary = []string{node.NodeID + ": irreversible side effect before approval checkpoint"}
			return result.seal(), nil
		}
		result.AcceptedNodes = append(result.AcceptedNodes, node.NodeID)
	}

	result.Status = ProofStatusProved
	return result.seal(), nil
}

func ProofStatusToCPI(status ProofStatus) string {
	switch status {
	case ProofStatusProved:
		return "ALLOW"
	case ProofStatusRefuted:
		return "DENY"
	default:
		return "ESCALATE"
	}
}

func EvaluateFormalProof(ctx context.Context, facts []byte, intent []byte) (bool, error) {
	payload := intent
	if len(payload) == 0 {
		payload = facts
	}
	var obligation ProofObligation
	if err := json.Unmarshal(payload, &obligation); err != nil {
		return false, fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}
	result, err := DeterministicFormalVerifier{}.Verify(ctx, obligation)
	if err != nil {
		return false, err
	}
	return result.Status == ProofStatusProved, nil
}

func (r ProofResult) seal() ProofResult {
	r.VerifierLogHash = formalHashJSON(struct {
		Status   ProofStatus `json:"status"`
		Failed   []string    `json:"failed,omitempty"`
		Accepted []string    `json:"accepted,omitempty"`
	}{r.Status, r.FailedNodesSummary, r.AcceptedNodes})
	r.ProofSearchMerkleRoot = formalHashJSON(struct {
		Accepted []string `json:"accepted,omitempty"`
		Failed   []string `json:"failed,omitempty"`
	}{r.AcceptedNodes, r.FailedNodesSummary})
	r.ResultHash = ""
	r.ResultHash = formalHashJSON(r)
	return r
}

func (v DeterministicFormalVerifier) digest() string {
	if v.ToolchainDigest != "" {
		return v.ToolchainDigest
	}
	return formalHashBytes([]byte("helm:" + ProofToolchainDeterministicV0))
}

func isIrreversibleProofEffect(value string) bool {
	value = strings.ToUpper(strings.TrimSpace(value))
	return value == "IRREVERSIBLE" || value == "IRREVERSIBLE_WRITE" || value == "E4"
}

func validProofSourceKind(value string) bool {
	switch strings.TrimSpace(value) {
	case "PlanIR", "GeneratedSpec", "OrgGenomePolicy", "ConnectorContract", "EvidencePack":
		return true
	default:
		return false
	}
}

func validProofRiskClass(value string) bool {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "T0", "T1", "T2", "T3":
		return true
	default:
		return false
	}
}

func isProofSHA256Ref(value string) bool {
	digest := strings.TrimPrefix(strings.TrimSpace(value), "sha256:")
	if len(digest) != 64 {
		return false
	}
	_, err := hex.DecodeString(digest)
	return err == nil
}

func nonEmptyProofStrings(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			out = append(out, value)
		}
	}
	return out
}

func containsProofString(values []string, want string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == want {
			return true
		}
	}
	return false
}

func formalHashJSON(value any) string {
	data, _ := json.Marshal(value)
	return formalHashBytes(data)
}

func formalHashBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}
