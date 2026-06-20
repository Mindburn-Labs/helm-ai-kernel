// Package financedemo proves the Finance department workflow: a payment above a
// policy limit is escalated for human approval BEFORE it can execute.
//
// It is a deterministic, scripted demonstration. It reuses existing kernel
// building blocks rather than introducing a parallel proof universe:
//
//   - the canonical verdict taxonomy (contracts.Verdict ALLOW|ESCALATE) and
//     reason-code registry (contracts.ReasonApprovalRequired),
//   - the dual-control approval ceremony (contracts.ApprovalCeremony), the same
//     type SPEND5 uses to gate manual ledger corrections,
//   - content-addressed receipts sealed into an EvidencePack.
//
// This component is risk:r3-external-effect. It performs NO real payment and
// dispatches NO live external side effect: the connector/action boundary is a
// stub (see connector.go) that only executes once a sealed, approved ceremony
// authorizes it. The boundary fails closed.
package financedemo

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// PaymentReasonCode mirrors the canonical reason-code vocabulary for the two
// finance-relevant outcomes. They are deliberately a subset of the kernel
// contracts registry so the demo never invents a new verdict universe.
const (
	// ReasonWithinLimit is the ALLOW reason for a payment at or below the limit.
	ReasonWithinLimit = contracts.ReasonCode("OK_WITHIN_PAYMENT_LIMIT")
	// ReasonApprovalRequired is the canonical ESCALATE reason; a payment above
	// the policy limit requires human approval before execution.
	ReasonApprovalRequired = contracts.ReasonApprovalRequired
)

// PaymentApprovalPolicy is the finance threshold policy. A payment whose amount
// is at or above ApprovalRequiredAboveCents must be escalated for approval by a
// quorum of named approvers (e.g. CFO / Finance controller) before execution.
//
// It is the finance-native projection of the same "approval gate above a
// ceiling" rule that AgentSpendEnvelope.RequiresApproval enforces for AI spend
// (SPEND3); keeping it here lets the demo read as a payment limit, not a model
// budget, while preserving the identical ESCALATE invariant.
type PaymentApprovalPolicy struct {
	PolicyID                   string   `json:"policy_id"`
	TenantID                   string   `json:"tenant_id"`
	Department                 string   `json:"department"`
	Currency                   string   `json:"currency"`
	ApprovalRequiredAboveCents int64    `json:"approval_required_above_cents"`
	RequiredApprovers          []string `json:"required_approvers"`
	ApprovalQuorum             int      `json:"approval_quorum"`
	PolicyHash                 string   `json:"policy_hash"`
}

// NewPaymentApprovalPolicy builds a policy and computes its content hash.
func NewPaymentApprovalPolicy(policyID, tenantID, department, currency string, approvalAboveCents int64, requiredApprovers []string, quorum int) *PaymentApprovalPolicy {
	p := &PaymentApprovalPolicy{
		PolicyID:                   policyID,
		TenantID:                   tenantID,
		Department:                 department,
		Currency:                   currency,
		ApprovalRequiredAboveCents: approvalAboveCents,
		RequiredApprovers:          requiredApprovers,
		ApprovalQuorum:             quorum,
	}
	p.PolicyHash = p.computeHash()
	return p
}

// Validate ensures the threshold policy is well-formed. A non-positive
// threshold, an empty approver set, or a quorum that cannot be met all fail
// closed: a policy that cannot escalate is not a safe finance policy.
func (p *PaymentApprovalPolicy) Validate() error {
	if p == nil {
		return errors.New("payment_approval_policy: policy is nil")
	}
	if p.PolicyID == "" {
		return errors.New("payment_approval_policy: policy_id is required")
	}
	if p.TenantID == "" {
		return errors.New("payment_approval_policy: tenant_id is required")
	}
	if p.Department == "" {
		return errors.New("payment_approval_policy: department is required")
	}
	if p.Currency == "" {
		return errors.New("payment_approval_policy: currency is required")
	}
	if p.ApprovalRequiredAboveCents <= 0 {
		return errors.New("payment_approval_policy: approval_required_above_cents must be positive")
	}
	if len(p.RequiredApprovers) == 0 {
		return errors.New("payment_approval_policy: at least one required approver is required")
	}
	if p.ApprovalQuorum <= 0 {
		return errors.New("payment_approval_policy: approval_quorum must be positive")
	}
	if p.ApprovalQuorum > len(p.RequiredApprovers) {
		return errors.New("payment_approval_policy: approval_quorum cannot exceed the number of required approvers")
	}
	if p.PolicyHash != "" && p.PolicyHash != p.computeHash() {
		return errors.New("payment_approval_policy: policy_hash mismatch")
	}
	return nil
}

// RequiresApproval reports whether a payment amount crosses the approval gate.
func (p *PaymentApprovalPolicy) RequiresApproval(amountCents int64) bool {
	return p != nil && amountCents >= p.ApprovalRequiredAboveCents
}

// PaymentVerdict is the auditable pre-execution decision for one payment.
type PaymentVerdict struct {
	Verdict      contracts.Verdict    `json:"verdict"`
	ReasonCode   contracts.ReasonCode `json:"reason_code"`
	Reason       string               `json:"reason"`
	AmountCents  int64                `json:"amount_cents"`
	LimitCents   int64                `json:"limit_cents"`
	PolicyHash   string               `json:"policy_hash"`
	DecisionHash string               `json:"decision_hash"`
}

// Evaluate returns the fail-closed verdict for a payment amount. A payment at
// or above the limit is ESCALATE/APPROVAL_REQUIRED; otherwise it is ALLOW. A
// non-positive amount fails closed as ESCALATE so a malformed payment can never
// silently bypass the approval gate.
func (p *PaymentApprovalPolicy) Evaluate(amountCents int64) PaymentVerdict {
	v := PaymentVerdict{
		AmountCents: amountCents,
		LimitCents:  p.ApprovalRequiredAboveCents,
		PolicyHash:  p.PolicyHash,
	}
	switch {
	case amountCents <= 0:
		v.Verdict = contracts.VerdictEscalate
		v.ReasonCode = ReasonApprovalRequired
		v.Reason = "payment amount must be positive; escalating for review"
	case p.RequiresApproval(amountCents):
		v.Verdict = contracts.VerdictEscalate
		v.ReasonCode = ReasonApprovalRequired
		v.Reason = fmt.Sprintf("payment of %d %s is above the %d %s policy limit and requires approval", amountCents, p.Currency, p.ApprovalRequiredAboveCents, p.Currency)
	default:
		v.Verdict = contracts.VerdictAllow
		v.ReasonCode = ReasonWithinLimit
		v.Reason = "payment is within the policy limit"
	}
	v.DecisionHash = v.computeHash()
	return v
}

func (p *PaymentApprovalPolicy) computeHash() string {
	return hashCanonical(struct {
		PolicyID           string   `json:"policy_id"`
		TenantID           string   `json:"tenant_id"`
		Department         string   `json:"department"`
		Currency           string   `json:"currency"`
		ApprovalAboveCents int64    `json:"approval_required_above_cents"`
		RequiredApprovers  []string `json:"required_approvers"`
		ApprovalQuorum     int      `json:"approval_quorum"`
	}{p.PolicyID, p.TenantID, p.Department, p.Currency, p.ApprovalRequiredAboveCents, p.RequiredApprovers, p.ApprovalQuorum})
}

func (v PaymentVerdict) computeHash() string {
	return hashCanonical(struct {
		Verdict     contracts.Verdict    `json:"verdict"`
		ReasonCode  contracts.ReasonCode `json:"reason_code"`
		AmountCents int64                `json:"amount_cents"`
		LimitCents  int64                `json:"limit_cents"`
		PolicyHash  string               `json:"policy_hash"`
	}{v.Verdict, v.ReasonCode, v.AmountCents, v.LimitCents, v.PolicyHash})
}

func hashCanonical(value any) string {
	canon, _ := json.Marshal(value)
	h := sha256.Sum256(canon)
	return "sha256:" + hex.EncodeToString(h[:])
}
