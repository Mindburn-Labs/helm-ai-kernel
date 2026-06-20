package financedemo

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// PaymentInstruction is the connector/action context for one payment: which
// connector and action would move funds, to whom, and how much. It is the
// stubbed boundary's input. No field carries a live credential or endpoint —
// the demo never reaches a real payment rail.
type PaymentInstruction struct {
	PaymentID       string `json:"payment_id"`
	TenantID        string `json:"tenant_id"`
	ConnectorID     string `json:"connector_id"`
	Action          string `json:"action"`
	Vendor          string `json:"vendor"`
	InvoiceRef      string `json:"invoice_ref"`
	AmountCents     int64  `json:"amount_cents"`
	Currency        string `json:"currency"`
	RequestedBy     string `json:"requested_by"`
	InstructionHash string `json:"instruction_hash"`
}

// NewPaymentInstruction builds a payment instruction and seals its hash.
func NewPaymentInstruction(paymentID, tenantID, connectorID, action, vendor, invoiceRef string, amountCents int64, currency, requestedBy string) *PaymentInstruction {
	p := &PaymentInstruction{
		PaymentID:   paymentID,
		TenantID:    tenantID,
		ConnectorID: connectorID,
		Action:      action,
		Vendor:      vendor,
		InvoiceRef:  invoiceRef,
		AmountCents: amountCents,
		Currency:    currency,
		RequestedBy: requestedBy,
	}
	p.InstructionHash = p.computeHash()
	return p
}

// Validate ensures the instruction is well-formed before any boundary decision.
func (p *PaymentInstruction) Validate() error {
	if p == nil {
		return errors.New("payment_instruction: instruction is nil")
	}
	if p.PaymentID == "" {
		return errors.New("payment_instruction: payment_id is required")
	}
	if p.TenantID == "" {
		return errors.New("payment_instruction: tenant_id is required")
	}
	if p.ConnectorID == "" {
		return errors.New("payment_instruction: connector_id is required")
	}
	if p.Action == "" {
		return errors.New("payment_instruction: action is required")
	}
	if p.Vendor == "" {
		return errors.New("payment_instruction: vendor is required")
	}
	if p.AmountCents <= 0 {
		return errors.New("payment_instruction: amount_cents must be positive")
	}
	if p.Currency == "" {
		return errors.New("payment_instruction: currency is required")
	}
	if p.RequestedBy == "" {
		return errors.New("payment_instruction: requested_by is required")
	}
	return nil
}

func (p *PaymentInstruction) computeHash() string {
	return hashCanonical(struct {
		PaymentID   string `json:"payment_id"`
		TenantID    string `json:"tenant_id"`
		ConnectorID string `json:"connector_id"`
		Action      string `json:"action"`
		Vendor      string `json:"vendor"`
		InvoiceRef  string `json:"invoice_ref"`
		AmountCents int64  `json:"amount_cents"`
		Currency    string `json:"currency"`
		RequestedBy string `json:"requested_by"`
	}{p.PaymentID, p.TenantID, p.ConnectorID, p.Action, p.Vendor, p.InvoiceRef, p.AmountCents, p.Currency, p.RequestedBy})
}

// PaymentExecutionReceipt is the content-addressed proof that the stubbed
// connector executed (or, for the demo's safety, *simulated*) the payment. It
// binds the instruction, the authorizing ceremony, and the pre-execution
// verdict so a verifier can prove the effect only happened after approval.
type PaymentExecutionReceipt struct {
	ReceiptID            string               `json:"receipt_id"`
	PaymentID            string               `json:"payment_id"`
	TenantID             string               `json:"tenant_id"`
	ConnectorID          string               `json:"connector_id"`
	Action               string               `json:"action"`
	AmountCents          int64                `json:"amount_cents"`
	Currency             string               `json:"currency"`
	Verdict              contracts.Verdict    `json:"verdict"`
	ReasonCode           contracts.ReasonCode `json:"reason_code"`
	Simulated            bool                 `json:"simulated"`
	InstructionHash      string               `json:"instruction_hash"`
	DecisionHash         string               `json:"decision_hash"`
	ApprovalCeremonyHash string               `json:"approval_ceremony_hash"`
	ExecutedAt           time.Time            `json:"executed_at"`
	ContentHash          string               `json:"content_hash"`
}

func (r *PaymentExecutionReceipt) computeHash() string {
	return hashCanonical(struct {
		ReceiptID            string               `json:"receipt_id"`
		PaymentID            string               `json:"payment_id"`
		TenantID             string               `json:"tenant_id"`
		ConnectorID          string               `json:"connector_id"`
		Action               string               `json:"action"`
		AmountCents          int64                `json:"amount_cents"`
		Currency             string               `json:"currency"`
		Verdict              contracts.Verdict    `json:"verdict"`
		ReasonCode           contracts.ReasonCode `json:"reason_code"`
		Simulated            bool                 `json:"simulated"`
		InstructionHash      string               `json:"instruction_hash"`
		DecisionHash         string               `json:"decision_hash"`
		ApprovalCeremonyHash string               `json:"approval_ceremony_hash"`
	}{r.ReceiptID, r.PaymentID, r.TenantID, r.ConnectorID, r.Action, r.AmountCents, r.Currency, r.Verdict, r.ReasonCode, r.Simulated, r.InstructionHash, r.DecisionHash, r.ApprovalCeremonyHash})
}

// StubPaymentConnector is the fail-closed, side-effect-free payment boundary.
//
// It NEVER contacts a real payment rail. risk:r3-external-effect is honored by
// construction: Execute returns a *simulated* receipt and refuses entirely
// unless a sealed, approved approval ceremony authorizes the instruction.
type StubPaymentConnector struct {
	// now is injectable so execution receipts are deterministic in tests/demo.
	now func() time.Time
}

// NewStubPaymentConnector returns a connector with the given clock. A nil clock
// defaults to the wall clock.
func NewStubPaymentConnector(now func() time.Time) *StubPaymentConnector {
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &StubPaymentConnector{now: now}
}

// Execute is the connector/action boundary. It is the security-critical gate:
//
//   - it requires a pre-execution verdict that already cleared approval (ALLOW),
//   - for any escalated payment it requires a sealed approval ceremony whose
//     state is approved AND whose distinct approvers meet the policy quorum,
//   - it performs NO real effect (Simulated is always true).
//
// Any missing or non-approved authorization fails closed with an error and no
// receipt — the boundary cannot be tricked into moving funds without approval.
func (c *StubPaymentConnector) Execute(instr *PaymentInstruction, decision PaymentVerdict, policy *PaymentApprovalPolicy, ceremony *contracts.ApprovalCeremony) (*PaymentExecutionReceipt, error) {
	if err := instr.Validate(); err != nil {
		return nil, err
	}
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	if decision.Verdict != contracts.VerdictAllow {
		return nil, fmt.Errorf("stub_payment_connector: refusing to execute payment %s: pre-execution verdict is %s/%s, not ALLOW", instr.PaymentID, decision.Verdict, decision.ReasonCode)
	}
	if decision.AmountCents != instr.AmountCents {
		return nil, errors.New("stub_payment_connector: decision amount does not match instruction amount")
	}

	ceremonyHash := ""
	// A payment that the policy says needs approval can only execute behind a
	// satisfied ceremony. A within-limit payment may execute without one.
	if policy.RequiresApproval(instr.AmountCents) {
		if err := approvalSatisfiesPolicy(ceremony, policy, instr); err != nil {
			return nil, err
		}
		ceremonyHash = ceremony.CeremonyHash
	}

	receipt := &PaymentExecutionReceipt{
		ReceiptID:            "pay-rcpt-" + shortHash(instr.InstructionHash),
		PaymentID:            instr.PaymentID,
		TenantID:             instr.TenantID,
		ConnectorID:          instr.ConnectorID,
		Action:               instr.Action,
		AmountCents:          instr.AmountCents,
		Currency:             instr.Currency,
		Verdict:              contracts.VerdictAllow,
		ReasonCode:           decision.ReasonCode,
		Simulated:            true, // r3: never a real effect.
		InstructionHash:      instr.InstructionHash,
		DecisionHash:         decision.DecisionHash,
		ApprovalCeremonyHash: ceremonyHash,
		ExecutedAt:           c.now(),
	}
	receipt.ContentHash = receipt.computeHash()
	return receipt, nil
}

// approvalSatisfiesPolicy enforces the dual-control + quorum invariant that
// authorizes an above-limit payment. It mirrors the SPEND5 correctionApproved
// rule (sealed, approved, approver distinct from requester) and additionally
// requires the configured quorum of policy-recognized approvers and that the
// ceremony actually binds this payment instruction.
func approvalSatisfiesPolicy(a *contracts.ApprovalCeremony, policy *PaymentApprovalPolicy, instr *PaymentInstruction) error {
	if a == nil {
		return errors.New("stub_payment_connector: above-limit payment requires an approval ceremony")
	}
	if err := a.Validate(); err != nil {
		return err
	}
	if a.CeremonyHash == "" || a.CeremonyHash != sealedCeremonyHash(a) {
		return errors.New("stub_payment_connector: approval ceremony is not sealed")
	}
	if a.State != contracts.ApprovalCeremonyAllowed {
		return fmt.Errorf("stub_payment_connector: approval ceremony state is %q, not approved", a.State)
	}
	if a.Subject != paymentSubject(instr) {
		return errors.New("stub_payment_connector: approval ceremony does not bind this payment")
	}

	// Count distinct approvers that the policy recognizes and that are not the
	// requester (dual control). The count must meet the policy quorum.
	allowed := make(map[string]struct{}, len(policy.RequiredApprovers))
	for _, ap := range policy.RequiredApprovers {
		allowed[ap] = struct{}{}
	}
	seen := make(map[string]struct{}, len(a.Approvers))
	distinct := 0
	for _, approver := range a.Approvers {
		if approver == "" || approver == a.RequestedBy {
			continue
		}
		if _, ok := allowed[approver]; !ok {
			continue
		}
		if _, dup := seen[approver]; dup {
			continue
		}
		seen[approver] = struct{}{}
		distinct++
	}
	if distinct < policy.ApprovalQuorum {
		return fmt.Errorf("stub_payment_connector: approval quorum not met: %d of %d required policy approvers", distinct, policy.ApprovalQuorum)
	}
	return nil
}

// paymentSubject is the canonical subject string an approval ceremony must
// carry to authorize a given payment instruction.
func paymentSubject(instr *PaymentInstruction) string {
	return "payment:" + instr.PaymentID
}

// sealedCeremonyHash recomputes the ceremony's seal so the connector can detect
// a tampered or unsealed ceremony.
func sealedCeremonyHash(a *contracts.ApprovalCeremony) string {
	sealed, err := a.Seal()
	if err != nil {
		return ""
	}
	return sealed.CeremonyHash
}

func shortHash(h string) string {
	sum := sha256.Sum256([]byte(h))
	return hex.EncodeToString(sum[:])[:12]
}
