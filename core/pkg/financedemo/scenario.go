package financedemo

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// fixedClock is the deterministic timestamp the demo uses everywhere a time is
// hashed or recorded, so the scenario, its receipts, and the EvidencePack are
// byte-reproducible across runs and machines.
var fixedClock = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// FixedClock returns the deterministic demo clock.
func FixedClock() time.Time { return fixedClock }

// ScenarioReceipt is one Lamport-ordered, hash-chained step in the finance
// workflow. The chain is what the EvidencePack seals and a verifier replays.
type ScenarioReceipt struct {
	ReceiptID  string `json:"receipt_id"`
	Step       string `json:"step"`
	Principal  string `json:"principal"`
	Action     string `json:"action"`
	Connector  string `json:"connector,omitempty"`
	Verdict    string `json:"verdict"`
	ReasonCode string `json:"reason_code"`
	Lamport    uint64 `json:"lamport_clock"`
	PrevHash   string `json:"prev_hash"`
	Hash       string `json:"hash"`
	// DecisionHash binds this step's governance decision. It mirrors the chain
	// hash so each receipt is independently decision-bound for the EvidencePack
	// verifier (policy_decision_hashes); the richer domain hashes (policy,
	// ceremony, execution) are carried in Detail.
	DecisionHash string            `json:"decision_hash"`
	Detail       map[string]string `json:"detail,omitempty"`
}

// ScenarioResult is the full, deterministic output of the finance demo. Every
// acceptance artifact the issue asks for is a field here.
type ScenarioResult struct {
	Policy             *PaymentApprovalPolicy      `json:"policy"`               // threshold policy
	Instruction        *PaymentInstruction         `json:"instruction"`          // connector/action context
	PreApprovalVerdict PaymentVerdict              `json:"pre_approval_verdict"` // ESCALATE before execution
	Ceremony           *contracts.ApprovalCeremony `json:"approval_ceremony"`    // CFO/Finance approval requirement + result
	ExecutionReceipt   *PaymentExecutionReceipt    `json:"execution_receipt"`    // receipt (with hashes)
	Receipts           []ScenarioReceipt           `json:"receipts"`             // hash-chained proof log
	RootHash           string                      `json:"root_hash"`
	LamportFinal       uint64                      `json:"lamport_final"`
}

// ScenarioInput parameterizes the demo. Zero values fall back to the canonical
// "Acme Finance" reference scenario.
type ScenarioInput struct {
	TenantID         string
	Department       string
	Currency         string
	LimitCents       int64
	PaymentCents     int64
	Vendor           string
	InvoiceRef       string
	ConnectorID      string
	Action           string
	Requester        string
	Approvers        []string
	Quorum           int
	ApproverDecision []string // subset of Approvers that actually approve
}

func (in ScenarioInput) withDefaults() ScenarioInput {
	if in.TenantID == "" {
		in.TenantID = "acme-corp"
	}
	if in.Department == "" {
		in.Department = "finance"
	}
	if in.Currency == "" {
		in.Currency = "USD"
	}
	if in.LimitCents == 0 {
		in.LimitCents = 1_000_000 // $10,000.00 policy limit
	}
	if in.PaymentCents == 0 {
		in.PaymentCents = 4_250_000 // $42,500.00 vendor invoice (above limit)
	}
	if in.Vendor == "" {
		in.Vendor = "Northwind Logistics"
	}
	if in.InvoiceRef == "" {
		in.InvoiceRef = "INV-2026-0042"
	}
	if in.ConnectorID == "" {
		in.ConnectorID = "stub-ap-payments"
	}
	if in.Action == "" {
		in.Action = "vendor_payment.send"
	}
	if in.Requester == "" {
		in.Requester = "ap-clerk@acme.example"
	}
	if len(in.Approvers) == 0 {
		in.Approvers = []string{"cfo@acme.example", "finance-controller@acme.example"}
	}
	if in.Quorum == 0 {
		in.Quorum = 2
	}
	if in.ApproverDecision == nil {
		in.ApproverDecision = in.Approvers
	}
	return in
}

// RunScenario executes the deterministic finance escalation workflow and
// returns the full proof set. It performs NO real side effect.
//
// The flow is:
//  1. Build the threshold policy.
//  2. Build the payment instruction (connector/action context).
//  3. Evaluate the payment -> ESCALATE/APPROVAL_REQUIRED (above the limit),
//     proving the payment cannot execute yet.
//  4. Open an approval ceremony naming the required approvers (CFO/Finance).
//  5. Record the human approval result (ceremony -> approved, sealed).
//  6. Re-evaluate as an approval-cleared ALLOW and run the stubbed connector,
//     which fails closed unless the sealed ceremony meets policy.
//  7. Emit a hash-chained receipt log over every step.
func RunScenario(in ScenarioInput) (*ScenarioResult, error) {
	in = in.withDefaults()

	policy := NewPaymentApprovalPolicy("finance.payments.approval", in.TenantID, in.Department, in.Currency, in.LimitCents, in.Approvers, in.Quorum)
	if err := policy.Validate(); err != nil {
		return nil, err
	}

	instr := NewPaymentInstruction(
		"pay-"+shortHash(in.InvoiceRef),
		in.TenantID, in.ConnectorID, in.Action, in.Vendor, in.InvoiceRef,
		in.PaymentCents, in.Currency, in.Requester,
	)
	if err := instr.Validate(); err != nil {
		return nil, err
	}

	// Pre-approval verdict: above the limit -> ESCALATE. This is the gate.
	preVerdict := policy.Evaluate(instr.AmountCents)
	if preVerdict.Verdict != contracts.VerdictEscalate {
		// This demo is specifically the above-limit path; a within-limit amount
		// here would mean the scenario was misconfigured.
		return nil, fmt.Errorf("financedemo: expected ESCALATE for payment above limit, got %s", preVerdict.Verdict)
	}

	r := &ScenarioResult{
		Policy:             policy,
		Instruction:        instr,
		PreApprovalVerdict: preVerdict,
	}

	emit := r.receiptEmitter()

	emit("policy_published", "finance-admin@acme.example", "PUBLISH_PAYMENT_POLICY", "", string(contracts.VerdictAllow), "POLICY_PUBLISHED", map[string]string{
		"policy_hash": policy.PolicyHash,
		"limit_cents": fmt.Sprintf("%d", policy.ApprovalRequiredAboveCents),
		"quorum":      fmt.Sprintf("%d", policy.ApprovalQuorum),
	})
	emit("payment_requested", in.Requester, "REQUEST_PAYMENT", instr.ConnectorID, "PENDING", "PAYMENT_SUBMITTED", map[string]string{
		"vendor":           instr.Vendor,
		"invoice_ref":      instr.InvoiceRef,
		"amount_cents":     fmt.Sprintf("%d", instr.AmountCents),
		"instruction_hash": instr.InstructionHash,
	})
	// The escalation step: the payment is blocked from executing.
	emit("policy_escalated", "helm-kernel", "EVALUATE_PAYMENT", instr.ConnectorID, string(preVerdict.Verdict), string(preVerdict.ReasonCode), map[string]string{
		"decision_hash": preVerdict.DecisionHash,
		"limit_cents":   fmt.Sprintf("%d", preVerdict.LimitCents),
		"amount_cents":  fmt.Sprintf("%d", preVerdict.AmountCents),
	})

	// Open + resolve the approval ceremony (the human approval result).
	ceremony, err := approveCeremony(instr, policy, in.Requester, in.ApproverDecision)
	if err != nil {
		return nil, err
	}
	r.Ceremony = ceremony
	emit("approval_recorded", approversLabel(in.ApproverDecision), "APPROVE_PAYMENT", instr.ConnectorID, string(contracts.VerdictAllow), "APPROVAL_GRANTED", map[string]string{
		"ceremony_hash": ceremony.CeremonyHash,
		"approvers":     approversLabel(ceremony.Approvers),
		"quorum_met":    fmt.Sprintf("%d/%d", len(in.ApproverDecision), policy.ApprovalQuorum),
	})

	// Post-approval: the verdict clears to ALLOW and the stubbed connector runs.
	postVerdict := preVerdict
	postVerdict.Verdict = contracts.VerdictAllow
	postVerdict.ReasonCode = contracts.ReasonCode("OK_APPROVED")
	postVerdict.Reason = "payment approved by required approvers"
	postVerdict.DecisionHash = postVerdict.computeHash()

	connector := NewStubPaymentConnector(FixedClock)
	execReceipt, err := connector.Execute(instr, postVerdict, policy, ceremony)
	if err != nil {
		return nil, err
	}
	r.ExecutionReceipt = execReceipt
	emit("payment_executed", "helm-kernel", "EXECUTE_PAYMENT", instr.ConnectorID, string(execReceipt.Verdict), string(execReceipt.ReasonCode), map[string]string{
		"execution_receipt_hash": execReceipt.ContentHash,
		"simulated":              fmt.Sprintf("%t", execReceipt.Simulated),
		"approval_ceremony_hash": execReceipt.ApprovalCeremonyHash,
	})

	r.RootHash = r.lastHash()
	r.LamportFinal = uint64(len(r.Receipts))
	return r, nil
}

// approveCeremony builds an approval ceremony bound to the payment, records the
// approver decision, and seals it. The resulting ceremony is the human approval
// result the connector boundary requires.
func approveCeremony(instr *PaymentInstruction, policy *PaymentApprovalPolicy, requester string, approvers []string) (*contracts.ApprovalCeremony, error) {
	if len(approvers) == 0 {
		return nil, errors.New("financedemo: at least one approver decision is required")
	}
	ceremony := contracts.ApprovalCeremony{
		ApprovalID:  "appr-" + shortHash(instr.InstructionHash),
		Subject:     paymentSubject(instr),
		Action:      instr.Action,
		State:       contracts.ApprovalCeremonyAllowed,
		RequestedBy: requester,
		Approvers:   approvers,
		Quorum:      policy.ApprovalQuorum,
		AuthMethod:  "demo-scripted",
		Reason:      fmt.Sprintf("approve %s payment to %s (invoice %s)", instr.Currency, instr.Vendor, instr.InvoiceRef),
		CreatedAt:   fixedClock,
		UpdatedAt:   fixedClock,
	}
	sealed, err := ceremony.Seal()
	if err != nil {
		return nil, fmt.Errorf("financedemo: seal approval ceremony: %w", err)
	}
	return &sealed, nil
}

// receiptEmitter returns a closure that appends a Lamport-ordered, hash-chained
// receipt to the result. The chain is deterministic: no wall clock enters a
// hashed field.
func (r *ScenarioResult) receiptEmitter() func(step, principal, action, connector, verdict, reason string, detail map[string]string) ScenarioReceipt {
	return func(step, principal, action, connector, verdict, reason string, detail map[string]string) ScenarioReceipt {
		lamport := uint64(len(r.Receipts)) + 1
		prev := r.lastHash()
		preimage := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%d|%s", step, principal, action, connector, verdict, reason, lamport, prev)
		sum := sha256.Sum256([]byte(preimage))
		hash := hex.EncodeToString(sum[:])
		rec := ScenarioReceipt{
			ReceiptID:    fmt.Sprintf("fin-rcpt-%s-%d", hash[:8], lamport),
			Step:         step,
			Principal:    principal,
			Action:       action,
			Connector:    connector,
			Verdict:      verdict,
			ReasonCode:   reason,
			Lamport:      lamport,
			PrevHash:     prev,
			Hash:         hash,
			DecisionHash: "sha256:" + hash,
			Detail:       detail,
		}
		r.Receipts = append(r.Receipts, rec)
		return rec
	}
}

func (r *ScenarioResult) lastHash() string {
	if len(r.Receipts) == 0 {
		return ""
	}
	return r.Receipts[len(r.Receipts)-1].Hash
}

// VerifyChain re-derives the receipt chain and reports the first break, if any.
// It is the deterministic-replay check the demo and tests run on the proof log.
func (r *ScenarioResult) VerifyChain() error {
	prev := ""
	for _, rec := range r.Receipts {
		if rec.PrevHash != prev {
			return fmt.Errorf("financedemo: chain break at lamport %d: prev_hash mismatch", rec.Lamport)
		}
		preimage := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%d|%s", rec.Step, rec.Principal, rec.Action, rec.Connector, rec.Verdict, rec.ReasonCode, rec.Lamport, rec.PrevHash)
		sum := sha256.Sum256([]byte(preimage))
		if got := hex.EncodeToString(sum[:]); got != rec.Hash {
			return fmt.Errorf("financedemo: chain break at lamport %d: hash mismatch", rec.Lamport)
		}
		prev = rec.Hash
	}
	return nil
}

func approversLabel(approvers []string) string {
	out := ""
	for i, a := range approvers {
		if i > 0 {
			out += "+"
		}
		out += a
	}
	if out == "" {
		return "none"
	}
	return out
}
