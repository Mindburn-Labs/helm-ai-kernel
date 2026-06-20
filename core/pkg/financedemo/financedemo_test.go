package financedemo

import (
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// --- Threshold policy verdict (escalate is the gate) ---------------------------

func TestPolicy_EscalatesAboveLimit(t *testing.T) {
	p := NewPaymentApprovalPolicy("finance.payments", "acme", "finance", "USD", 1_000_000, []string{"cfo@acme", "controller@acme"}, 2)
	if err := p.Validate(); err != nil {
		t.Fatalf("valid policy rejected: %v", err)
	}

	above := p.Evaluate(1_000_001)
	if above.Verdict != contracts.VerdictEscalate {
		t.Fatalf("payment above limit: want ESCALATE, got %s", above.Verdict)
	}
	if above.ReasonCode != contracts.ReasonApprovalRequired {
		t.Fatalf("payment above limit: want APPROVAL_REQUIRED reason, got %s", above.ReasonCode)
	}

	atLimit := p.Evaluate(1_000_000)
	if atLimit.Verdict != contracts.VerdictEscalate {
		t.Fatalf("payment at limit: want ESCALATE (>=), got %s", atLimit.Verdict)
	}
}

func TestPolicy_AllowsWithinLimit(t *testing.T) {
	p := NewPaymentApprovalPolicy("finance.payments", "acme", "finance", "USD", 1_000_000, []string{"cfo@acme"}, 1)
	below := p.Evaluate(999_999)
	if below.Verdict != contracts.VerdictAllow {
		t.Fatalf("payment below limit: want ALLOW, got %s", below.Verdict)
	}
	if below.ReasonCode != ReasonWithinLimit {
		t.Fatalf("payment below limit: want OK_WITHIN_PAYMENT_LIMIT, got %s", below.ReasonCode)
	}
}

func TestPolicy_NonPositiveAmountFailsClosed(t *testing.T) {
	p := NewPaymentApprovalPolicy("finance.payments", "acme", "finance", "USD", 1_000_000, []string{"cfo@acme"}, 1)
	for _, amt := range []int64{0, -1, -5000} {
		v := p.Evaluate(amt)
		if v.Verdict != contracts.VerdictEscalate {
			t.Fatalf("non-positive amount %d: want fail-closed ESCALATE, got %s", amt, v.Verdict)
		}
	}
}

func TestPolicy_VerdictHashIsStable(t *testing.T) {
	p := NewPaymentApprovalPolicy("finance.payments", "acme", "finance", "USD", 1_000_000, []string{"cfo@acme", "controller@acme"}, 2)
	a := p.Evaluate(4_250_000)
	b := p.Evaluate(4_250_000)
	if a.DecisionHash == "" || a.DecisionHash != b.DecisionHash {
		t.Fatalf("verdict hash not stable: %q vs %q", a.DecisionHash, b.DecisionHash)
	}
	if !strings.HasPrefix(a.DecisionHash, "sha256:") {
		t.Fatalf("verdict hash missing sha256 prefix: %q", a.DecisionHash)
	}
}

func TestPolicy_InvalidConfigsRejected(t *testing.T) {
	cases := map[string]*PaymentApprovalPolicy{
		"no threshold":       NewPaymentApprovalPolicy("p", "t", "finance", "USD", 0, []string{"cfo"}, 1),
		"negative threshold": NewPaymentApprovalPolicy("p", "t", "finance", "USD", -1, []string{"cfo"}, 1),
		"no approvers":       NewPaymentApprovalPolicy("p", "t", "finance", "USD", 100, nil, 1),
		"quorum too high":    NewPaymentApprovalPolicy("p", "t", "finance", "USD", 100, []string{"cfo"}, 2),
		"zero quorum":        NewPaymentApprovalPolicy("p", "t", "finance", "USD", 100, []string{"cfo"}, 0),
	}
	for name, p := range cases {
		if err := p.Validate(); err == nil {
			t.Fatalf("%s: expected validation error, got nil", name)
		}
	}
}

func TestPolicy_TamperedHashRejected(t *testing.T) {
	p := NewPaymentApprovalPolicy("finance.payments", "acme", "finance", "USD", 1_000_000, []string{"cfo@acme"}, 1)
	p.ApprovalRequiredAboveCents = 50 // mutate after sealing, do not recompute
	if err := p.Validate(); err == nil {
		t.Fatal("tampered policy_hash must be rejected")
	}
}

// --- Connector boundary: the security-critical fail-closed invariants ----------

func approvedCeremonyFor(instr *PaymentInstruction, policy *PaymentApprovalPolicy, requester string, approvers []string) *contracts.ApprovalCeremony {
	c, err := approveCeremony(instr, policy, requester, approvers)
	if err != nil {
		panic(err)
	}
	return c
}

func baseSetup() (*PaymentInstruction, *PaymentApprovalPolicy) {
	policy := NewPaymentApprovalPolicy("finance.payments", "acme", "finance", "USD", 1_000_000, []string{"cfo@acme", "controller@acme"}, 2)
	instr := NewPaymentInstruction("pay-1", "acme", "stub-ap", "vendor_payment.send", "Northwind", "INV-1", 4_250_000, "USD", "clerk@acme")
	return instr, policy
}

func TestConnector_RefusesEscalateVerdict(t *testing.T) {
	instr, policy := baseSetup()
	escalate := policy.Evaluate(instr.AmountCents) // ESCALATE
	ceremony := approvedCeremonyFor(instr, policy, instr.RequestedBy, policy.RequiredApprovers)

	conn := NewStubPaymentConnector(FixedClock)
	_, err := conn.Execute(instr, escalate, policy, ceremony)
	if err == nil {
		t.Fatal("connector must refuse a payment whose pre-execution verdict is ESCALATE")
	}
	if !strings.Contains(err.Error(), "not ALLOW") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func allowVerdict(instr *PaymentInstruction, policy *PaymentApprovalPolicy) PaymentVerdict {
	v := policy.Evaluate(instr.AmountCents)
	v.Verdict = contracts.VerdictAllow
	v.ReasonCode = contracts.ReasonCode("OK_APPROVED")
	v.DecisionHash = v.computeHash()
	return v
}

func TestConnector_RefusesAboveLimitWithoutCeremony(t *testing.T) {
	instr, policy := baseSetup()
	v := allowVerdict(instr, policy)
	conn := NewStubPaymentConnector(FixedClock)
	_, err := conn.Execute(instr, v, policy, nil)
	if err == nil {
		t.Fatal("above-limit payment must require an approval ceremony")
	}
	if !strings.Contains(err.Error(), "requires an approval ceremony") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestConnector_RefusesUnapprovedCeremony(t *testing.T) {
	instr, policy := baseSetup()
	v := allowVerdict(instr, policy)

	ceremony := contracts.ApprovalCeremony{
		ApprovalID:  "appr-x",
		Subject:     paymentSubject(instr),
		Action:      instr.Action,
		State:       contracts.ApprovalCeremonyPending, // NOT approved
		RequestedBy: instr.RequestedBy,
		Approvers:   policy.RequiredApprovers,
		CreatedAt:   FixedClock(),
		UpdatedAt:   FixedClock(),
	}
	sealed, err := ceremony.Seal()
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	conn := NewStubPaymentConnector(FixedClock)
	if _, err := conn.Execute(instr, v, policy, &sealed); err == nil {
		t.Fatal("connector must refuse a pending (unapproved) ceremony")
	}
}

func TestConnector_RefusesUnsealedCeremony(t *testing.T) {
	instr, policy := baseSetup()
	v := allowVerdict(instr, policy)

	// Approved but never sealed (CeremonyHash empty).
	ceremony := &contracts.ApprovalCeremony{
		ApprovalID:  "appr-x",
		Subject:     paymentSubject(instr),
		Action:      instr.Action,
		State:       contracts.ApprovalCeremonyAllowed,
		RequestedBy: instr.RequestedBy,
		Approvers:   policy.RequiredApprovers,
		CreatedAt:   FixedClock(),
		UpdatedAt:   FixedClock(),
	}
	conn := NewStubPaymentConnector(FixedClock)
	if _, err := conn.Execute(instr, v, policy, ceremony); err == nil {
		t.Fatal("connector must refuse an unsealed ceremony")
	}
}

func TestConnector_RefusesTamperedCeremony(t *testing.T) {
	instr, policy := baseSetup()
	v := allowVerdict(instr, policy)
	ceremony := approvedCeremonyFor(instr, policy, instr.RequestedBy, policy.RequiredApprovers)

	// Tamper after sealing: change content but keep the stale seal hash.
	ceremony.Action = "vendor_payment.send.evil"
	conn := NewStubPaymentConnector(FixedClock)
	if _, err := conn.Execute(instr, v, policy, ceremony); err == nil {
		t.Fatal("connector must refuse a ceremony whose seal no longer matches its content")
	}
}

func TestConnector_RefusesQuorumNotMet(t *testing.T) {
	instr, policy := baseSetup() // quorum 2
	v := allowVerdict(instr, policy)
	// Only one approver actually signs.
	ceremony := approvedCeremonyFor(instr, policy, instr.RequestedBy, []string{"cfo@acme"})
	conn := NewStubPaymentConnector(FixedClock)
	if _, err := conn.Execute(instr, v, policy, ceremony); err == nil {
		t.Fatal("connector must refuse when approval quorum is not met")
	}
}

func TestConnector_RefusesSelfApproval(t *testing.T) {
	// Dual control: the requester cannot be the approving party.
	policy := NewPaymentApprovalPolicy("finance.payments", "acme", "finance", "USD", 1_000_000, []string{"clerk@acme", "cfo@acme"}, 1)
	instr := NewPaymentInstruction("pay-1", "acme", "stub-ap", "vendor_payment.send", "Northwind", "INV-1", 4_250_000, "USD", "clerk@acme")
	v := allowVerdict(instr, policy)
	// The only "approver" is the requester themselves.
	ceremony := approvedCeremonyFor(instr, policy, "clerk@acme", []string{"clerk@acme"})
	conn := NewStubPaymentConnector(FixedClock)
	if _, err := conn.Execute(instr, v, policy, ceremony); err == nil {
		t.Fatal("connector must refuse self-approval (dual control)")
	}
}

func TestConnector_RefusesCeremonyBindingWrongPayment(t *testing.T) {
	instr, policy := baseSetup()
	other := NewPaymentInstruction("pay-OTHER", "acme", "stub-ap", "vendor_payment.send", "Northwind", "INV-99", 4_250_000, "USD", "clerk@acme")
	v := allowVerdict(instr, policy)
	// Ceremony is for a DIFFERENT payment.
	ceremony := approvedCeremonyFor(other, policy, instr.RequestedBy, policy.RequiredApprovers)
	conn := NewStubPaymentConnector(FixedClock)
	if _, err := conn.Execute(instr, v, policy, ceremony); err == nil {
		t.Fatal("connector must refuse a ceremony bound to a different payment")
	}
}

func TestConnector_RefusesAmountMismatch(t *testing.T) {
	instr, policy := baseSetup()
	v := allowVerdict(instr, policy)
	v.AmountCents = instr.AmountCents - 1 // verdict no longer matches instruction
	ceremony := approvedCeremonyFor(instr, policy, instr.RequestedBy, policy.RequiredApprovers)
	conn := NewStubPaymentConnector(FixedClock)
	if _, err := conn.Execute(instr, v, policy, ceremony); err == nil {
		t.Fatal("connector must refuse when verdict amount != instruction amount")
	}
}

func TestConnector_ExecutesWhenApprovedAndSimulatesOnly(t *testing.T) {
	instr, policy := baseSetup()
	v := allowVerdict(instr, policy)
	ceremony := approvedCeremonyFor(instr, policy, instr.RequestedBy, policy.RequiredApprovers)
	conn := NewStubPaymentConnector(FixedClock)
	rcpt, err := conn.Execute(instr, v, policy, ceremony)
	if err != nil {
		t.Fatalf("approved payment must execute: %v", err)
	}
	if !rcpt.Simulated {
		t.Fatal("r3 safety: execution receipt must be Simulated=true (no real effect)")
	}
	if rcpt.Verdict != contracts.VerdictAllow {
		t.Fatalf("execution receipt verdict: want ALLOW, got %s", rcpt.Verdict)
	}
	if rcpt.ApprovalCeremonyHash != ceremony.CeremonyHash {
		t.Fatal("execution receipt must bind the authorizing ceremony hash")
	}
	if rcpt.ContentHash == "" || rcpt.ContentHash != rcpt.computeHash() {
		t.Fatal("execution receipt content hash must be stable and present")
	}
}

func TestConnector_WithinLimitExecutesWithoutCeremony(t *testing.T) {
	policy := NewPaymentApprovalPolicy("finance.payments", "acme", "finance", "USD", 1_000_000, []string{"cfo@acme"}, 1)
	instr := NewPaymentInstruction("pay-small", "acme", "stub-ap", "vendor_payment.send", "Northwind", "INV-2", 500_000, "USD", "clerk@acme")
	v := policy.Evaluate(instr.AmountCents) // ALLOW within limit
	if v.Verdict != contracts.VerdictAllow {
		t.Fatalf("within-limit precondition: want ALLOW, got %s", v.Verdict)
	}
	conn := NewStubPaymentConnector(FixedClock)
	rcpt, err := conn.Execute(instr, v, policy, nil)
	if err != nil {
		t.Fatalf("within-limit payment should execute without a ceremony: %v", err)
	}
	if rcpt.ApprovalCeremonyHash != "" {
		t.Fatal("within-limit payment should not reference a ceremony")
	}
}

// --- End-to-end scenario + determinism -----------------------------------------

func TestRunScenario_EscalatesThenExecutesAfterApproval(t *testing.T) {
	res, err := RunScenario(ScenarioInput{})
	if err != nil {
		t.Fatalf("scenario failed: %v", err)
	}
	if res.PreApprovalVerdict.Verdict != contracts.VerdictEscalate {
		t.Fatalf("pre-approval verdict: want ESCALATE, got %s", res.PreApprovalVerdict.Verdict)
	}
	if res.Ceremony == nil || res.Ceremony.State != contracts.ApprovalCeremonyAllowed {
		t.Fatal("scenario must record an approved ceremony")
	}
	if res.ExecutionReceipt == nil || !res.ExecutionReceipt.Simulated {
		t.Fatal("scenario must produce a simulated execution receipt")
	}
	if err := res.VerifyChain(); err != nil {
		t.Fatalf("scenario receipt chain must verify: %v", err)
	}

	// The escalation must appear in the proof log BEFORE the execution step.
	escIdx, execIdx := -1, -1
	for i, r := range res.Receipts {
		switch r.Step {
		case "policy_escalated":
			escIdx = i
		case "payment_executed":
			execIdx = i
		}
	}
	if escIdx < 0 || execIdx < 0 {
		t.Fatalf("missing escalation/execution steps: esc=%d exec=%d", escIdx, execIdx)
	}
	if escIdx >= execIdx {
		t.Fatalf("escalation (idx %d) must precede execution (idx %d)", escIdx, execIdx)
	}
	if res.Receipts[escIdx].Verdict != string(contracts.VerdictEscalate) {
		t.Fatalf("escalation step verdict: want ESCALATE, got %s", res.Receipts[escIdx].Verdict)
	}
}

func TestRunScenario_IsDeterministic(t *testing.T) {
	a, err := RunScenario(ScenarioInput{})
	if err != nil {
		t.Fatalf("run a: %v", err)
	}
	b, err := RunScenario(ScenarioInput{})
	if err != nil {
		t.Fatalf("run b: %v", err)
	}
	if a.RootHash == "" || a.RootHash != b.RootHash {
		t.Fatalf("scenario root hash not deterministic: %q vs %q", a.RootHash, b.RootHash)
	}
	if a.Policy.PolicyHash != b.Policy.PolicyHash {
		t.Fatal("policy hash not deterministic")
	}
	if a.Ceremony.CeremonyHash != b.Ceremony.CeremonyHash {
		t.Fatal("ceremony hash not deterministic")
	}
	if a.ExecutionReceipt.ContentHash != b.ExecutionReceipt.ContentHash {
		t.Fatal("execution receipt hash not deterministic")
	}
}

func TestRunScenario_QuorumShortfallBlocksExecution(t *testing.T) {
	// Approvers configured for quorum 2, but only one signs => scenario fails at
	// the connector boundary, proving the gate cannot be bypassed end to end.
	_, err := RunScenario(ScenarioInput{
		Approvers:        []string{"cfo@acme.example", "finance-controller@acme.example"},
		Quorum:           2,
		ApproverDecision: []string{"cfo@acme.example"},
	})
	if err == nil {
		t.Fatal("scenario must fail when the approval quorum is not met")
	}
	if !strings.Contains(err.Error(), "quorum not met") {
		t.Fatalf("unexpected error: %v", err)
	}
}
