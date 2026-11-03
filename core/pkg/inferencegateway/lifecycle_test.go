package inferencegateway

import (
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/economic"
)

// newLedger builds an isolated balance ledger with a controllable opening
// balance for pure-lifecycle (non-engine) tests.
func newLedger(t *testing.T, openingCents int64) *BalanceLedger {
	t.Helper()
	acct := economic.NewBalanceAccount("balance-lc", "tenant-1", "USD", openingCents, "evidence://balance-lc")
	l, err := NewBalanceLedger(acct)
	if err != nil {
		t.Fatalf("new ledger: %v", err)
	}
	return l
}

// approvedCeremony builds a sealed, dual-control approval ceremony.
func approvedCeremony(t *testing.T, requester, approver string) *contracts.ApprovalCeremony {
	t.Helper()
	now := time.Now().UTC()
	c := contracts.ApprovalCeremony{
		ApprovalID:  "appr-1",
		Subject:     "balance:balance-lc",
		Action:      "correction",
		State:       contracts.ApprovalCeremonyAllowed,
		RequestedBy: requester,
		Approvers:   []string{approver},
		Reason:      "manual correction after provider credit dispute",
		ReceiptID:   "rcpt-appr-1",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	sealed, err := c.Seal()
	if err != nil {
		t.Fatalf("seal ceremony: %v", err)
	}
	return &sealed
}
