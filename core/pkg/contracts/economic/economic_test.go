package economic

import (
	"encoding/json"
	"testing"
	"time"
)

// ── SpendIntent ────────────────────────────────────────────────────

func TestSpendIntentDeterministicHash(t *testing.T) {
	a := NewSpendIntent("si-1", "t-1", "test spend", 10000, "USD", SpendOperational, "b-1", "user-1", "testing")
	b := NewSpendIntent("si-1", "t-1", "test spend", 10000, "USD", SpendOperational, "b-1", "user-1", "testing")
	// Same inputs must produce same hash (timestamps differ, but hash excludes time)
	if a.ContentHash != b.ContentHash {
		t.Errorf("determinism: want same hash, got %s vs %s", a.ContentHash, b.ContentHash)
	}
}

func TestSpendIntentValidation(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(*SpendIntent)
		wantErr bool
	}{
		{"valid", func(si *SpendIntent) {}, false},
		{"no id", func(si *SpendIntent) { si.ID = "" }, true},
		{"no tenant", func(si *SpendIntent) { si.TenantID = "" }, true},
		{"zero amount", func(si *SpendIntent) { si.AmountCents = 0 }, true},
		{"negative amount", func(si *SpendIntent) { si.AmountCents = -100 }, true},
		{"no currency", func(si *SpendIntent) { si.Currency = "" }, true},
		{"no budget", func(si *SpendIntent) { si.BudgetID = "" }, true},
		{"no requester", func(si *SpendIntent) { si.RequestedBy = "" }, true},
		{"no category", func(si *SpendIntent) { si.Category = "" }, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			si := NewSpendIntent("si-1", "t-1", "test", 1000, "USD", SpendOperational, "b-1", "user-1", "test")
			tt.modify(si)
			err := si.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSpendIntentLifecycle(t *testing.T) {
	si := NewSpendIntent("si-1", "t-1", "test", 1000, "USD", SpendOperational, "b-1", "user-1", "test")
	if si.Status != SpendStatusDraft {
		t.Fatalf("expected DRAFT, got %s", si.Status)
	}

	// DRAFT → PENDING
	if err := si.Submit(); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if si.Status != SpendStatusPending {
		t.Fatalf("expected PENDING, got %s", si.Status)
	}

	// PENDING → APPROVED
	if err := si.Approve(); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if si.Status != SpendStatusApproved {
		t.Fatalf("expected APPROVED, got %s", si.Status)
	}

	// Cannot re-approve
	if err := si.Approve(); err == nil {
		t.Fatal("expected error re-approving")
	}
}

func TestSpendIntentReject(t *testing.T) {
	si := NewSpendIntent("si-1", "t-1", "test", 1000, "USD", SpendOperational, "b-1", "user-1", "test")
	_ = si.Submit()
	if err := si.Reject(); err != nil {
		t.Fatalf("Reject: %v", err)
	}
	if si.Status != SpendStatusRejected {
		t.Fatalf("expected REJECTED, got %s", si.Status)
	}
}

func TestSpendIntentJSONRoundTrip(t *testing.T) {
	si := NewSpendIntent("si-1", "t-1", "test", 1000, "USD", SpendAICompute, "b-1", "user-1", "test")
	data, err := json.Marshal(si)
	if err != nil {
		t.Fatal(err)
	}
	var decoded SpendIntent
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.ID != si.ID || decoded.AmountCents != si.AmountCents || decoded.Category != si.Category {
		t.Error("round-trip mismatch")
	}
}

// ── Treasury ───────────────────────────────────────────────────────

func TestTreasuryCreditDebit(t *testing.T) {
	ta := NewTreasuryAccount("ta-1", "t-1", "Operating", AccountOperating, "USD", TreasuryLimit{
		DailyMaxCents:   100000,
		MonthlyMaxCents: 1000000,
	})

	// Credit
	receipt, err := ta.Credit("r-1", 50000, "initial funding")
	if err != nil {
		t.Fatalf("Credit: %v", err)
	}
	if ta.BalanceCents != 50000 {
		t.Fatalf("expected 50000, got %d", ta.BalanceCents)
	}
	if receipt.Operation != "credit" {
		t.Fatalf("expected credit receipt, got %s", receipt.Operation)
	}

	// Debit
	receipt, err = ta.Debit("r-2", 20000, "expense")
	if err != nil {
		t.Fatalf("Debit: %v", err)
	}
	if ta.BalanceCents != 30000 {
		t.Fatalf("expected 30000, got %d", ta.BalanceCents)
	}
	if receipt.BalanceAfter != 30000 {
		t.Fatalf("receipt balance should be 30000, got %d", receipt.BalanceAfter)
	}

	// Overdraft fails closed
	_, err = ta.Debit("r-3", 50000, "too much")
	if err == nil {
		t.Fatal("expected overdraft error")
	}
}

func TestTreasuryHoldRelease(t *testing.T) {
	ta := NewTreasuryAccount("ta-1", "t-1", "Ops", AccountOperating, "USD", TreasuryLimit{})
	ta.Credit("r-1", 10000, "fund")

	// Hold reduces available
	_, err := ta.Hold("h-1", 6000, "pending vendor", time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatalf("Hold: %v", err)
	}
	if ta.AvailableBalance() != 4000 {
		t.Fatalf("expected available=4000, got %d", ta.AvailableBalance())
	}

	// Cannot hold more than available
	_, err = ta.Hold("h-2", 5000, "too much", time.Now().Add(24*time.Hour))
	if err == nil {
		t.Fatal("expected insufficient hold error")
	}

	// Release restores available
	_, err = ta.ReleaseHold("h-1")
	if err != nil {
		t.Fatalf("Release: %v", err)
	}
	if ta.AvailableBalance() != 10000 {
		t.Fatalf("expected available=10000, got %d", ta.AvailableBalance())
	}
}

func TestTreasuryValidation(t *testing.T) {
	ta := NewTreasuryAccount("", "t-1", "Ops", AccountOperating, "USD", TreasuryLimit{})
	if err := ta.Validate(); err == nil {
		t.Fatal("expected validation error for empty ID")
	}
}

// ── Vendor ─────────────────────────────────────────────────────────

func TestVendorSpendCap(t *testing.T) {
	v := NewVendor("v-1", "t-1", "Acme", "cloud", VendorRiskLow, "USD", 50000, ContractTerms{
		StartDate: time.Now().Add(-24 * time.Hour),
	})

	if !v.WithinSpendCap(40000) {
		t.Fatal("should be within cap")
	}
	if v.WithinSpendCap(60000) {
		t.Fatal("should exceed cap")
	}

	if err := v.RecordSpend(40000); err != nil {
		t.Fatalf("RecordSpend: %v", err)
	}
	if err := v.RecordSpend(20000); err == nil {
		t.Fatal("expected spend cap exceeded error")
	}
}

func TestVendorContractActive(t *testing.T) {
	v := NewVendor("v-1", "t-1", "Acme", "cloud", VendorRiskMedium, "USD", 0, ContractTerms{
		StartDate: time.Now().Add(-30 * 24 * time.Hour),
		EndDate:   time.Now().Add(30 * 24 * time.Hour),
	})
	if !v.ContractActive(time.Now()) {
		t.Fatal("contract should be active")
	}
	if v.ContractActive(time.Now().Add(60 * 24 * time.Hour)) {
		t.Fatal("contract should be expired")
	}
}

// ── TransactionManifest ────────────────────────────────────────────

func TestTransactionManifestLineItemTotal(t *testing.T) {
	items := []LineItem{
		{Description: "compute", AmountCents: 5000, Category: "AI_COMPUTE"},
		{Description: "storage", AmountCents: 3000, Category: "INFRASTRUCTURE"},
	}
	tm := NewTransactionManifest("tx-1", "t-1", "si-1", "ta-1", "USD", items)
	if tm.TotalAmountCents != 8000 {
		t.Fatalf("expected 8000, got %d", tm.TotalAmountCents)
	}
	if tm.LineItemTotal() != 8000 {
		t.Fatalf("LineItemTotal: expected 8000, got %d", tm.LineItemTotal())
	}
}

func TestTransactionManifestLifecycle(t *testing.T) {
	items := []LineItem{{Description: "test", AmountCents: 1000, Category: "OPERATIONAL"}}
	tm := NewTransactionManifest("tx-1", "t-1", "si-1", "ta-1", "USD", items)

	// Cannot execute from PENDING
	if err := tm.Execute(); err == nil {
		t.Fatal("expected error executing from PENDING")
	}

	tm.Status = TxStatusApproved
	if err := tm.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if err := tm.Complete("receipt-hash-123"); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if tm.Status != TxStatusCompleted {
		t.Fatalf("expected COMPLETED, got %s", tm.Status)
	}
}

func TestTransactionManifestValidation(t *testing.T) {
	items := []LineItem{
		{Description: "a", AmountCents: 3000},
		{Description: "b", AmountCents: 2000},
	}
	tm := NewTransactionManifest("tx-1", "t-1", "si-1", "ta-1", "USD", items)
	if err := tm.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Tamper with total
	tm.TotalAmountCents = 9999
	if err := tm.Validate(); err == nil {
		t.Fatal("expected validation error for mismatched total")
	}
}

// ── Reconciliation ─────────────────────────────────────────────────

func TestReconciliationBalanced(t *testing.T) {
	r := NewReconciliationRecord("rec-1", "t-1", "ta-1", time.Now().Add(-24*time.Hour), time.Now(), 10000, 10000)
	if !r.IsBalanced() {
		t.Fatal("expected balanced")
	}
	if r.Status != ReconStatusMatched {
		t.Fatalf("expected MATCHED, got %s", r.Status)
	}
}

func TestReconciliationDiscrepant(t *testing.T) {
	r := NewReconciliationRecord("rec-1", "t-1", "ta-1", time.Now().Add(-24*time.Hour), time.Now(), 10000, 12000)
	if r.IsBalanced() {
		t.Fatal("expected imbalanced")
	}
	if r.Status != ReconStatusDiscrepant {
		t.Fatalf("expected DISCREPANT, got %s", r.Status)
	}
	if len(r.Discrepancies) != 1 {
		t.Fatalf("expected 1 discrepancy, got %d", len(r.Discrepancies))
	}
}

func TestReconciliationResolve(t *testing.T) {
	r := NewReconciliationRecord("rec-1", "t-1", "ta-1", time.Now().Add(-24*time.Hour), time.Now(), 10000, 12000)
	if err := r.Resolve("admin-1"); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if r.Status != ReconStatusResolved {
		t.Fatalf("expected RESOLVED, got %s", r.Status)
	}
}

// ── Labor ──────────────────────────────────────────────────────────

func TestLaborRecordDeterministicHash(t *testing.T) {
	a := NewLaborRecord("l-1", "t-1", ActorAgent, "agent-1", "task-1", "prompting", 5*time.Second, 50, "USD")
	b := NewLaborRecord("l-1", "t-1", ActorAgent, "agent-1", "task-1", "prompting", 5*time.Second, 50, "USD")
	if a.ContentHash != b.ContentHash {
		t.Errorf("determinism: %s vs %s", a.ContentHash, b.ContentHash)
	}
}

func TestCostAttribution(t *testing.T) {
	records := []*LaborRecord{
		NewLaborRecord("l-1", "t-1", ActorHuman, "h-1", "task-1", "review", time.Hour, 5000, "USD"),
		NewLaborRecord("l-2", "t-1", ActorAgent, "a-1", "task-1", "generate", 10*time.Second, 200, "USD"),
		NewLaborRecord("l-3", "t-1", ActorService, "s-1", "task-1", "compute", 30*time.Second, 100, "USD"),
	}
	ca := NewCostAttribution("t-1", "USD", time.Now().Add(-24*time.Hour), time.Now(), records)
	if ca.TotalCents != 5300 {
		t.Fatalf("expected total=5300, got %d", ca.TotalCents)
	}
	if ca.HumanCents != 5000 {
		t.Fatalf("expected human=5000, got %d", ca.HumanCents)
	}
	if ca.HumanRatio() < 0.94 {
		t.Fatalf("expected human ratio ~0.94, got %f", ca.HumanRatio())
	}
}

// ── OrgBudget ──────────────────────────────────────────────────────

func TestOrgBudgetSpend(t *testing.T) {
	ob := NewOrgBudget("ob-1", "t-1", "Q1 Engineering", BudgetScopeDepartment, "dept-eng", "USD", 100000,
		time.Now().Add(-30*24*time.Hour), time.Now().Add(60*24*time.Hour))

	if !ob.CanSpend(50000) {
		t.Fatal("should be able to spend 50000")
	}
	if err := ob.RecordSpend(60000); err != nil {
		t.Fatalf("RecordSpend: %v", err)
	}
	if ob.RemainingCents() != 40000 {
		t.Fatalf("expected remaining=40000, got %d", ob.RemainingCents())
	}
	// Cannot overspend
	if err := ob.RecordSpend(50000); err == nil {
		t.Fatal("expected overspend error")
	}
}

func TestOrgBudgetApprovalThreshold(t *testing.T) {
	ob := NewOrgBudget("ob-1", "t-1", "Team Budget", BudgetScopeTeam, "team-1", "USD", 100000,
		time.Now(), time.Now().Add(30*24*time.Hour))
	ob.ApprovalThresholds = []ApprovalThreshold{
		{AmountCents: 1000, ApproverRole: "team_lead"},
		{AmountCents: 10000, ApproverRole: "director"},
		{AmountCents: 50000, ApproverRole: "vp"},
	}
	if ob.RequiredApprover(500) != "" {
		t.Fatal("should not require approval for 500")
	}
	if ob.RequiredApprover(5000) != "team_lead" {
		t.Fatalf("expected team_lead, got %s", ob.RequiredApprover(5000))
	}
	if ob.RequiredApprover(30000) != "director" {
		t.Fatalf("expected director, got %s", ob.RequiredApprover(30000))
	}
	if ob.RequiredApprover(70000) != "vp" {
		t.Fatalf("expected vp, got %s", ob.RequiredApprover(70000))
	}
}

// ── Procurement ────────────────────────────────────────────────────

func TestProcurementLifecycle(t *testing.T) {
	pr := NewProcurementRequest("pr-1", "t-1", "si-1", "v-1", "Cloud hosting", "user-1", "USD", ProcTypeSubscription, 20000)
	if pr.Status != ProcStatusDraft {
		t.Fatalf("expected DRAFT, got %s", pr.Status)
	}
	if err := pr.Submit(); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if err := pr.Approve("manager-1"); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	pr.BindManifest("tx-1")
	if pr.Status != ProcStatusInProgress {
		t.Fatalf("expected IN_PROGRESS, got %s", pr.Status)
	}
}
