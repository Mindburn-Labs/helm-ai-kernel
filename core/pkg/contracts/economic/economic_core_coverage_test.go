package economic

import (
	"strings"
	"testing"
	"time"
)

func TestRecurringAuthorityAndLedgerCoverage(t *testing.T) {
	authority := RecurringAuthority{AuthorityID: "auth-1", GrantedTo: "agent-1", MaxAmountCents: 1000, UsedThisPeriod: 400, Active: true}
	if authority.Remaining() != 600 {
		t.Fatalf("Remaining = %d, want 600", authority.Remaining())
	}
	if !authority.CanSpend(600) || authority.CanSpend(601) {
		t.Fatal("CanSpend did not enforce remaining amount")
	}
	authority.UsedThisPeriod = 1200
	if authority.Remaining() != 0 || authority.CanSpend(1) {
		t.Fatal("overspent authority should have zero remaining and deny spend")
	}
	authority.UsedThisPeriod = 0
	authority.Active = false
	if authority.CanSpend(1) {
		t.Fatal("inactive authority should deny spend")
	}

	ledger := NewLedger()
	if err := ledger.RegisterAuthority(RecurringAuthority{}); err == nil {
		t.Fatal("RegisterAuthority accepted missing authority_id")
	}
	authority.Active = true
	authority.UsedThisPeriod = 100
	if err := ledger.RegisterAuthority(authority); err != nil {
		t.Fatalf("RegisterAuthority: %v", err)
	}
	gotAuthority, err := ledger.GetAuthority("auth-1")
	if err != nil || gotAuthority.AuthorityID != "auth-1" {
		t.Fatalf("GetAuthority = (%#v, %v), want auth-1", gotAuthority, err)
	}
	if _, err := ledger.GetAuthority("missing"); err == nil {
		t.Fatal("GetAuthority missing error = nil")
	}
	if len(ledger.ListAuthorities()) != 1 {
		t.Fatalf("ListAuthorities length = %d, want 1", len(ledger.ListAuthorities()))
	}
	if err := ledger.Spend("missing", 1); err == nil {
		t.Fatal("Spend missing authority error = nil")
	}
	if err := ledger.Spend("auth-1", 1000); err == nil {
		t.Fatal("Spend over remaining error = nil")
	}
	if err := ledger.Spend("auth-1", 500); err != nil {
		t.Fatalf("Spend valid: %v", err)
	}
	gotAuthority, _ = ledger.GetAuthority("auth-1")
	if gotAuthority.UsedThisPeriod != 600 {
		t.Fatalf("Spend used_this_period = %d, want 600", gotAuthority.UsedThisPeriod)
	}

	if err := ledger.RegisterAllocation(CapitalAllocation{}); err == nil {
		t.Fatal("RegisterAllocation accepted missing allocation_id")
	}
	if err := ledger.RegisterAllocation(CapitalAllocation{AllocationID: "alloc-1", TotalCents: 1000}); err != nil {
		t.Fatalf("RegisterAllocation: %v", err)
	}
	if len(ledger.ListAllocations()) != 1 {
		t.Fatalf("ListAllocations length = %d, want 1", len(ledger.ListAllocations()))
	}
	if err := ledger.RecordCharge(ServiceChargeRecord{}); err == nil {
		t.Fatal("RecordCharge accepted missing charge_id")
	}
	if err := ledger.RecordCharge(ServiceChargeRecord{ChargeID: "charge-1", AmountCents: 250}); err != nil {
		t.Fatalf("RecordCharge: %v", err)
	}
	charges := ledger.ListCharges()
	if len(charges) != 1 || charges[0].ChargeID != "charge-1" || charges[0].CreatedAt.IsZero() {
		t.Fatalf("ListCharges = %#v, want timestamped charge-1", charges)
	}
	charges[0].ChargeID = "mutated"
	if ledger.ListCharges()[0].ChargeID != "charge-1" {
		t.Fatal("ListCharges returned mutable backing storage")
	}
}

func TestLaborValidationRatiosAndAttributionCoverage(t *testing.T) {
	zero := NewCostAttribution("tenant-1", "USD", time.Now(), time.Now(), nil)
	if zero.HumanRatio() != 0 || zero.AgentRatio() != 0 {
		t.Fatalf("zero ratios = human %f agent %f, want 0", zero.HumanRatio(), zero.AgentRatio())
	}
	records := []*LaborRecord{
		NewLaborRecord("human", "tenant-1", ActorHuman, "human-1", "task-1", "review", time.Second, 100, "USD"),
		NewLaborRecord("agent", "tenant-1", ActorAgent, "agent-1", "task-1", "draft", time.Second, 300, "USD"),
		NewLaborRecord("service", "tenant-1", ActorService, "svc-1", "task-1", "compute", time.Second, 50, "USD"),
		NewLaborRecord("robot", "tenant-1", ActorRobot, "robot-1", "task-1", "move", time.Second, 50, "USD"),
	}
	attribution := NewCostAttribution("tenant-1", "USD", time.Now(), time.Now(), records)
	if attribution.RobotCents != 50 || attribution.AgentRatio() != 0.6 {
		t.Fatalf("attribution robot=%d agent_ratio=%f, want 50 and 0.6", attribution.RobotCents, attribution.AgentRatio())
	}

	cases := []struct {
		name    string
		mutate  func(*LaborRecord)
		wantErr string
	}{
		{"valid", func(*LaborRecord) {}, ""},
		{"missing id", func(l *LaborRecord) { l.ID = "" }, "id is required"},
		{"missing tenant", func(l *LaborRecord) { l.TenantID = "" }, "tenant_id is required"},
		{"missing actor", func(l *LaborRecord) { l.ActorID = "" }, "actor_id is required"},
		{"missing task", func(l *LaborRecord) { l.TaskID = "" }, "task_id is required"},
		{"negative cost", func(l *LaborRecord) { l.CostCents = -1 }, "cost_cents cannot be negative"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			record := NewLaborRecord("labor-1", "tenant-1", ActorAgent, "agent-1", "task-1", "work", time.Second, 1, "USD")
			tc.mutate(record)
			err := record.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			requireEconomicErrorContains(t, err, tc.wantErr)
		})
	}
}

func TestOrgBudgetValidationAndUtilizationCoverage(t *testing.T) {
	start := time.Now().Add(-time.Hour)
	end := time.Now().Add(time.Hour)
	budget := NewOrgBudget("budget-1", "tenant-1", "Ops", BudgetScopeOrg, "org", "USD", 1000, start, end)
	budget.SpentCents = 250
	if budget.UtilizationPct() != 0.25 {
		t.Fatalf("UtilizationPct = %f, want 0.25", budget.UtilizationPct())
	}
	budget.ReservedCents = 900
	if budget.RemainingCents() != 0 {
		t.Fatalf("RemainingCents overspent = %d, want 0", budget.RemainingCents())
	}
	var zeroBudget OrgBudget
	if zeroBudget.UtilizationPct() != 0 {
		t.Fatal("zero allocation UtilizationPct should be 0")
	}

	cases := []struct {
		name    string
		mutate  func(*OrgBudget)
		wantErr string
	}{
		{"valid", func(*OrgBudget) {}, ""},
		{"missing id", func(b *OrgBudget) { b.ID = "" }, "id is required"},
		{"missing tenant", func(b *OrgBudget) { b.TenantID = "" }, "tenant_id is required"},
		{"nonpositive allocation", func(b *OrgBudget) { b.AllocatedCents = 0 }, "allocated_cents must be positive"},
		{"missing currency", func(b *OrgBudget) { b.Currency = "" }, "currency is required"},
		{"reversed period", func(b *OrgBudget) { b.PeriodEnd = b.PeriodStart.Add(-time.Second) }, "period_end must be after period_start"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := NewOrgBudget("budget-1", "tenant-1", "Ops", BudgetScopeOrg, "org", "USD", 1000, start, end)
			tc.mutate(b)
			err := b.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			requireEconomicErrorContains(t, err, tc.wantErr)
		})
	}
}

func TestProcurementValidationAndInvalidTransitionsCoverage(t *testing.T) {
	request := NewProcurementRequest("proc-1", "tenant-1", "spend-1", "vendor-1", "Cloud", "user-1", "USD", ProcTypeService, 1000)
	if err := request.Approve("manager-1"); err == nil {
		t.Fatal("Approve from DRAFT error = nil")
	}
	if err := request.Submit(); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if err := request.Submit(); err == nil {
		t.Fatal("Submit from SUBMITTED error = nil")
	}

	cases := []struct {
		name    string
		mutate  func(*ProcurementRequest)
		wantErr string
	}{
		{"valid", func(*ProcurementRequest) {}, ""},
		{"missing id", func(p *ProcurementRequest) { p.ID = "" }, "id is required"},
		{"missing tenant", func(p *ProcurementRequest) { p.TenantID = "" }, "tenant_id is required"},
		{"missing vendor", func(p *ProcurementRequest) { p.VendorID = "" }, "vendor_id is required"},
		{"nonpositive amount", func(p *ProcurementRequest) { p.AmountCents = 0 }, "amount_cents must be positive"},
		{"missing type", func(p *ProcurementRequest) { p.Type = "" }, "type is required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := NewProcurementRequest("proc-1", "tenant-1", "spend-1", "vendor-1", "Cloud", "user-1", "USD", ProcTypeService, 1000)
			tc.mutate(p)
			err := p.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			requireEconomicErrorContains(t, err, tc.wantErr)
		})
	}
}

func TestReconciliationDiscrepancyValidationAndResolveFailuresCoverage(t *testing.T) {
	start := time.Now().Add(-time.Hour)
	end := time.Now()
	matched := NewReconciliationRecord("rec-1", "tenant-1", "treasury-1", start, end, 100, 100)
	if err := matched.Resolve("admin-1"); err == nil {
		t.Fatal("Resolve matched record error = nil")
	}
	record := NewReconciliationRecord("rec-2", "tenant-1", "treasury-1", start, end, 100, 120)
	record.AddDiscrepancy(Discrepancy{TransactionID: "tx-1", ExpectedCents: 1, ActualCents: 2, DeltaCents: 1, Reason: "line item"})
	if record.Status != ReconStatusDiscrepant || len(record.Discrepancies) != 2 {
		t.Fatalf("AddDiscrepancy status=%s count=%d, want DISCREPANT and 2", record.Status, len(record.Discrepancies))
	}
	escalated := NewReconciliationRecord("rec-3", "tenant-1", "treasury-1", start, end, 100, 120)
	escalated.Status = ReconStatusEscalated
	if err := escalated.Resolve("admin-1"); err != nil {
		t.Fatalf("Resolve escalated: %v", err)
	}

	cases := []struct {
		name    string
		mutate  func(*ReconciliationRecord)
		wantErr string
	}{
		{"valid", func(*ReconciliationRecord) {}, ""},
		{"missing id", func(r *ReconciliationRecord) { r.ID = "" }, "id is required"},
		{"missing tenant", func(r *ReconciliationRecord) { r.TenantID = "" }, "tenant_id is required"},
		{"missing treasury", func(r *ReconciliationRecord) { r.TreasuryID = "" }, "treasury_id is required"},
		{"reversed period", func(r *ReconciliationRecord) { r.PeriodEnd = r.PeriodStart.Add(-time.Second) }, "period_end must be after period_start"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := NewReconciliationRecord("rec-1", "tenant-1", "treasury-1", start, end, 100, 100)
			tc.mutate(r)
			err := r.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			requireEconomicErrorContains(t, err, tc.wantErr)
		})
	}
}

func TestTransactionManifestApprovalCompletionAndValidationFailuresCoverage(t *testing.T) {
	manifest := economicTestManifest()
	manifest.AddApproval("approver-1", "budget", "sig")
	if len(manifest.ApprovalChain) != 1 {
		t.Fatalf("approval count = %d, want 1", len(manifest.ApprovalChain))
	}
	if err := manifest.Complete("receipt"); err == nil {
		t.Fatal("Complete before EXECUTING error = nil")
	}

	cases := []struct {
		name    string
		mutate  func(*TransactionManifest)
		wantErr string
	}{
		{"valid", func(*TransactionManifest) {}, ""},
		{"missing id", func(m *TransactionManifest) { m.ID = "" }, "id is required"},
		{"missing tenant", func(m *TransactionManifest) { m.TenantID = "" }, "tenant_id is required"},
		{"missing spend intent", func(m *TransactionManifest) { m.SpendIntentID = "" }, "spend_intent_id is required"},
		{"missing treasury", func(m *TransactionManifest) { m.TreasuryAccountID = "" }, "treasury_account_id is required"},
		{"nonpositive total", func(m *TransactionManifest) { m.TotalAmountCents = 0 }, "total_amount_cents must be positive"},
		{"no line items", func(m *TransactionManifest) { m.LineItems = nil }, "at least one line item required"},
		{"sum mismatch", func(m *TransactionManifest) { m.TotalAmountCents++ }, "line item sum does not match total"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := economicTestManifest()
			tc.mutate(m)
			err := m.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			requireEconomicErrorContains(t, err, tc.wantErr)
		})
	}
}

func TestTreasuryAndVendorAdditionalBranches(t *testing.T) {
	account := NewTreasuryAccount("treasury-1", "tenant-1", "Ops", AccountOperating, "USD", TreasuryLimit{})
	account.BalanceCents = 100
	account.HeldCents = 200
	if account.AvailableBalance() != 0 {
		t.Fatalf("negative available balance = %d, want 0", account.AvailableBalance())
	}
	if _, err := account.Credit("credit-0", 0, "bad"); err == nil {
		t.Fatal("Credit zero error = nil")
	}
	if _, err := account.Debit("debit-0", 0, "bad"); err == nil {
		t.Fatal("Debit zero error = nil")
	}
	if _, err := account.Hold("hold-0", 0, "bad", time.Now()); err == nil {
		t.Fatal("Hold zero error = nil")
	}
	if _, err := account.ReleaseHold("missing"); err == nil {
		t.Fatal("ReleaseHold missing error = nil")
	}

	treasuryCases := []struct {
		name    string
		mutate  func(*TreasuryAccount)
		wantErr string
	}{
		{"valid", func(*TreasuryAccount) {}, ""},
		{"missing id", func(a *TreasuryAccount) { a.ID = "" }, "id is required"},
		{"missing tenant", func(a *TreasuryAccount) { a.TenantID = "" }, "tenant_id is required"},
		{"missing currency", func(a *TreasuryAccount) { a.Currency = "" }, "currency is required"},
		{"negative balance", func(a *TreasuryAccount) { a.BalanceCents = -1 }, "balance cannot be negative"},
	}
	for _, tc := range treasuryCases {
		t.Run("treasury "+tc.name, func(t *testing.T) {
			a := NewTreasuryAccount("treasury-1", "tenant-1", "Ops", AccountOperating, "USD", TreasuryLimit{})
			tc.mutate(a)
			err := a.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			requireEconomicErrorContains(t, err, tc.wantErr)
		})
	}

	now := time.Now()
	vendor := NewVendor("vendor-1", "tenant-1", "Acme", "cloud", VendorRiskLow, "USD", 0, ContractTerms{StartDate: now.Add(-time.Hour)})
	if !vendor.WithinSpendCap(1_000_000) {
		t.Fatal("uncapped vendor should allow additional spend")
	}
	vendor.Suspend()
	if vendor.Status != VendorStatusSuspended {
		t.Fatalf("Suspend status = %s, want SUSPENDED", vendor.Status)
	}
	futureVendor := NewVendor("vendor-2", "tenant-1", "Future", "cloud", VendorRiskLow, "USD", 1000, ContractTerms{StartDate: now.Add(time.Hour)})
	if futureVendor.ContractActive(now) {
		t.Fatal("future contract should not be active")
	}
	openEnded := NewVendor("vendor-3", "tenant-1", "Open", "cloud", VendorRiskLow, "USD", 1000, ContractTerms{StartDate: now.Add(-time.Hour)})
	if !openEnded.ContractActive(now) {
		t.Fatal("open-ended active contract should be active")
	}

	vendorCases := []struct {
		name    string
		mutate  func(*Vendor)
		wantErr string
	}{
		{"valid", func(*Vendor) {}, ""},
		{"missing id", func(v *Vendor) { v.ID = "" }, "id is required"},
		{"missing tenant", func(v *Vendor) { v.TenantID = "" }, "tenant_id is required"},
		{"missing name", func(v *Vendor) { v.Name = "" }, "name is required"},
		{"missing currency", func(v *Vendor) { v.Currency = "" }, "currency is required"},
		{"missing risk", func(v *Vendor) { v.RiskTier = "" }, "risk_tier is required"},
	}
	for _, tc := range vendorCases {
		t.Run("vendor "+tc.name, func(t *testing.T) {
			v := NewVendor("vendor-1", "tenant-1", "Acme", "cloud", VendorRiskLow, "USD", 1000, ContractTerms{StartDate: now})
			tc.mutate(v)
			err := v.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			requireEconomicErrorContains(t, err, tc.wantErr)
		})
	}
}

func TestSpendIntentInvalidSubmitRejectCoverage(t *testing.T) {
	intent := NewSpendIntent("spend-1", "tenant-1", "compute", 1000, "USD", SpendAICompute, "budget-1", "user-1", "test")
	if err := intent.Reject(); err == nil {
		t.Fatal("Reject from DRAFT error = nil")
	}
	if err := intent.Submit(); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if err := intent.Submit(); err == nil {
		t.Fatal("Submit from PENDING error = nil")
	}
}

func economicTestManifest() *TransactionManifest {
	return NewTransactionManifest("tx-1", "tenant-1", "spend-1", "treasury-1", "USD", []LineItem{
		{Description: "compute", AmountCents: 1000, Category: "AI_COMPUTE"},
		{Description: "storage", AmountCents: 500, Category: "INFRASTRUCTURE"},
	})
}

func requireEconomicErrorContains(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("error = nil, want substring %q", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %v, want substring %q", err, want)
	}
}
