package economic

import (
	"errors"
	"time"
)

// ProviderAccountMode describes how HELM is allowed to route through a provider.
type ProviderAccountMode string

const (
	ProviderAccountBYOK              ProviderAccountMode = "BYOK"
	ProviderAccountDirect            ProviderAccountMode = "DIRECT"
	ProviderAccountManagedOrgAccount ProviderAccountMode = "MANAGED_ORG_ACCOUNT"
)

// ProviderTermsProfile captures the legal and commercial boundary for a provider.
type ProviderTermsProfile struct {
	ID                                 string              `json:"id"`
	TenantID                           string              `json:"tenant_id,omitempty"`
	ProviderID                         string              `json:"provider_id"`
	AccountMode                        ProviderAccountMode `json:"account_mode"`
	TermsVersion                       string              `json:"terms_version"`
	ContractRef                        string              `json:"contract_ref,omitempty"`
	LegalReviewRef                     string              `json:"legal_review_ref"`
	Jurisdiction                       string              `json:"jurisdiction,omitempty"`
	DataRetentionDays                  int                 `json:"data_retention_days,omitempty"`
	AllowsUsageResale                  bool                `json:"allows_usage_resale"`
	AllowsProviderCreditTransfer       bool                `json:"allows_provider_credit_transfer"`
	AllowsProviderCreditCashRedemption bool                `json:"allows_provider_credit_cash_redemption"`
	RequiresContractForManagedBilling  bool                `json:"requires_contract_for_managed_billing"`
	EffectiveAt                        time.Time           `json:"effective_at"`
	ExpiresAt                          *time.Time          `json:"expires_at,omitempty"`
	ContentHash                        string              `json:"content_hash"`
}

// NewProviderTermsProfile creates a provider terms profile with safe defaults.
func NewProviderTermsProfile(id, providerID string, mode ProviderAccountMode, termsVersion, legalReviewRef string) *ProviderTermsProfile {
	p := &ProviderTermsProfile{
		ID:                                id,
		ProviderID:                        providerID,
		AccountMode:                       mode,
		TermsVersion:                      termsVersion,
		LegalReviewRef:                    legalReviewRef,
		RequiresContractForManagedBilling: mode == ProviderAccountManagedOrgAccount,
		EffectiveAt:                       time.Now().UTC(),
	}
	p.ContentHash = p.computeHash()
	return p
}

// Validate rejects unsafe provider-credit or resale claims unless legal changes the contract.
func (p *ProviderTermsProfile) Validate() error {
	if p == nil {
		return errors.New("provider_terms_profile: profile is nil")
	}
	if p.ID == "" {
		return errors.New("provider_terms_profile: id is required")
	}
	if p.ProviderID == "" {
		return errors.New("provider_terms_profile: provider_id is required")
	}
	if p.AccountMode == "" {
		return errors.New("provider_terms_profile: account_mode is required")
	}
	if p.TermsVersion == "" {
		return errors.New("provider_terms_profile: terms_version is required")
	}
	if p.LegalReviewRef == "" {
		return errors.New("provider_terms_profile: legal_review_ref is required")
	}
	if p.DataRetentionDays < 0 {
		return errors.New("provider_terms_profile: data_retention_days cannot be negative")
	}
	if p.AllowsUsageResale {
		return errors.New("provider_terms_profile: usage resale is forbidden without explicit legal override")
	}
	if p.AllowsProviderCreditTransfer {
		return errors.New("provider_terms_profile: provider credit transfer is forbidden without explicit legal override")
	}
	if p.AllowsProviderCreditCashRedemption {
		return errors.New("provider_terms_profile: provider credit cash redemption is forbidden without explicit legal override")
	}
	if p.RequiresContractForManagedBilling && p.ContractRef == "" {
		return errors.New("provider_terms_profile: contract_ref is required for managed billing")
	}
	if p.ExpiresAt != nil && p.ExpiresAt.Before(p.EffectiveAt) {
		return errors.New("provider_terms_profile: expires_at must be after effective_at")
	}
	return nil
}

func (p *ProviderTermsProfile) computeHash() string {
	return hashSpendAuthorityCanonical(struct {
		ID                                 string              `json:"id"`
		TenantID                           string              `json:"tenant_id,omitempty"`
		ProviderID                         string              `json:"provider_id"`
		AccountMode                        ProviderAccountMode `json:"account_mode"`
		TermsVersion                       string              `json:"terms_version"`
		ContractRef                        string              `json:"contract_ref,omitempty"`
		LegalReviewRef                     string              `json:"legal_review_ref"`
		Jurisdiction                       string              `json:"jurisdiction,omitempty"`
		DataRetentionDays                  int                 `json:"data_retention_days,omitempty"`
		AllowsUsageResale                  bool                `json:"allows_usage_resale"`
		AllowsProviderCreditTransfer       bool                `json:"allows_provider_credit_transfer"`
		AllowsProviderCreditCashRedemption bool                `json:"allows_provider_credit_cash_redemption"`
		RequiresContractForManagedBilling  bool                `json:"requires_contract_for_managed_billing"`
	}{p.ID, p.TenantID, p.ProviderID, p.AccountMode, p.TermsVersion, p.ContractRef, p.LegalReviewRef, p.Jurisdiction, p.DataRetentionDays, p.AllowsUsageResale, p.AllowsProviderCreditTransfer, p.AllowsProviderCreditCashRedemption, p.RequiresContractForManagedBilling})
}

// ProviderPriceSnapshot captures quoted provider pricing at a point in time.
type ProviderPriceSnapshot struct {
	ID                     string    `json:"id"`
	ProviderID             string    `json:"provider_id"`
	ModelID                string    `json:"model_id"`
	Currency               string    `json:"currency"`
	InputTokenMicroCents   int64     `json:"input_token_micro_cents,omitempty"`
	OutputTokenMicroCents  int64     `json:"output_token_micro_cents,omitempty"`
	RequestCents           int64     `json:"request_cents,omitempty"`
	ProviderTermsProfileID string    `json:"provider_terms_profile_id"`
	SourceURI              string    `json:"source_uri,omitempty"`
	SourceHash             string    `json:"source_hash"`
	CapturedAt             time.Time `json:"captured_at"`
	EffectiveAt            time.Time `json:"effective_at"`
	ExpiresAt              time.Time `json:"expires_at"`
	ContentHash            string    `json:"content_hash"`
}

// NewProviderPriceSnapshot creates a price snapshot for a provider/model pair.
func NewProviderPriceSnapshot(id, providerID, modelID, currency, termsProfileID, sourceHash string, effectiveAt, expiresAt time.Time) *ProviderPriceSnapshot {
	s := &ProviderPriceSnapshot{
		ID:                     id,
		ProviderID:             providerID,
		ModelID:                modelID,
		Currency:               currency,
		ProviderTermsProfileID: termsProfileID,
		SourceHash:             sourceHash,
		CapturedAt:             time.Now().UTC(),
		EffectiveAt:            effectiveAt,
		ExpiresAt:              expiresAt,
	}
	s.ContentHash = s.computeHash()
	return s
}

// Validate ensures a quote cannot use stale or source-less pricing.
func (s *ProviderPriceSnapshot) Validate() error {
	if s == nil {
		return errors.New("provider_price_snapshot: snapshot is nil")
	}
	if s.ID == "" {
		return errors.New("provider_price_snapshot: id is required")
	}
	if s.ProviderID == "" {
		return errors.New("provider_price_snapshot: provider_id is required")
	}
	if s.ModelID == "" {
		return errors.New("provider_price_snapshot: model_id is required")
	}
	if s.Currency == "" {
		return errors.New("provider_price_snapshot: currency is required")
	}
	if s.ProviderTermsProfileID == "" {
		return errors.New("provider_price_snapshot: provider_terms_profile_id is required")
	}
	if s.SourceHash == "" {
		return errors.New("provider_price_snapshot: source_hash is required")
	}
	if s.InputTokenMicroCents < 0 || s.OutputTokenMicroCents < 0 || s.RequestCents < 0 {
		return errors.New("provider_price_snapshot: price fields cannot be negative")
	}
	if s.InputTokenMicroCents == 0 && s.OutputTokenMicroCents == 0 && s.RequestCents == 0 {
		return errors.New("provider_price_snapshot: at least one price field is required")
	}
	if !s.ExpiresAt.After(s.EffectiveAt) {
		return errors.New("provider_price_snapshot: expires_at must be after effective_at")
	}
	return nil
}

func (s *ProviderPriceSnapshot) Stale(now time.Time) bool {
	return s == nil || !now.Before(s.ExpiresAt)
}

// QuoteCents computes the quoted cost in whole cents for the given token usage.
//
// Token prices are expressed in micro-cents (1e-6 cents) per token so that
// sub-cent per-token rates remain exact integers. The running total is kept in
// micro-cents and rounded up to the next whole cent so a quote never
// under-charges the envelope. RequestCents is a flat per-request surcharge.
func (s *ProviderPriceSnapshot) QuoteCents(inputTokens, outputTokens int64) (int64, error) {
	if s == nil {
		return 0, errors.New("provider_price_snapshot: snapshot is nil")
	}
	if inputTokens < 0 || outputTokens < 0 {
		return 0, errors.New("provider_price_snapshot: token counts cannot be negative")
	}
	microCents := inputTokens*s.InputTokenMicroCents + outputTokens*s.OutputTokenMicroCents
	if microCents < 0 {
		return 0, errors.New("provider_price_snapshot: token cost overflow")
	}
	// Round up to the next whole cent (ceil division), then add the flat surcharge.
	cents := (microCents + 999_999) / 1_000_000
	total := cents + s.RequestCents
	if total <= 0 {
		return 0, errors.New("provider_price_snapshot: quoted cost must be positive")
	}
	return total, nil
}

func (s *ProviderPriceSnapshot) computeHash() string {
	return hashSpendAuthorityCanonical(struct {
		ID                    string `json:"id"`
		ProviderID            string `json:"provider_id"`
		ModelID               string `json:"model_id"`
		Currency              string `json:"currency"`
		InputTokenMicroCents  int64  `json:"input_token_micro_cents,omitempty"`
		OutputTokenMicroCents int64  `json:"output_token_micro_cents,omitempty"`
		RequestCents          int64  `json:"request_cents,omitempty"`
		TermsProfileID        string `json:"provider_terms_profile_id"`
		SourceHash            string `json:"source_hash"`
	}{s.ID, s.ProviderID, s.ModelID, s.Currency, s.InputTokenMicroCents, s.OutputTokenMicroCents, s.RequestCents, s.ProviderTermsProfileID, s.SourceHash})
}

// BalanceAccountType describes the ledger account backing spend authority.
type BalanceAccountType string

const (
	BalanceAccountUsageBalance   BalanceAccountType = "USAGE_BALANCE"
	BalanceAccountInternalLedger BalanceAccountType = "INTERNAL_LEDGER"
	BalanceAccountProviderPrepay BalanceAccountType = "PROVIDER_PREPAY"
	BalanceAccountInvoiceAccrual BalanceAccountType = "INVOICE_ACCRUAL"
)

// BalanceAccountStatus tracks whether debits are allowed.
type BalanceAccountStatus string

const (
	BalanceAccountActive BalanceAccountStatus = "ACTIVE"
	BalanceAccountFrozen BalanceAccountStatus = "FROZEN"
	BalanceAccountClosed BalanceAccountStatus = "CLOSED"
)

// BalanceAccount is the governed usage balance for a tenant/workspace.
type BalanceAccount struct {
	ID               string               `json:"id"`
	TenantID         string               `json:"tenant_id"`
	WorkspaceID      string               `json:"workspace_id,omitempty"`
	Type             BalanceAccountType   `json:"type"`
	Status           BalanceAccountStatus `json:"status"`
	Currency         string               `json:"currency"`
	BalanceCents     int64                `json:"balance_cents"`
	HoldCents        int64                `json:"hold_cents"`
	CreditLimitCents int64                `json:"credit_limit_cents,omitempty"`
	CreditLineID     string               `json:"credit_line_id,omitempty"`
	LegalEntityID    string               `json:"legal_entity_id,omitempty"`
	EvidencePackRef  string               `json:"evidence_pack_ref"`
	UpdatedAt        time.Time            `json:"updated_at"`
	ContentHash      string               `json:"content_hash"`
}

// NewBalanceAccount creates an active usage balance account.
func NewBalanceAccount(id, tenantID, currency string, balanceCents int64, evidencePackRef string) *BalanceAccount {
	a := &BalanceAccount{
		ID:              id,
		TenantID:        tenantID,
		Type:            BalanceAccountUsageBalance,
		Status:          BalanceAccountActive,
		Currency:        currency,
		BalanceCents:    balanceCents,
		EvidencePackRef: evidencePackRef,
		UpdatedAt:       time.Now().UTC(),
	}
	a.ContentHash = a.computeHash()
	return a
}

// AvailableCents returns funds available for new holds/debits.
func (a *BalanceAccount) AvailableCents() int64 {
	if a == nil || a.Status != BalanceAccountActive {
		return 0
	}
	available := a.BalanceCents - a.HoldCents
	if available < 0 {
		return 0
	}
	return available
}

// Validate ensures the balance account can support spend decisions.
func (a *BalanceAccount) Validate() error {
	if a == nil {
		return errors.New("balance_account: account is nil")
	}
	if a.ID == "" {
		return errors.New("balance_account: id is required")
	}
	if a.TenantID == "" {
		return errors.New("balance_account: tenant_id is required")
	}
	if a.Type == "" {
		return errors.New("balance_account: type is required")
	}
	if a.Status == "" {
		return errors.New("balance_account: status is required")
	}
	if a.Currency == "" {
		return errors.New("balance_account: currency is required")
	}
	if a.BalanceCents < 0 {
		return errors.New("balance_account: balance_cents cannot be negative")
	}
	if a.HoldCents < 0 {
		return errors.New("balance_account: hold_cents cannot be negative")
	}
	if a.HoldCents > a.BalanceCents {
		return errors.New("balance_account: hold_cents cannot exceed balance_cents")
	}
	if a.CreditLimitCents > 0 && a.CreditLineID == "" {
		return errors.New("balance_account: credit_line_id is required when credit_limit_cents is positive")
	}
	if a.EvidencePackRef == "" {
		return errors.New("balance_account: evidence_pack_ref is required")
	}
	return nil
}

func (a *BalanceAccount) computeHash() string {
	return hashSpendAuthorityCanonical(struct {
		ID               string               `json:"id"`
		TenantID         string               `json:"tenant_id"`
		WorkspaceID      string               `json:"workspace_id,omitempty"`
		Type             BalanceAccountType   `json:"type"`
		Status           BalanceAccountStatus `json:"status"`
		Currency         string               `json:"currency"`
		BalanceCents     int64                `json:"balance_cents"`
		HoldCents        int64                `json:"hold_cents"`
		CreditLimitCents int64                `json:"credit_limit_cents,omitempty"`
		CreditLineID     string               `json:"credit_line_id,omitempty"`
		EvidencePackRef  string               `json:"evidence_pack_ref"`
	}{a.ID, a.TenantID, a.WorkspaceID, a.Type, a.Status, a.Currency, a.BalanceCents, a.HoldCents, a.CreditLimitCents, a.CreditLineID, a.EvidencePackRef})
}

// UsageLedgerEntryType classifies a balance ledger mutation.
type UsageLedgerEntryType string

const (
	UsageLedgerReserve    UsageLedgerEntryType = "RESERVE"
	UsageLedgerRelease    UsageLedgerEntryType = "RELEASE"
	UsageLedgerDebit      UsageLedgerEntryType = "DEBIT"
	UsageLedgerCredit     UsageLedgerEntryType = "CREDIT"
	UsageLedgerAdjustment UsageLedgerEntryType = "ADJUSTMENT"
)

// UsageLedgerEntry records one balance-account mutation.
type UsageLedgerEntry struct {
	ID                  string               `json:"id"`
	TenantID            string               `json:"tenant_id"`
	BalanceAccountID    string               `json:"balance_account_id"`
	UsageReceiptID      string               `json:"usage_receipt_id,omitempty"`
	SettlementReceiptID string               `json:"settlement_receipt_id,omitempty"`
	Type                UsageLedgerEntryType `json:"type"`
	Direction           SettlementDirection  `json:"direction"`
	AmountCents         int64                `json:"amount_cents"`
	Currency            string               `json:"currency"`
	ReasonCode          SpendReasonCode      `json:"reason_code"`
	SourceContentHash   string               `json:"source_content_hash"`
	CreatedAt           time.Time            `json:"created_at"`
	ContentHash         string               `json:"content_hash"`
}

// NewUsageLedgerEntry creates a balance ledger entry with deterministic hash.
func NewUsageLedgerEntry(id, tenantID, balanceAccountID string, entryType UsageLedgerEntryType, direction SettlementDirection, amountCents int64, currency string, reasonCode SpendReasonCode, sourceContentHash string) *UsageLedgerEntry {
	entry := &UsageLedgerEntry{
		ID:                id,
		TenantID:          tenantID,
		BalanceAccountID:  balanceAccountID,
		Type:              entryType,
		Direction:         direction,
		AmountCents:       amountCents,
		Currency:          currency,
		ReasonCode:        reasonCode,
		SourceContentHash: sourceContentHash,
		CreatedAt:         time.Now().UTC(),
	}
	entry.ContentHash = entry.computeHash()
	return entry
}

// Validate ensures the ledger entry is auditable and typed.
func (entry *UsageLedgerEntry) Validate() error {
	if entry == nil {
		return errors.New("usage_ledger_entry: entry is nil")
	}
	if entry.ID == "" {
		return errors.New("usage_ledger_entry: id is required")
	}
	if entry.TenantID == "" {
		return errors.New("usage_ledger_entry: tenant_id is required")
	}
	if entry.BalanceAccountID == "" {
		return errors.New("usage_ledger_entry: balance_account_id is required")
	}
	if entry.Type == "" {
		return errors.New("usage_ledger_entry: type is required")
	}
	if entry.Direction != SettlementDebit && entry.Direction != SettlementCredit {
		return errors.New("usage_ledger_entry: direction must be DEBIT or CREDIT")
	}
	if entry.AmountCents <= 0 {
		return errors.New("usage_ledger_entry: amount_cents must be positive")
	}
	if entry.Currency == "" {
		return errors.New("usage_ledger_entry: currency is required")
	}
	if entry.ReasonCode == "" {
		return errors.New("usage_ledger_entry: reason_code is required")
	}
	if entry.SourceContentHash == "" {
		return errors.New("usage_ledger_entry: source_content_hash is required")
	}
	if entry.Type == UsageLedgerDebit && entry.UsageReceiptID == "" {
		return errors.New("usage_ledger_entry: usage_receipt_id is required for DEBIT entries")
	}
	return nil
}

func (entry *UsageLedgerEntry) computeHash() string {
	return hashSpendAuthorityCanonical(struct {
		ID                  string               `json:"id"`
		TenantID            string               `json:"tenant_id"`
		BalanceAccountID    string               `json:"balance_account_id"`
		UsageReceiptID      string               `json:"usage_receipt_id,omitempty"`
		SettlementReceiptID string               `json:"settlement_receipt_id,omitempty"`
		Type                UsageLedgerEntryType `json:"type"`
		Direction           SettlementDirection  `json:"direction"`
		AmountCents         int64                `json:"amount_cents"`
		Currency            string               `json:"currency"`
		ReasonCode          SpendReasonCode      `json:"reason_code"`
		SourceContentHash   string               `json:"source_content_hash"`
	}{entry.ID, entry.TenantID, entry.BalanceAccountID, entry.UsageReceiptID, entry.SettlementReceiptID, entry.Type, entry.Direction, entry.AmountCents, entry.Currency, entry.ReasonCode, entry.SourceContentHash})
}

// CapacityCommitmentStatus tracks a provider usage commitment.
type CapacityCommitmentStatus string

const (
	CapacityCommitmentDraft     CapacityCommitmentStatus = "DRAFT"
	CapacityCommitmentActive    CapacityCommitmentStatus = "ACTIVE"
	CapacityCommitmentExhausted CapacityCommitmentStatus = "EXHAUSTED"
	CapacityCommitmentExpired   CapacityCommitmentStatus = "EXPIRED"
	CapacityCommitmentCanceled  CapacityCommitmentStatus = "CANCELED"
)

// CapacityCommitment records committed provider capacity gated by contract evidence.
type CapacityCommitment struct {
	ID                   string                   `json:"id"`
	TenantID             string                   `json:"tenant_id"`
	ProviderID           string                   `json:"provider_id"`
	ModelFamily          string                   `json:"model_family,omitempty"`
	Currency             string                   `json:"currency"`
	CommittedAmountCents int64                    `json:"committed_amount_cents"`
	UsedAmountCents      int64                    `json:"used_amount_cents"`
	ContractRef          string                   `json:"contract_ref"`
	EvidencePackRef      string                   `json:"evidence_pack_ref"`
	Status               CapacityCommitmentStatus `json:"status"`
	PeriodStart          time.Time                `json:"period_start"`
	PeriodEnd            time.Time                `json:"period_end"`
	ContentHash          string                   `json:"content_hash"`
}

// NewCapacityCommitment creates a draft commitment.
func NewCapacityCommitment(id, tenantID, providerID, currency string, committedAmountCents int64, periodStart, periodEnd time.Time) *CapacityCommitment {
	c := &CapacityCommitment{
		ID:                   id,
		TenantID:             tenantID,
		ProviderID:           providerID,
		Currency:             currency,
		CommittedAmountCents: committedAmountCents,
		Status:               CapacityCommitmentDraft,
		PeriodStart:          periodStart,
		PeriodEnd:            periodEnd,
	}
	c.ContentHash = c.computeHash()
	return c
}

// RemainingCents returns unused committed capacity.
func (c *CapacityCommitment) RemainingCents() int64 {
	if c == nil {
		return 0
	}
	remaining := c.CommittedAmountCents - c.UsedAmountCents
	if remaining < 0 {
		return 0
	}
	return remaining
}

// Validate ensures active commitments have contract and evidence proof.
func (c *CapacityCommitment) Validate() error {
	if c == nil {
		return errors.New("capacity_commitment: commitment is nil")
	}
	if c.ID == "" {
		return errors.New("capacity_commitment: id is required")
	}
	if c.TenantID == "" {
		return errors.New("capacity_commitment: tenant_id is required")
	}
	if c.ProviderID == "" {
		return errors.New("capacity_commitment: provider_id is required")
	}
	if c.Currency == "" {
		return errors.New("capacity_commitment: currency is required")
	}
	if c.CommittedAmountCents <= 0 {
		return errors.New("capacity_commitment: committed_amount_cents must be positive")
	}
	if c.UsedAmountCents < 0 {
		return errors.New("capacity_commitment: used_amount_cents cannot be negative")
	}
	if c.UsedAmountCents > c.CommittedAmountCents {
		return errors.New("capacity_commitment: used_amount_cents cannot exceed committed_amount_cents")
	}
	if c.Status == "" {
		return errors.New("capacity_commitment: status is required")
	}
	if !c.PeriodEnd.After(c.PeriodStart) {
		return errors.New("capacity_commitment: period_end must be after period_start")
	}
	if c.Status == CapacityCommitmentActive && c.ContractRef == "" {
		return errors.New("capacity_commitment: contract_ref is required for ACTIVE commitments")
	}
	if c.Status == CapacityCommitmentActive && c.EvidencePackRef == "" {
		return errors.New("capacity_commitment: evidence_pack_ref is required for ACTIVE commitments")
	}
	return nil
}

func (c *CapacityCommitment) computeHash() string {
	return hashSpendAuthorityCanonical(struct {
		ID                   string                   `json:"id"`
		TenantID             string                   `json:"tenant_id"`
		ProviderID           string                   `json:"provider_id"`
		ModelFamily          string                   `json:"model_family,omitempty"`
		Currency             string                   `json:"currency"`
		CommittedAmountCents int64                    `json:"committed_amount_cents"`
		UsedAmountCents      int64                    `json:"used_amount_cents"`
		ContractRef          string                   `json:"contract_ref"`
		EvidencePackRef      string                   `json:"evidence_pack_ref"`
		Status               CapacityCommitmentStatus `json:"status"`
	}{c.ID, c.TenantID, c.ProviderID, c.ModelFamily, c.Currency, c.CommittedAmountCents, c.UsedAmountCents, c.ContractRef, c.EvidencePackRef, c.Status})
}

// CreditLineStatus is intentionally restricted for MVP runtime.
type CreditLineStatus string

const (
	CreditLineDeferred CreditLineStatus = "DEFERRED"
)

// CreditLine records the deferred credit-line concept and prevents runtime use.
type CreditLine struct {
	ID              string           `json:"id"`
	TenantID        string           `json:"tenant_id"`
	ProviderID      string           `json:"provider_id,omitempty"`
	Currency        string           `json:"currency"`
	LimitCents      int64            `json:"limit_cents"`
	Status          CreditLineStatus `json:"status"`
	RuntimeUsable   bool             `json:"runtime_usable"`
	DeferralReason  SpendReasonCode  `json:"deferral_reason"`
	LegalReviewRef  string           `json:"legal_review_ref,omitempty"`
	EvidencePackRef string           `json:"evidence_pack_ref,omitempty"`
	ContentHash     string           `json:"content_hash"`
}

// NewDeferredCreditLine creates a non-runtime credit-line placeholder.
func NewDeferredCreditLine(id, tenantID, currency string) *CreditLine {
	c := &CreditLine{
		ID:             id,
		TenantID:       tenantID,
		Currency:       currency,
		Status:         CreditLineDeferred,
		RuntimeUsable:  false,
		DeferralReason: SpendReasonProviderContractNeeded,
	}
	c.ContentHash = c.computeHash()
	return c
}

// Validate ensures credit lines cannot be used by the MVP runtime.
func (c *CreditLine) Validate() error {
	if c == nil {
		return errors.New("credit_line: credit line is nil")
	}
	if c.ID == "" {
		return errors.New("credit_line: id is required")
	}
	if c.TenantID == "" {
		return errors.New("credit_line: tenant_id is required")
	}
	if c.Currency == "" {
		return errors.New("credit_line: currency is required")
	}
	if c.LimitCents < 0 {
		return errors.New("credit_line: limit_cents cannot be negative")
	}
	if c.Status != CreditLineDeferred {
		return errors.New("credit_line: only DEFERRED status is allowed in MVP")
	}
	if c.RuntimeUsable {
		return errors.New("credit_line: runtime_usable must be false in MVP")
	}
	if c.DeferralReason == "" {
		return errors.New("credit_line: deferral_reason is required")
	}
	return nil
}

func (c *CreditLine) computeHash() string {
	return hashSpendAuthorityCanonical(struct {
		ID             string           `json:"id"`
		TenantID       string           `json:"tenant_id"`
		ProviderID     string           `json:"provider_id,omitempty"`
		Currency       string           `json:"currency"`
		LimitCents     int64            `json:"limit_cents"`
		Status         CreditLineStatus `json:"status"`
		RuntimeUsable  bool             `json:"runtime_usable"`
		DeferralReason SpendReasonCode  `json:"deferral_reason"`
	}{c.ID, c.TenantID, c.ProviderID, c.Currency, c.LimitCents, c.Status, c.RuntimeUsable, c.DeferralReason})
}
