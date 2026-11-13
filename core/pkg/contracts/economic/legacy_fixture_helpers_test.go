// quantum_posture: historical test fixtures retain classical receipt hashing;
// these helpers are test-only and grant no runtime spending authority.

package economic

import (
	"errors"
	"time"
)

// NewAgentSpendEnvelope creates an active envelope and computes its content hash.
func NewAgentSpendEnvelope(id, tenantID, agentID, principalID, budgetID, currency string, period SpendPeriod, maxAmountCents, perRequestMaxCents int64, policyHash string) *AgentSpendEnvelope {
	e := &AgentSpendEnvelope{
		ID:                 id,
		TenantID:           tenantID,
		AgentID:            agentID,
		PrincipalID:        principalID,
		BudgetID:           budgetID,
		Currency:           currency,
		Period:             period,
		MaxAmountCents:     maxAmountCents,
		PerRequestMaxCents: perRequestMaxCents,
		Active:             true,
		PolicyHash:         policyHash,
		EffectiveAt:        time.Now().UTC(),
	}
	e.ContentHash = e.computeHash()
	return e
}

// RemainingCents returns unspent and unreserved cents. Negative balances clamp
// to zero, and so does used or reserved spend at the int64 limit: the
// subtraction never wraps (helm-tracker#313 r1, F12).
func (e *AgentSpendEnvelope) RemainingCents() int64 {
	if e == nil {
		return 0
	}
	remaining := e.MaxAmountCents
	for _, spent := range []int64{e.UsedAmountCents, e.ReservedAmountCents} {
		switch {
		case spent <= 0:
		case spent >= remaining:
			return 0
		default:
			remaining -= spent
		}
	}
	return max(remaining, 0)
}

// RequiresApproval reports whether the amount crosses the envelope's approval gate.
func (e *AgentSpendEnvelope) RequiresApproval(amountCents int64) bool {
	return e != nil && e.ApprovalRequiredAboveCents > 0 && amountCents >= e.ApprovalRequiredAboveCents
}

// AllowsProvider fails closed when the provider allow-list is empty or missing the provider.
func (e *AgentSpendEnvelope) AllowsProvider(providerID string) bool {
	return e != nil && providerID != "" && containsString(e.AllowedProviders, providerID)
}

// AllowsModel fails closed when the model allow-list is empty or missing the model.
func (e *AgentSpendEnvelope) AllowsModel(modelID string) bool {
	return e != nil && modelID != "" && containsString(e.AllowedModels, modelID)
}

// EvaluateSpend returns the fail-closed budget verdict for a selected route.
func (e *AgentSpendEnvelope) EvaluateSpend(amountCents int64, providerID, modelID string) SpendAuthorityDecision {
	if e == nil {
		return newSpendAuthorityDecision(BudgetVerdictDeny, SpendReasonEnvelopeNotFound, "spend envelope not found", 0, "")
	}
	if !e.Active {
		return newSpendAuthorityDecision(BudgetVerdictDeny, SpendReasonEnvelopeInactive, "spend envelope is inactive", e.RemainingCents(), e.ContentHash)
	}
	now := time.Now().UTC()
	if e.EffectiveAt.After(now) {
		return newSpendAuthorityDecision(BudgetVerdictDeny, SpendReasonEnvelopeNotYetEffective, "spend envelope is not yet effective", e.RemainingCents(), e.ContentHash)
	}
	if e.ExpiresAt != nil && !now.Before(*e.ExpiresAt) {
		return newSpendAuthorityDecision(BudgetVerdictDeny, SpendReasonEnvelopeExpired, "spend envelope is expired", e.RemainingCents(), e.ContentHash)
	}
	if e.EmergencyStop {
		return newSpendAuthorityDecision(BudgetVerdictDeny, SpendReasonEmergencyStop, "spend envelope emergency stop is active", e.RemainingCents(), e.ContentHash)
	}
	if amountCents <= 0 {
		return newSpendAuthorityDecision(BudgetVerdictDeny, SpendReasonInvalidAmount, "spend amount must be positive", e.RemainingCents(), e.ContentHash)
	}
	if amountCents > e.RemainingCents() {
		return newSpendAuthorityDecision(BudgetVerdictDeny, SpendReasonBalanceInsufficient, "spend exceeds remaining envelope balance", e.RemainingCents(), e.ContentHash)
	}
	if e.PerRequestMaxCents > 0 && amountCents > e.PerRequestMaxCents {
		return newSpendAuthorityDecision(BudgetVerdictDeny, SpendReasonPerRequestLimit, "spend exceeds per-request envelope limit", e.RemainingCents(), e.ContentHash)
	}
	if !e.AllowsProvider(providerID) {
		return newSpendAuthorityDecision(BudgetVerdictDeny, SpendReasonProviderNotAllowed, "provider is not allowed by spend envelope", e.RemainingCents(), e.ContentHash)
	}
	if !e.AllowsModel(modelID) {
		return newSpendAuthorityDecision(BudgetVerdictDeny, SpendReasonModelNotAllowed, "model is not allowed by spend envelope", e.RemainingCents(), e.ContentHash)
	}
	if e.RequiresApproval(amountCents) {
		return newSpendAuthorityDecision(BudgetVerdictEscalate, SpendReasonApprovalRequired, "spend requires approval", e.RemainingCents(), e.ContentHash)
	}
	return newSpendAuthorityDecision(BudgetVerdictAllow, SpendReasonOKWithinEnvelope, "spend is within envelope", e.RemainingCents(), e.ContentHash)
}

// Validate ensures the envelope is well-formed. Runtime state can still deny it.
func (e *AgentSpendEnvelope) Validate() error {
	if e == nil {
		return errors.New("agent_spend_envelope: envelope is nil")
	}
	if e.ID == "" {
		return errors.New("agent_spend_envelope: id is required")
	}
	if e.TenantID == "" {
		return errors.New("agent_spend_envelope: tenant_id is required")
	}
	if e.AgentID == "" {
		return errors.New("agent_spend_envelope: agent_id is required")
	}
	if e.PrincipalID == "" {
		return errors.New("agent_spend_envelope: principal_id is required")
	}
	if e.BudgetID == "" {
		return errors.New("agent_spend_envelope: budget_id is required")
	}
	if e.Currency == "" {
		return errors.New("agent_spend_envelope: currency is required")
	}
	if e.Period == "" {
		return errors.New("agent_spend_envelope: period is required")
	}
	if e.MaxAmountCents <= 0 {
		return errors.New("agent_spend_envelope: max_amount_cents must be positive")
	}
	if e.UsedAmountCents < 0 {
		return errors.New("agent_spend_envelope: used_amount_cents cannot be negative")
	}
	if e.ReservedAmountCents < 0 {
		return errors.New("agent_spend_envelope: reserved_amount_cents cannot be negative")
	}
	if e.UsedAmountCents > e.MaxAmountCents || e.ReservedAmountCents > e.MaxAmountCents-e.UsedAmountCents {
		return errors.New("agent_spend_envelope: used plus reserved exceeds max_amount_cents")
	}
	if e.PerRequestMaxCents <= 0 {
		return errors.New("agent_spend_envelope: per_request_max_cents must be positive")
	}
	if e.PerRequestMaxCents > e.MaxAmountCents {
		return errors.New("agent_spend_envelope: per_request_max_cents exceeds max_amount_cents")
	}
	if e.ApprovalRequiredAboveCents < 0 {
		return errors.New("agent_spend_envelope: approval_required_above_cents cannot be negative")
	}
	if len(e.AllowedProviders) == 0 {
		return errors.New("agent_spend_envelope: at least one allowed provider is required")
	}
	if len(e.AllowedModels) == 0 {
		return errors.New("agent_spend_envelope: at least one allowed model is required")
	}
	if e.PolicyHash == "" {
		return errors.New("agent_spend_envelope: policy_hash is required")
	}
	if e.ExpiresAt != nil && e.ExpiresAt.Before(e.EffectiveAt) {
		return errors.New("agent_spend_envelope: expires_at must be after effective_at")
	}
	return nil
}

func (e *AgentSpendEnvelope) computeHash() string {
	return hashSpendAuthorityCanonical(struct {
		ID                  string       `json:"id"`
		TenantID            string       `json:"tenant_id"`
		WorkspaceID         string       `json:"workspace_id,omitempty"`
		AgentID             string       `json:"agent_id"`
		PrincipalID         string       `json:"principal_id"`
		BudgetID            string       `json:"budget_id"`
		Currency            string       `json:"currency"`
		Period              SpendPeriod  `json:"period"`
		MaxAmountCents      int64        `json:"max_amount_cents"`
		UsedAmountCents     int64        `json:"used_amount_cents"`
		ReservedAmountCents int64        `json:"reserved_amount_cents"`
		PerRequestMaxCents  int64        `json:"per_request_max_cents"`
		ApprovalAboveCents  int64        `json:"approval_required_above_cents,omitempty"`
		AllowedProviders    []string     `json:"allowed_providers"`
		AllowedModels       []string     `json:"allowed_models"`
		FallbackModels      []ModelRoute `json:"fallback_models,omitempty"`
		ModelSubstitution   bool         `json:"allow_model_substitution"`
		EmergencyStop       bool         `json:"emergency_stop"`
		Active              bool         `json:"active"`
		PolicyHash          string       `json:"policy_hash"`
	}{
		e.ID,
		e.TenantID,
		e.WorkspaceID,
		e.AgentID,
		e.PrincipalID,
		e.BudgetID,
		e.Currency,
		e.Period,
		e.MaxAmountCents,
		e.UsedAmountCents,
		e.ReservedAmountCents,
		e.PerRequestMaxCents,
		e.ApprovalRequiredAboveCents,
		e.AllowedProviders,
		e.AllowedModels,
		e.FallbackModels,
		e.AllowModelSubstitution,
		e.EmergencyStop,
		e.Active,
		e.PolicyHash,
	})
}

func newSpendAuthorityDecision(verdict BudgetVerdict, code SpendReasonCode, reason string, remainingCents int64, envelopeHash string) SpendAuthorityDecision {
	d := SpendAuthorityDecision{
		Verdict:        verdict,
		ReasonCode:     code,
		Reason:         reason,
		RemainingCents: remainingCents,
		EnvelopeHash:   envelopeHash,
	}
	d.ContentHash = d.computeHash()
	return d
}

// NewRouteQuote creates a route quote with deterministic content hash.
func NewRouteQuote(id, tenantID, spendIntentID, envelopeID, agentID string, selected ModelRoute, quotedAmountCents, maxAmountCents int64, currency, routePolicyHash string, expiresAt time.Time, decision SpendAuthorityDecision) *RouteQuote {
	q := &RouteQuote{
		ID:                        id,
		TenantID:                  tenantID,
		SpendIntentID:             spendIntentID,
		EnvelopeID:                envelopeID,
		AgentID:                   agentID,
		RequestedProviderID:       selected.ProviderID,
		RequestedModelID:          selected.ModelID,
		SelectedProviderID:        selected.ProviderID,
		SelectedModelID:           selected.ModelID,
		ProviderPriceSnapshotHash: selected.PriceSnapshotHash,
		QuotedAmountCents:         quotedAmountCents,
		MaxAmountCents:            maxAmountCents,
		Currency:                  currency,
		RoutePolicyHash:           routePolicyHash,
		BudgetVerdict:             decision.Verdict,
		ReasonCode:                decision.ReasonCode,
		CreatedAt:                 time.Now().UTC(),
		ExpiresAt:                 expiresAt,
	}
	q.ContentHash = q.computeHash()
	return q
}

// NewBudgetVerdictReceipt creates an unsigned pre-dispatch receipt.
func NewBudgetVerdictReceipt(id, tenantID, spendIntentID, envelopeID, agentID, providerID, modelID string, quotedAmountCents, maxAmountCents int64, currency, providerPriceSnapshotHash, routePolicyHash, evidencePackRef string, decision SpendAuthorityDecision) *BudgetVerdictReceipt {
	r := &BudgetVerdictReceipt{
		ID:                        id,
		TenantID:                  tenantID,
		SpendIntentID:             spendIntentID,
		EnvelopeID:                envelopeID,
		AgentID:                   agentID,
		ProviderID:                providerID,
		ModelID:                   modelID,
		ProviderPriceSnapshotHash: providerPriceSnapshotHash,
		QuotedAmountCents:         quotedAmountCents,
		MaxAmountCents:            maxAmountCents,
		Currency:                  currency,
		BudgetVerdict:             decision.Verdict,
		ReasonCode:                decision.ReasonCode,
		DecisionHash:              decision.ContentHash,
		EnvelopeHash:              decision.EnvelopeHash,
		RoutePolicyHash:           routePolicyHash,
		EvidencePackRef:           evidencePackRef,
		CreatedAt:                 time.Now().UTC(),
	}
	r.ContentHash = r.computeHash()
	return r
}

// NewUsageReceipt creates a completed usage receipt with deterministic hash.
func NewUsageReceipt(id, tenantID, routeQuoteID, spendIntentID, envelopeID, agentID, providerID, modelID string, quotedAmountCents, providerCostCents, platformFeeCents int64, currency, policyHash, evidencePackRef string) *UsageReceipt {
	actualAmountCents := providerCostCents + platformFeeCents
	r := &UsageReceipt{
		ID:                id,
		TenantID:          tenantID,
		RouteQuoteID:      routeQuoteID,
		SpendIntentID:     spendIntentID,
		EnvelopeID:        envelopeID,
		AgentID:           agentID,
		ProviderID:        providerID,
		ModelID:           modelID,
		QuotedAmountCents: quotedAmountCents,
		ActualAmountCents: actualAmountCents,
		ProviderCostCents: providerCostCents,
		PlatformFeeCents:  platformFeeCents,
		BalanceDebitCents: actualAmountCents,
		Currency:          currency,
		BudgetVerdict:     BudgetVerdictAllow,
		ReasonCode:        SpendReasonOKWithinEnvelope,
		PolicyHash:        policyHash,
		EvidencePackRef:   evidencePackRef,
		CreatedAt:         time.Now().UTC(),
	}
	r.ContentHash = r.computeHash()
	return r
}

// NewSettlementReceipt creates a settlement receipt with deterministic hash.
func NewSettlementReceipt(id, tenantID, usageReceiptID, routeQuoteID, treasuryAccountID, sourceUsageReceiptHash, currency, evidencePackRef string, entries []SettlementLedgerEntry) *SettlementReceipt {
	s := &SettlementReceipt{
		ID:                     id,
		TenantID:               tenantID,
		UsageReceiptID:         usageReceiptID,
		RouteQuoteID:           routeQuoteID,
		TreasuryAccountID:      treasuryAccountID,
		SourceUsageReceiptHash: sourceUsageReceiptHash,
		LedgerEntries:          entries,
		Currency:               currency,
		EvidencePackRef:        evidencePackRef,
		CreatedAt:              time.Now().UTC(),
	}
	s.ContentHash = s.computeHash()
	return s
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
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
