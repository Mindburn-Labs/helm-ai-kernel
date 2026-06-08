// Package economic - Mindburn Spend Authority contracts.
//
// These contracts bind AI compute spend to a fail-closed budget verdict before
// provider dispatch. Runtime enforcement lives in the PEP/CPI and gateway
// layers; this package defines the source-owned evidence objects they emit.
package economic

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// BudgetVerdict is the kernel-level decision for a spend attempt.
type BudgetVerdict string

const (
	BudgetVerdictAllow    BudgetVerdict = "ALLOW"
	BudgetVerdictDeny     BudgetVerdict = "DENY"
	BudgetVerdictEscalate BudgetVerdict = "ESCALATE"
)

// SpendReasonCode is a stable machine-readable reason for a spend verdict.
type SpendReasonCode string

const (
	SpendReasonOKWithinEnvelope        SpendReasonCode = "OK_WITHIN_ENVELOPE"
	SpendReasonOKApproved              SpendReasonCode = "OK_APPROVED"
	SpendReasonEnvelopeNotFound        SpendReasonCode = "ERR_SPEND_ENVELOPE_NOT_FOUND"
	SpendReasonEnvelopeInactive        SpendReasonCode = "ERR_SPEND_ENVELOPE_INACTIVE"
	SpendReasonEnvelopeNotYetEffective SpendReasonCode = "ERR_SPEND_ENVELOPE_NOT_YET_EFFECTIVE"
	SpendReasonEnvelopeExpired         SpendReasonCode = "ERR_SPEND_ENVELOPE_EXPIRED"
	SpendReasonEmergencyStop           SpendReasonCode = "ERR_SPEND_EMERGENCY_STOP"
	SpendReasonInvalidAmount           SpendReasonCode = "ERR_SPEND_INVALID_AMOUNT"
	SpendReasonBalanceInsufficient     SpendReasonCode = "ERR_BALANCE_INSUFFICIENT"
	SpendReasonPerRequestLimit         SpendReasonCode = "ERR_SPEND_PER_REQUEST_LIMIT"
	SpendReasonProviderNotAllowed      SpendReasonCode = "ERR_SPEND_PROVIDER_NOT_ALLOWED"
	SpendReasonModelNotAllowed         SpendReasonCode = "ERR_SPEND_MODEL_NOT_ALLOWED"
	SpendReasonApprovalRequired        SpendReasonCode = "ERR_APPROVAL_REQUIRED"
	SpendReasonRouteQuoteExpired       SpendReasonCode = "ERR_ROUTE_QUOTE_EXPIRED"
	SpendReasonProviderPriceStale      SpendReasonCode = "ERR_PROVIDER_PRICE_STALE"
	SpendReasonReceiptMismatch         SpendReasonCode = "ERR_RECEIPT_MISMATCH"
	SpendReasonLedgerUnbalanced        SpendReasonCode = "ERR_LEDGER_UNBALANCED"
	SpendReasonEvidenceMissing         SpendReasonCode = "ERR_EVIDENCE_MISSING"
	SpendReasonSettlementMissing       SpendReasonCode = "ERR_SETTLEMENT_MISSING"
	SpendReasonProviderContractNeeded  SpendReasonCode = "ERR_PROVIDER_CONTRACT_NEEDED"
)

// SpendPeriod is the reset cadence for an agent envelope.
type SpendPeriod string

const (
	SpendPeriodDaily     SpendPeriod = "DAILY"
	SpendPeriodWeekly    SpendPeriod = "WEEKLY"
	SpendPeriodMonthly   SpendPeriod = "MONTHLY"
	SpendPeriodQuarterly SpendPeriod = "QUARTERLY"
)

// AgentSpendEnvelope constrains spend for one agent/principal/workspace scope.
type AgentSpendEnvelope struct {
	ID                         string            `json:"id"`
	TenantID                   string            `json:"tenant_id"`
	WorkspaceID                string            `json:"workspace_id,omitempty"`
	AgentID                    string            `json:"agent_id"`
	PrincipalID                string            `json:"principal_id"`
	BudgetID                   string            `json:"budget_id"`
	Name                       string            `json:"name,omitempty"`
	Currency                   string            `json:"currency"`
	Period                     SpendPeriod       `json:"period"`
	MaxAmountCents             int64             `json:"max_amount_cents"`
	UsedAmountCents            int64             `json:"used_amount_cents"`
	ReservedAmountCents        int64             `json:"reserved_amount_cents"`
	PerRequestMaxCents         int64             `json:"per_request_max_cents"`
	ApprovalRequiredAboveCents int64             `json:"approval_required_above_cents,omitempty"`
	AllowedProviders           []string          `json:"allowed_providers"`
	AllowedModels              []string          `json:"allowed_models"`
	FallbackModels             []ModelRoute      `json:"fallback_models,omitempty"`
	AllowModelSubstitution     bool              `json:"allow_model_substitution"`
	EmergencyStop              bool              `json:"emergency_stop"`
	Active                     bool              `json:"active"`
	ApprovalPolicyRef          string            `json:"approval_policy_ref,omitempty"`
	PolicyHash                 string            `json:"policy_hash"`
	EffectiveAt                time.Time         `json:"effective_at"`
	ExpiresAt                  *time.Time        `json:"expires_at,omitempty"`
	Metadata                   map[string]string `json:"metadata,omitempty"`
	ContentHash                string            `json:"content_hash"`
}

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

// RemainingCents returns unspent and unreserved cents. Negative balances clamp to zero.
func (e *AgentSpendEnvelope) RemainingCents() int64 {
	if e == nil {
		return 0
	}
	remaining := e.MaxAmountCents - e.UsedAmountCents - e.ReservedAmountCents
	if remaining < 0 {
		return 0
	}
	return remaining
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
	if e.UsedAmountCents+e.ReservedAmountCents > e.MaxAmountCents {
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

// SpendAuthorityDecision is the auditable outcome of envelope evaluation.
type SpendAuthorityDecision struct {
	Verdict        BudgetVerdict   `json:"verdict"`
	ReasonCode     SpendReasonCode `json:"reason_code"`
	Reason         string          `json:"reason"`
	RemainingCents int64           `json:"remaining_cents"`
	EnvelopeHash   string          `json:"envelope_hash,omitempty"`
	ContentHash    string          `json:"content_hash"`
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

func (d SpendAuthorityDecision) computeHash() string {
	return hashSpendAuthorityCanonical(struct {
		Verdict        BudgetVerdict   `json:"verdict"`
		ReasonCode     SpendReasonCode `json:"reason_code"`
		RemainingCents int64           `json:"remaining_cents"`
		EnvelopeHash   string          `json:"envelope_hash,omitempty"`
	}{d.Verdict, d.ReasonCode, d.RemainingCents, d.EnvelopeHash})
}

// ModelRoute identifies an allowed or fallback provider/model route.
type ModelRoute struct {
	ProviderID        string `json:"provider_id"`
	ModelID           string `json:"model_id"`
	PriceSnapshotHash string `json:"price_snapshot_hash"`
	MaxAmountCents    int64  `json:"max_amount_cents,omitempty"`
}

// RouteQuote records the selected provider/model and quoted cost before dispatch.
type RouteQuote struct {
	ID                        string            `json:"id"`
	TenantID                  string            `json:"tenant_id"`
	SpendIntentID             string            `json:"spend_intent_id"`
	EnvelopeID                string            `json:"envelope_id"`
	AgentID                   string            `json:"agent_id"`
	PrincipalID               string            `json:"principal_id,omitempty"`
	RequestedProviderID       string            `json:"requested_provider_id,omitempty"`
	RequestedModelID          string            `json:"requested_model_id"`
	SelectedProviderID        string            `json:"selected_provider_id"`
	SelectedModelID           string            `json:"selected_model_id"`
	ProviderPriceSnapshotHash string            `json:"provider_price_snapshot_hash"`
	QuotedAmountCents         int64             `json:"quoted_amount_cents"`
	MaxAmountCents            int64             `json:"max_amount_cents"`
	Currency                  string            `json:"currency"`
	InputTokens               int64             `json:"input_tokens,omitempty"`
	OutputTokens              int64             `json:"output_tokens,omitempty"`
	FallbackChain             []ModelRoute      `json:"fallback_chain,omitempty"`
	ModelSubstituted          bool              `json:"model_substituted"`
	RoutePolicyHash           string            `json:"route_policy_hash"`
	BudgetVerdict             BudgetVerdict     `json:"budget_verdict"`
	ReasonCode                SpendReasonCode   `json:"reason_code"`
	ReceiptHash               string            `json:"receipt_hash,omitempty"`
	Metadata                  map[string]string `json:"metadata,omitempty"`
	CreatedAt                 time.Time         `json:"created_at"`
	ExpiresAt                 time.Time         `json:"expires_at"`
	ContentHash               string            `json:"content_hash"`
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

// Expired reports whether the quote can no longer be used.
func (q *RouteQuote) Expired(now time.Time) bool {
	return q == nil || !now.Before(q.ExpiresAt)
}

// Validate ensures the route quote is dispatch-safe.
func (q *RouteQuote) Validate() error {
	if q == nil {
		return errors.New("route_quote: quote is nil")
	}
	if q.ID == "" {
		return errors.New("route_quote: id is required")
	}
	if q.TenantID == "" {
		return errors.New("route_quote: tenant_id is required")
	}
	if q.SpendIntentID == "" {
		return errors.New("route_quote: spend_intent_id is required")
	}
	if q.EnvelopeID == "" {
		return errors.New("route_quote: envelope_id is required")
	}
	if q.AgentID == "" {
		return errors.New("route_quote: agent_id is required")
	}
	if q.RequestedModelID == "" {
		return errors.New("route_quote: requested_model_id is required")
	}
	if q.SelectedProviderID == "" {
		return errors.New("route_quote: selected_provider_id is required")
	}
	if q.SelectedModelID == "" {
		return errors.New("route_quote: selected_model_id is required")
	}
	if q.ProviderPriceSnapshotHash == "" {
		return errors.New("route_quote: provider_price_snapshot_hash is required")
	}
	if q.QuotedAmountCents <= 0 {
		return errors.New("route_quote: quoted_amount_cents must be positive")
	}
	if q.MaxAmountCents <= 0 {
		return errors.New("route_quote: max_amount_cents must be positive")
	}
	if q.QuotedAmountCents > q.MaxAmountCents {
		return errors.New("route_quote: quoted_amount_cents exceeds max_amount_cents")
	}
	if q.Currency == "" {
		return errors.New("route_quote: currency is required")
	}
	if q.RoutePolicyHash == "" {
		return errors.New("route_quote: route_policy_hash is required")
	}
	if q.BudgetVerdict == "" {
		return errors.New("route_quote: budget_verdict is required")
	}
	if q.ReasonCode == "" {
		return errors.New("route_quote: reason_code is required")
	}
	if !q.ExpiresAt.After(q.CreatedAt) {
		return errors.New("route_quote: expires_at must be after created_at")
	}
	if q.ModelSubstituted && len(q.FallbackChain) == 0 {
		return errors.New("route_quote: fallback_chain is required when model_substituted is true")
	}
	return nil
}

func (q *RouteQuote) computeHash() string {
	return hashSpendAuthorityCanonical(struct {
		ID                        string          `json:"id"`
		TenantID                  string          `json:"tenant_id"`
		SpendIntentID             string          `json:"spend_intent_id"`
		EnvelopeID                string          `json:"envelope_id"`
		AgentID                   string          `json:"agent_id"`
		SelectedProviderID        string          `json:"selected_provider_id"`
		SelectedModelID           string          `json:"selected_model_id"`
		ProviderPriceSnapshotHash string          `json:"provider_price_snapshot_hash"`
		QuotedAmountCents         int64           `json:"quoted_amount_cents"`
		MaxAmountCents            int64           `json:"max_amount_cents"`
		Currency                  string          `json:"currency"`
		RoutePolicyHash           string          `json:"route_policy_hash"`
		BudgetVerdict             BudgetVerdict   `json:"budget_verdict"`
		ReasonCode                SpendReasonCode `json:"reason_code"`
		ReceiptHash               string          `json:"receipt_hash,omitempty"`
	}{q.ID, q.TenantID, q.SpendIntentID, q.EnvelopeID, q.AgentID, q.SelectedProviderID, q.SelectedModelID, q.ProviderPriceSnapshotHash, q.QuotedAmountCents, q.MaxAmountCents, q.Currency, q.RoutePolicyHash, q.BudgetVerdict, q.ReasonCode, q.ReceiptHash})
}

// UsageReceipt records the actual provider usage and balance debit after dispatch.
type UsageReceipt struct {
	ID                        string            `json:"id"`
	TenantID                  string            `json:"tenant_id"`
	RouteQuoteID              string            `json:"route_quote_id"`
	SpendIntentID             string            `json:"spend_intent_id"`
	EnvelopeID                string            `json:"envelope_id"`
	AgentID                   string            `json:"agent_id"`
	ProviderID                string            `json:"provider_id"`
	ModelID                   string            `json:"model_id"`
	ProviderRequestID         string            `json:"provider_request_id"`
	ProviderPriceSnapshotHash string            `json:"provider_price_snapshot_hash"`
	QuotedAmountCents         int64             `json:"quoted_amount_cents"`
	ActualAmountCents         int64             `json:"actual_amount_cents"`
	ProviderCostCents         int64             `json:"provider_cost_cents"`
	PlatformFeeCents          int64             `json:"platform_fee_cents"`
	BalanceDebitCents         int64             `json:"balance_debit_cents"`
	Currency                  string            `json:"currency"`
	InputTokens               int64             `json:"input_tokens,omitempty"`
	OutputTokens              int64             `json:"output_tokens,omitempty"`
	BudgetVerdict             BudgetVerdict     `json:"budget_verdict"`
	ReasonCode                SpendReasonCode   `json:"reason_code"`
	PolicyHash                string            `json:"policy_hash"`
	LedgerEntryIDs            []string          `json:"ledger_entry_ids,omitempty"`
	SettlementReceiptHash     string            `json:"settlement_receipt_hash,omitempty"`
	EvidencePackRef           string            `json:"evidence_pack_ref"`
	ReconciliationRef         string            `json:"reconciliation_ref,omitempty"`
	Metadata                  map[string]string `json:"metadata,omitempty"`
	CreatedAt                 time.Time         `json:"created_at"`
	ContentHash               string            `json:"content_hash"`
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

// Validate ensures the usage receipt can support reconciliation.
func (r *UsageReceipt) Validate() error {
	if r == nil {
		return errors.New("usage_receipt: receipt is nil")
	}
	if r.ID == "" {
		return errors.New("usage_receipt: id is required")
	}
	if r.TenantID == "" {
		return errors.New("usage_receipt: tenant_id is required")
	}
	if r.RouteQuoteID == "" {
		return errors.New("usage_receipt: route_quote_id is required")
	}
	if r.SpendIntentID == "" {
		return errors.New("usage_receipt: spend_intent_id is required")
	}
	if r.EnvelopeID == "" {
		return errors.New("usage_receipt: envelope_id is required")
	}
	if r.AgentID == "" {
		return errors.New("usage_receipt: agent_id is required")
	}
	if r.ProviderID == "" {
		return errors.New("usage_receipt: provider_id is required")
	}
	if r.ModelID == "" {
		return errors.New("usage_receipt: model_id is required")
	}
	if r.ProviderRequestID == "" {
		return errors.New("usage_receipt: provider_request_id is required")
	}
	if r.ProviderPriceSnapshotHash == "" {
		return errors.New("usage_receipt: provider_price_snapshot_hash is required")
	}
	if r.QuotedAmountCents <= 0 {
		return errors.New("usage_receipt: quoted_amount_cents must be positive")
	}
	if r.ActualAmountCents < 0 || r.ProviderCostCents < 0 || r.PlatformFeeCents < 0 || r.BalanceDebitCents < 0 {
		return errors.New("usage_receipt: amount fields cannot be negative")
	}
	expectedActual := r.ProviderCostCents + r.PlatformFeeCents
	if r.ActualAmountCents != expectedActual {
		return fmt.Errorf("usage_receipt: actual_amount_cents must equal provider_cost_cents plus platform_fee_cents (%d != %d)", r.ActualAmountCents, expectedActual)
	}
	if r.BalanceDebitCents != r.ActualAmountCents {
		return errors.New("usage_receipt: balance_debit_cents must equal actual_amount_cents")
	}
	if r.Currency == "" {
		return errors.New("usage_receipt: currency is required")
	}
	if r.BudgetVerdict == "" {
		return errors.New("usage_receipt: budget_verdict is required")
	}
	if r.ReasonCode == "" {
		return errors.New("usage_receipt: reason_code is required")
	}
	if r.PolicyHash == "" {
		return errors.New("usage_receipt: policy_hash is required")
	}
	if r.EvidencePackRef == "" {
		return errors.New("usage_receipt: evidence_pack_ref is required")
	}
	if r.SettlementReceiptHash == "" {
		return errors.New("usage_receipt: settlement_receipt_hash is required")
	}
	if len(r.LedgerEntryIDs) == 0 {
		return errors.New("usage_receipt: at least one ledger entry id is required")
	}
	return nil
}

func (r *UsageReceipt) computeHash() string {
	return hashSpendAuthorityCanonical(struct {
		ID                        string          `json:"id"`
		TenantID                  string          `json:"tenant_id"`
		RouteQuoteID              string          `json:"route_quote_id"`
		SpendIntentID             string          `json:"spend_intent_id"`
		EnvelopeID                string          `json:"envelope_id"`
		AgentID                   string          `json:"agent_id"`
		ProviderID                string          `json:"provider_id"`
		ModelID                   string          `json:"model_id"`
		ProviderPriceSnapshotHash string          `json:"provider_price_snapshot_hash"`
		QuotedAmountCents         int64           `json:"quoted_amount_cents"`
		ActualAmountCents         int64           `json:"actual_amount_cents"`
		ProviderCostCents         int64           `json:"provider_cost_cents"`
		PlatformFeeCents          int64           `json:"platform_fee_cents"`
		BalanceDebitCents         int64           `json:"balance_debit_cents"`
		Currency                  string          `json:"currency"`
		BudgetVerdict             BudgetVerdict   `json:"budget_verdict"`
		ReasonCode                SpendReasonCode `json:"reason_code"`
		PolicyHash                string          `json:"policy_hash"`
		SettlementReceiptHash     string          `json:"settlement_receipt_hash,omitempty"`
		EvidencePackRef           string          `json:"evidence_pack_ref"`
	}{r.ID, r.TenantID, r.RouteQuoteID, r.SpendIntentID, r.EnvelopeID, r.AgentID, r.ProviderID, r.ModelID, r.ProviderPriceSnapshotHash, r.QuotedAmountCents, r.ActualAmountCents, r.ProviderCostCents, r.PlatformFeeCents, r.BalanceDebitCents, r.Currency, r.BudgetVerdict, r.ReasonCode, r.PolicyHash, r.SettlementReceiptHash, r.EvidencePackRef})
}

// SettlementDirection identifies how a ledger entry affects an account.
type SettlementDirection string

const (
	SettlementDebit  SettlementDirection = "DEBIT"
	SettlementCredit SettlementDirection = "CREDIT"
)

// SettlementLedgerEntry is one double-entry movement backing a usage receipt.
type SettlementLedgerEntry struct {
	ID          string              `json:"id"`
	AccountID   string              `json:"account_id"`
	Direction   SettlementDirection `json:"direction"`
	AmountCents int64               `json:"amount_cents"`
	Currency    string              `json:"currency"`
	Reference   string              `json:"reference,omitempty"`
}

// SettlementReceipt records double-entry settlement for a usage receipt.
type SettlementReceipt struct {
	ID                     string                  `json:"id"`
	TenantID               string                  `json:"tenant_id"`
	UsageReceiptID         string                  `json:"usage_receipt_id"`
	RouteQuoteID           string                  `json:"route_quote_id"`
	TreasuryAccountID      string                  `json:"treasury_account_id"`
	SourceUsageReceiptHash string                  `json:"source_usage_receipt_hash"`
	LedgerEntries          []SettlementLedgerEntry `json:"ledger_entries"`
	Currency               string                  `json:"currency"`
	EvidencePackRef        string                  `json:"evidence_pack_ref"`
	CreatedAt              time.Time               `json:"created_at"`
	ContentHash            string                  `json:"content_hash"`
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

// Balanced reports whether debits equal credits.
func (s *SettlementReceipt) Balanced() bool {
	if s == nil {
		return false
	}
	var debits, credits int64
	for _, entry := range s.LedgerEntries {
		switch entry.Direction {
		case SettlementDebit:
			debits += entry.AmountCents
		case SettlementCredit:
			credits += entry.AmountCents
		}
	}
	return debits == credits && debits > 0
}

// Validate ensures the settlement can be used as financial evidence.
func (s *SettlementReceipt) Validate() error {
	if s == nil {
		return errors.New("settlement_receipt: receipt is nil")
	}
	if s.ID == "" {
		return errors.New("settlement_receipt: id is required")
	}
	if s.TenantID == "" {
		return errors.New("settlement_receipt: tenant_id is required")
	}
	if s.UsageReceiptID == "" {
		return errors.New("settlement_receipt: usage_receipt_id is required")
	}
	if s.RouteQuoteID == "" {
		return errors.New("settlement_receipt: route_quote_id is required")
	}
	if s.TreasuryAccountID == "" {
		return errors.New("settlement_receipt: treasury_account_id is required")
	}
	if s.SourceUsageReceiptHash == "" {
		return errors.New("settlement_receipt: source_usage_receipt_hash is required")
	}
	if s.Currency == "" {
		return errors.New("settlement_receipt: currency is required")
	}
	if s.EvidencePackRef == "" {
		return errors.New("settlement_receipt: evidence_pack_ref is required")
	}
	if len(s.LedgerEntries) < 2 {
		return errors.New("settlement_receipt: at least two ledger entries are required")
	}
	for _, entry := range s.LedgerEntries {
		if entry.ID == "" {
			return errors.New("settlement_receipt: ledger entry id is required")
		}
		if entry.AccountID == "" {
			return errors.New("settlement_receipt: ledger entry account_id is required")
		}
		if entry.Direction != SettlementDebit && entry.Direction != SettlementCredit {
			return errors.New("settlement_receipt: ledger entry direction must be DEBIT or CREDIT")
		}
		if entry.AmountCents <= 0 {
			return errors.New("settlement_receipt: ledger entry amount_cents must be positive")
		}
		if entry.Currency != s.Currency {
			return errors.New("settlement_receipt: ledger entry currency must match settlement currency")
		}
	}
	if !s.Balanced() {
		return errors.New("settlement_receipt: ledger entries are not balanced")
	}
	return nil
}

func (s *SettlementReceipt) computeHash() string {
	return hashSpendAuthorityCanonical(struct {
		ID                     string                  `json:"id"`
		TenantID               string                  `json:"tenant_id"`
		UsageReceiptID         string                  `json:"usage_receipt_id"`
		RouteQuoteID           string                  `json:"route_quote_id"`
		TreasuryAccountID      string                  `json:"treasury_account_id"`
		SourceUsageReceiptHash string                  `json:"source_usage_receipt_hash"`
		LedgerEntries          []SettlementLedgerEntry `json:"ledger_entries"`
		Currency               string                  `json:"currency"`
		EvidencePackRef        string                  `json:"evidence_pack_ref"`
	}{s.ID, s.TenantID, s.UsageReceiptID, s.RouteQuoteID, s.TreasuryAccountID, s.SourceUsageReceiptHash, s.LedgerEntries, s.Currency, s.EvidencePackRef})
}

func hashSpendAuthorityCanonical(value any) string {
	canon, _ := json.Marshal(value)
	h := sha256.Sum256(canon)
	return "sha256:" + hex.EncodeToString(h[:])
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
