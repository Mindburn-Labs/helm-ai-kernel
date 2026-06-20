// spend_receipt_views.go renders the SPEND3/5 spend receipts (RouteQuote,
// BudgetVerdictReceipt, UsageReceipt, SettlementReceipt) into business-readable
// VIEWS so a non-engineer can answer six questions about any spend:
//
//	who proposed / approved it    -> AgentID / PrincipalID / Approvers
//	which policy governed it       -> RoutePolicyHash / PolicyHash
//	which data was involved        -> RequestedModelID + content hashes (NOT the prompt body)
//	what actually happened         -> verdict + requested/selected route + fallback
//	how much it cost               -> quoted / actual / provider cost / platform fee / debit
//	what proves it                 -> receipt ContentHash + EvidencePackRef
//
// These views are a presentation layer over the source-owned receipts: they add
// no new financial truth and recompute nothing. The receipts already store only
// hashes + metadata for sensitive payloads, so a view can never surface a prompt
// body. The RedactionProfile makes that guarantee explicit and enforceable for
// the free-form Metadata maps that ride along on RouteQuote / UsageReceipt.
package economic

import (
	"sort"
	"strings"
)

// SpendReceiptKind identifies which spend receipt a view was rendered from. The
// values double as ProofGraph/EvidencePack node labels so a business view maps
// cleanly onto the kernel's attestation node taxonomy.
type SpendReceiptKind string

const (
	SpendReceiptKindRoute      SpendReceiptKind = "ROUTE_RECEIPT"
	SpendReceiptKindBudget     SpendReceiptKind = "BUDGET_VERDICT_RECEIPT"
	SpendReceiptKindUsage      SpendReceiptKind = "USAGE_RECEIPT"
	SpendReceiptKindSettlement SpendReceiptKind = "SETTLEMENT_RECEIPT"
)

// RedactionProfile controls which fields are allowed to cross from the spend
// receipts into a business graph / EvidencePack. The default profile keeps the
// prompt body OFF-graph: receipts only ever carry hashes + metadata, and this
// profile additionally strips any metadata key that could smuggle prompt text
// (or other sensitive payloads) through the free-form Metadata maps.
//
// The contract is fail-closed for prompt bodies: with RedactPromptBody=true
// (the default) any metadata key flagged as prompt-bearing is dropped before it
// reaches a view, so the business graph stores hashes + metadata only.
type RedactionProfile struct {
	// Name identifies the profile in audit output.
	Name string `json:"name"`
	// RedactPromptBody drops prompt-bearing metadata keys. Default profile: true.
	RedactPromptBody bool `json:"redact_prompt_body"`
	// DeniedMetadataKeys are dropped from every view's metadata (case-insensitive).
	DeniedMetadataKeys []string `json:"denied_metadata_keys,omitempty"`
	// DeniedMetadataSubstrings drop any metadata key containing the substring
	// (case-insensitive), catching variants like "prompt", "prompt_text",
	// "messages", "completion_body" without enumerating every key.
	DeniedMetadataSubstrings []string `json:"denied_metadata_substrings,omitempty"`
}

// DefaultRedactionProfile returns the launch-default profile: prompt body stays
// off-graph. This is the profile the business views use unless a caller opts
// into a wider profile for an internal, access-controlled surface.
func DefaultRedactionProfile() RedactionProfile {
	return RedactionProfile{
		Name:             "default-prompt-off-graph",
		RedactPromptBody: true,
		DeniedMetadataKeys: []string{
			"prompt", "prompt_body", "prompt_text", "input", "input_body",
			"messages", "completion", "completion_body", "output_text",
			"system_prompt", "user_message", "request_body", "response_body",
		},
		DeniedMetadataSubstrings: []string{
			"prompt", "message", "completion", "_body", "payload", "transcript",
		},
	}
}

// redactedKey reports whether a metadata key must be dropped under the profile.
func (p RedactionProfile) redactedKey(key string) bool {
	lk := strings.ToLower(strings.TrimSpace(key))
	for _, denied := range p.DeniedMetadataKeys {
		if lk == strings.ToLower(denied) {
			return true
		}
	}
	if p.RedactPromptBody {
		for _, sub := range p.DeniedMetadataSubstrings {
			if sub != "" && strings.Contains(lk, strings.ToLower(sub)) {
				return true
			}
		}
	}
	return false
}

// redactMetadata returns a copy of md with denied keys removed and a sorted,
// deterministic list of the keys that were redacted (for the audit trail).
func (p RedactionProfile) redactMetadata(md map[string]string) (map[string]string, []string) {
	if len(md) == 0 {
		return nil, nil
	}
	out := make(map[string]string, len(md))
	var redacted []string
	for k, v := range md {
		if p.redactedKey(k) {
			redacted = append(redacted, k)
			continue
		}
		out[k] = v
	}
	if len(out) == 0 {
		out = nil
	}
	sort.Strings(redacted)
	return out, redacted
}

// RouteHop is one provider/model option in a business-readable fallback chain.
type RouteHop struct {
	ProviderID        string `json:"provider_id"`
	ModelID           string `json:"model_id"`
	PriceSnapshotHash string `json:"price_snapshot_hash"`
}

// RouteReceiptView answers "what did the router propose and why" for a RouteQuote.
type RouteReceiptView struct {
	Kind SpendReceiptKind `json:"kind"`

	// Who
	TenantID    string `json:"tenant_id"`
	AgentID     string `json:"agent_id"`
	PrincipalID string `json:"principal_id,omitempty"`

	// What happened (route)
	RequestedProviderID string     `json:"requested_provider_id,omitempty"`
	RequestedModelID    string     `json:"requested_model_id"`
	SelectedProviderID  string     `json:"selected_provider_id"`
	SelectedModelID     string     `json:"selected_model_id"`
	ModelSubstituted    bool       `json:"model_substituted"`
	FallbackChain       []RouteHop `json:"fallback_chain,omitempty"`
	Verdict             string     `json:"verdict"`
	ReasonCode          string     `json:"reason_code"`

	// How much (quote)
	QuotedAmountCents int64  `json:"quoted_amount_cents"`
	MaxAmountCents    int64  `json:"max_amount_cents"`
	Currency          string `json:"currency"`

	// Which policy / which data (hashes only)
	RoutePolicyHash           string `json:"route_policy_hash"`
	ProviderPriceSnapshotHash string `json:"provider_price_snapshot_hash"`

	// What proves it
	ContentHash string `json:"content_hash"`

	// Audit of redaction
	Metadata        map[string]string `json:"metadata,omitempty"`
	RedactedFields  []string          `json:"redacted_fields,omitempty"`
	RedactionPolicy string            `json:"redaction_policy"`
}

// BudgetVerdictView answers "who approved, under which policy" for a verdict.
type BudgetVerdictView struct {
	Kind SpendReceiptKind `json:"kind"`

	// Who
	TenantID    string   `json:"tenant_id"`
	AgentID     string   `json:"agent_id"`
	PrincipalID string   `json:"principal_id,omitempty"`
	Approvers   []string `json:"approvers,omitempty"`

	// What happened (decision)
	Verdict        string `json:"verdict"` // ALLOW / DENY / ESCALATE
	ReasonCode     string `json:"reason_code"`
	ProviderID     string `json:"provider_id"`
	ModelID        string `json:"model_id"`
	ApprovalNeeded bool   `json:"approval_needed"`

	// How much
	QuotedAmountCents int64  `json:"quoted_amount_cents"`
	MaxAmountCents    int64  `json:"max_amount_cents"`
	Currency          string `json:"currency"`

	// Which policy / envelope (hashes only)
	EnvelopeHash    string `json:"envelope_hash,omitempty"`
	RoutePolicyHash string `json:"route_policy_hash"`
	DecisionHash    string `json:"decision_hash"`

	// What proves it
	ContentHash     string `json:"content_hash"`
	EvidencePackRef string `json:"evidence_pack_ref"`
	SignatureKeyID  string `json:"signature_key_id,omitempty"`

	RedactionPolicy string `json:"redaction_policy"`
}

// UsageReceiptView answers "what actually happened and how much" post-dispatch.
type UsageReceiptView struct {
	Kind SpendReceiptKind `json:"kind"`

	// Who
	TenantID string `json:"tenant_id"`
	AgentID  string `json:"agent_id"`

	// What happened
	ProviderID        string `json:"provider_id"`
	ModelID           string `json:"model_id"`
	ProviderRequestID string `json:"provider_request_id,omitempty"`
	Verdict           string `json:"verdict"`
	ReasonCode        string `json:"reason_code"`

	// How much (full cost breakdown)
	QuotedAmountCents int64  `json:"quoted_amount_cents"`
	ActualAmountCents int64  `json:"actual_amount_cents"`
	ProviderCostCents int64  `json:"provider_cost_cents"`
	PlatformFeeCents  int64  `json:"platform_fee_cents"`
	BalanceDebitCents int64  `json:"balance_debit_cents"`
	Currency          string `json:"currency"`
	// SettledVia tells a business reader whether the spend hit a prepaid balance
	// or accrued to an invoice. Derived from the presence of a balance debit.
	SettledVia string `json:"settled_via"` // "BALANCE_DEBIT" or "INVOICE_ACCRUAL"

	// Which policy / which data (hashes only)
	PolicyHash                string `json:"policy_hash"`
	ProviderPriceSnapshotHash string `json:"provider_price_snapshot_hash"`

	// What proves it
	ContentHash           string `json:"content_hash"`
	SettlementReceiptHash string `json:"settlement_receipt_hash,omitempty"`
	EvidencePackRef       string `json:"evidence_pack_ref"`

	Metadata        map[string]string `json:"metadata,omitempty"`
	RedactedFields  []string          `json:"redacted_fields,omitempty"`
	RedactionPolicy string            `json:"redaction_policy"`
}

// LedgerMovementView is one business-readable double-entry movement.
type LedgerMovementView struct {
	AccountID   string `json:"account_id"`
	Direction   string `json:"direction"` // DEBIT / CREDIT
	AmountCents int64  `json:"amount_cents"`
	Currency    string `json:"currency"`
	Reference   string `json:"reference,omitempty"`
}

// SettlementReceiptView answers "what moved on the ledger and what proves it".
type SettlementReceiptView struct {
	Kind SpendReceiptKind `json:"kind"`

	TenantID          string `json:"tenant_id"`
	TreasuryAccountID string `json:"treasury_account_id"`

	// What moved
	LedgerMovements []LedgerMovementView `json:"ledger_movements"`
	TotalDebits     int64                `json:"total_debits_cents"`
	TotalCredits    int64                `json:"total_credits_cents"`
	Currency        string               `json:"currency"`
	Balanced        bool                 `json:"balanced"`

	// Links / correction references
	UsageReceiptID         string `json:"usage_receipt_id"`
	SourceUsageReceiptHash string `json:"source_usage_receipt_hash"`

	// What proves it
	ContentHash     string `json:"content_hash"`
	EvidencePackRef string `json:"evidence_pack_ref"`

	RedactionPolicy string `json:"redaction_policy"`
}

// NewRouteReceiptView renders a RouteQuote into a business-readable view under
// the given redaction profile. The prompt body never appears: only the model
// id, hashes, and redacted metadata cross into the view.
func NewRouteReceiptView(q *RouteQuote, profile RedactionProfile) RouteReceiptView {
	if q == nil {
		return RouteReceiptView{Kind: SpendReceiptKindRoute, RedactionPolicy: profile.Name}
	}
	md, redacted := profile.redactMetadata(q.Metadata)
	chain := make([]RouteHop, 0, len(q.FallbackChain))
	for _, hop := range q.FallbackChain {
		chain = append(chain, RouteHop{
			ProviderID:        hop.ProviderID,
			ModelID:           hop.ModelID,
			PriceSnapshotHash: hop.PriceSnapshotHash,
		})
	}
	return RouteReceiptView{
		Kind:                      SpendReceiptKindRoute,
		TenantID:                  q.TenantID,
		AgentID:                   q.AgentID,
		PrincipalID:               q.PrincipalID,
		RequestedProviderID:       q.RequestedProviderID,
		RequestedModelID:          q.RequestedModelID,
		SelectedProviderID:        q.SelectedProviderID,
		SelectedModelID:           q.SelectedModelID,
		ModelSubstituted:          q.ModelSubstituted,
		FallbackChain:             chain,
		Verdict:                   string(q.BudgetVerdict),
		ReasonCode:                string(q.ReasonCode),
		QuotedAmountCents:         q.QuotedAmountCents,
		MaxAmountCents:            q.MaxAmountCents,
		Currency:                  q.Currency,
		RoutePolicyHash:           q.RoutePolicyHash,
		ProviderPriceSnapshotHash: q.ProviderPriceSnapshotHash,
		ContentHash:               q.ContentHash,
		Metadata:                  md,
		RedactedFields:            redacted,
		RedactionPolicy:           profile.Name,
	}
}

// NewBudgetVerdictView renders a BudgetVerdictReceipt into a business view.
// approvers may be nil for an ALLOW; for ESCALATE it carries the required
// approver roles/ids so a business reader can answer "who must approve".
func NewBudgetVerdictView(r *BudgetVerdictReceipt, approvers []string, profile RedactionProfile) BudgetVerdictView {
	if r == nil {
		return BudgetVerdictView{Kind: SpendReceiptKindBudget, RedactionPolicy: profile.Name}
	}
	return BudgetVerdictView{
		Kind:              SpendReceiptKindBudget,
		TenantID:          r.TenantID,
		AgentID:           r.AgentID,
		PrincipalID:       r.PrincipalID,
		Approvers:         append([]string(nil), approvers...),
		Verdict:           string(r.BudgetVerdict),
		ReasonCode:        string(r.ReasonCode),
		ProviderID:        r.ProviderID,
		ModelID:           r.ModelID,
		ApprovalNeeded:    r.BudgetVerdict == BudgetVerdictEscalate,
		QuotedAmountCents: r.QuotedAmountCents,
		MaxAmountCents:    r.MaxAmountCents,
		Currency:          r.Currency,
		EnvelopeHash:      r.EnvelopeHash,
		RoutePolicyHash:   r.RoutePolicyHash,
		DecisionHash:      r.DecisionHash,
		ContentHash:       r.ContentHash,
		EvidencePackRef:   r.EvidencePackRef,
		SignatureKeyID:    r.SignatureKeyID,
		RedactionPolicy:   profile.Name,
	}
}

// NewUsageReceiptView renders a UsageReceipt into a business view.
func NewUsageReceiptView(r *UsageReceipt, profile RedactionProfile) UsageReceiptView {
	if r == nil {
		return UsageReceiptView{Kind: SpendReceiptKindUsage, RedactionPolicy: profile.Name}
	}
	md, redacted := profile.redactMetadata(r.Metadata)
	settledVia := "INVOICE_ACCRUAL"
	if r.BalanceDebitCents > 0 {
		settledVia = "BALANCE_DEBIT"
	}
	return UsageReceiptView{
		Kind:                      SpendReceiptKindUsage,
		TenantID:                  r.TenantID,
		AgentID:                   r.AgentID,
		ProviderID:                r.ProviderID,
		ModelID:                   r.ModelID,
		ProviderRequestID:         r.ProviderRequestID,
		Verdict:                   string(r.BudgetVerdict),
		ReasonCode:                string(r.ReasonCode),
		QuotedAmountCents:         r.QuotedAmountCents,
		ActualAmountCents:         r.ActualAmountCents,
		ProviderCostCents:         r.ProviderCostCents,
		PlatformFeeCents:          r.PlatformFeeCents,
		BalanceDebitCents:         r.BalanceDebitCents,
		Currency:                  r.Currency,
		SettledVia:                settledVia,
		PolicyHash:                r.PolicyHash,
		ProviderPriceSnapshotHash: r.ProviderPriceSnapshotHash,
		ContentHash:               r.ContentHash,
		SettlementReceiptHash:     r.SettlementReceiptHash,
		EvidencePackRef:           r.EvidencePackRef,
		Metadata:                  md,
		RedactedFields:            redacted,
		RedactionPolicy:           profile.Name,
	}
}

// NewSettlementReceiptView renders a SettlementReceipt into a business view,
// summing debits and credits so a business reader sees the net ledger movement.
func NewSettlementReceiptView(s *SettlementReceipt, profile RedactionProfile) SettlementReceiptView {
	if s == nil {
		return SettlementReceiptView{Kind: SpendReceiptKindSettlement, RedactionPolicy: profile.Name}
	}
	movements := make([]LedgerMovementView, 0, len(s.LedgerEntries))
	var debits, credits int64
	for _, e := range s.LedgerEntries {
		movements = append(movements, LedgerMovementView{
			AccountID:   e.AccountID,
			Direction:   string(e.Direction),
			AmountCents: e.AmountCents,
			Currency:    e.Currency,
			Reference:   e.Reference,
		})
		switch e.Direction {
		case SettlementDebit:
			debits += e.AmountCents
		case SettlementCredit:
			credits += e.AmountCents
		}
	}
	return SettlementReceiptView{
		Kind:                   SpendReceiptKindSettlement,
		TenantID:               s.TenantID,
		TreasuryAccountID:      s.TreasuryAccountID,
		LedgerMovements:        movements,
		TotalDebits:            debits,
		TotalCredits:           credits,
		Currency:               s.Currency,
		Balanced:               s.Balanced(),
		UsageReceiptID:         s.UsageReceiptID,
		SourceUsageReceiptHash: s.SourceUsageReceiptHash,
		ContentHash:            s.ContentHash,
		EvidencePackRef:        s.EvidencePackRef,
		RedactionPolicy:        profile.Name,
	}
}
