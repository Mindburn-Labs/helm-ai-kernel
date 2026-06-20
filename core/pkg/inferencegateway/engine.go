package inferencegateway

import (
	"errors"
	"fmt"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/economic"
)

// StalePricePolicy decides what the engine does when the selected provider's
// price snapshot is stale at quote time.
type StalePricePolicy string

const (
	// StalePriceFailClosed denies the quote outright (default, fail-closed).
	StalePriceFailClosed StalePricePolicy = "FAIL_CLOSED"
	// StalePriceEscalate emits an ESCALATE verdict so an approver can intervene.
	StalePriceEscalate StalePricePolicy = "ESCALATE"
)

// CostCapPolicy decides what the engine does when actual cost exceeds the
// quote's max ceiling at settlement time.
type CostCapPolicy string

const (
	// CostCapClamp debits at the max ceiling and never above it.
	CostCapClamp CostCapPolicy = "CAP"
	// CostCapEscalate refuses to settle and surfaces an ESCALATE outcome.
	CostCapEscalate CostCapPolicy = "ESCALATE"
)

// Clock is injectable for deterministic expiry tests.
type Clock func() time.Time

// EngineConfig configures the RouteQuote engine.
type EngineConfig struct {
	Prices         PriceProvider
	Terms          TermsProvider
	Ledger         *BalanceLedger
	TreasuryID     string
	RoutePolicyID  string // route policy identity, hashed into RoutePolicyHash
	QuoteTTL       time.Duration
	StalePrice     StalePricePolicy
	CostCap        CostCapPolicy
	PlatformFeeBps int64 // platform fee in basis points of provider cost
	Now            Clock
}

// Engine is the RouteQuote engine. It is safe for concurrent use because its
// only mutable state (the BalanceLedger) is internally synchronized.
type Engine struct {
	cfg             EngineConfig
	routePolicyHash string
}

// RouteRequest is one governed inference request mapped onto the engine.
type RouteRequest struct {
	TenantID         string
	WorkspaceID      string
	AgentID          string
	PrincipalID      string
	IdempotencyKey   string
	RequestedModelID string
	// EstimatedInputTokens / EstimatedOutputTokens drive the pre-dispatch quote.
	EstimatedInputTokens  int64
	EstimatedOutputTokens int64
}

// QuoteResult is the pre-dispatch outcome.
type QuoteResult struct {
	Decision         economic.SpendAuthorityDecision
	Quote            *economic.RouteQuote
	Receipt          *economic.BudgetVerdictReceipt
	PriceSnapshot    *economic.ProviderPriceSnapshot
	ModelSubstituted bool
	FallbackUsed     bool
	EvidencePackRef  string
}

// SettleResult is the post-dispatch outcome.
type SettleResult struct {
	UsageReceipt      *economic.UsageReceipt
	SettlementReceipt *economic.SettlementReceipt
	Capped            bool
	Escalated         bool
	ReasonCode        economic.SpendReasonCode
	QuotedAmountCents int64
	ActualAmountCents int64
	BalanceDebitCents int64
	BalanceAfterCents int64
	Replayed          bool
	EvidencePackRef   string
}

// QuoteError carries a fail-closed verdict for callers that must translate it
// to an HTTP status while still surfacing the governed reason code.
type QuoteError struct {
	Verdict    economic.BudgetVerdict
	ReasonCode economic.SpendReasonCode
	Message    string
}

func (e *QuoteError) Error() string {
	if e == nil {
		return "inferencegateway: nil quote error"
	}
	return fmt.Sprintf("inferencegateway: %s/%s: %s", e.Verdict, e.ReasonCode, e.Message)
}

func quoteErr(verdict economic.BudgetVerdict, code economic.SpendReasonCode, msg string) *QuoteError {
	return &QuoteError{Verdict: verdict, ReasonCode: code, Message: msg}
}

// NewEngine validates configuration and returns a ready engine.
func NewEngine(cfg EngineConfig) (*Engine, error) {
	if cfg.Prices == nil {
		return nil, errors.New("inferencegateway: price provider is required")
	}
	if cfg.Terms == nil {
		return nil, errors.New("inferencegateway: terms provider is required")
	}
	if cfg.Ledger == nil {
		return nil, errors.New("inferencegateway: balance ledger is required")
	}
	if cfg.TreasuryID == "" {
		return nil, errors.New("inferencegateway: treasury id is required")
	}
	if cfg.RoutePolicyID == "" {
		return nil, errors.New("inferencegateway: route policy id is required")
	}
	if cfg.QuoteTTL <= 0 {
		cfg.QuoteTTL = 30 * time.Second
	}
	if cfg.StalePrice == "" {
		cfg.StalePrice = StalePriceFailClosed
	}
	if cfg.CostCap == "" {
		cfg.CostCap = CostCapClamp
	}
	if cfg.PlatformFeeBps < 0 {
		return nil, errors.New("inferencegateway: platform fee bps cannot be negative")
	}
	if cfg.Now == nil {
		cfg.Now = func() time.Time { return time.Now().UTC() }
	}
	return &Engine{
		cfg:             cfg,
		routePolicyHash: hashRoutePolicy(cfg.RoutePolicyID, cfg.QuoteTTL, cfg.StalePrice, cfg.CostCap, cfg.PlatformFeeBps),
	}, nil
}

// RoutePolicyHash exposes the deterministic policy hash bound into every quote.
func (e *Engine) RoutePolicyHash() string { return e.routePolicyHash }

// Quote runs route selection and the pre-dispatch spend verdict. It creates the
// expiring RouteQuote BEFORE any provider dispatch. A non-ALLOW verdict yields a
// *QuoteError so no dispatch can proceed; the quote is still returned for
// receipt/escalation purposes.
//
// env is the caller-resolved AgentSpendEnvelope for the request scope; the
// engine re-validates it here and fails closed on any mismatch.
func (e *Engine) Quote(env *economic.AgentSpendEnvelope, req RouteRequest) (*QuoteResult, error) {
	if env == nil {
		return nil, quoteErr(economic.BudgetVerdictDeny, economic.SpendReasonEnvelopeNotFound, "spend envelope is required")
	}
	if err := env.Validate(); err != nil {
		return nil, quoteErr(economic.BudgetVerdictDeny, economic.SpendReasonEnvelopeNotFound, err.Error())
	}
	if req.IdempotencyKey == "" {
		return nil, quoteErr(economic.BudgetVerdictDeny, economic.SpendReasonReceiptMismatch, "idempotency key is required")
	}
	if req.TenantID != env.TenantID || req.AgentID != env.AgentID {
		return nil, quoteErr(economic.BudgetVerdictDeny, economic.SpendReasonEnvelopeNotFound, "request scope does not match spend envelope")
	}
	if req.RequestedModelID == "" {
		return nil, quoteErr(economic.BudgetVerdictDeny, economic.SpendReasonModelNotAllowed, "requested model is required")
	}
	if req.EstimatedInputTokens < 0 || req.EstimatedOutputTokens < 0 {
		return nil, quoteErr(economic.BudgetVerdictDeny, economic.SpendReasonInvalidAmount, "estimated token counts cannot be negative")
	}

	now := e.cfg.Now()
	route, fallbackChain, substituted, fallbackUsed, rerr := e.selectRoute(env, req)
	if rerr != nil {
		return nil, rerr
	}

	snapshot, ok := e.cfg.Prices.Snapshot(route.ProviderID, route.ModelID)
	if !ok {
		return nil, quoteErr(economic.BudgetVerdictDeny, economic.SpendReasonProviderPriceStale, "no provider price snapshot for selected route")
	}
	if err := snapshot.Validate(); err != nil {
		return nil, quoteErr(economic.BudgetVerdictDeny, economic.SpendReasonProviderPriceStale, err.Error())
	}

	// Fail-closed (or escalate) on a stale provider price snapshot.
	if snapshot.Stale(now) {
		if e.cfg.StalePrice == StalePriceEscalate {
			return nil, quoteErr(economic.BudgetVerdictEscalate, economic.SpendReasonProviderPriceStale, "provider price snapshot is stale; escalating")
		}
		return nil, quoteErr(economic.BudgetVerdictDeny, economic.SpendReasonProviderPriceStale, "provider price snapshot is stale; failing closed")
	}

	// Terms block before dispatch: provider must have a reviewed, valid terms
	// profile whose id matches the price snapshot's bound profile.
	terms, ok := e.cfg.Terms.Terms(route.ProviderID)
	if !ok {
		return nil, quoteErr(economic.BudgetVerdictDeny, economic.SpendReasonProviderContractNeeded, "provider terms profile is required before dispatch")
	}
	if err := terms.Validate(); err != nil {
		return nil, quoteErr(economic.BudgetVerdictDeny, economic.SpendReasonProviderContractNeeded, err.Error())
	}
	if snapshot.ProviderTermsProfileID != terms.ID {
		return nil, quoteErr(economic.BudgetVerdictDeny, economic.SpendReasonProviderContractNeeded, "price snapshot is not bound to the reviewed terms profile")
	}

	quotedCents, err := snapshot.QuoteCents(req.EstimatedInputTokens, req.EstimatedOutputTokens)
	if err != nil {
		return nil, quoteErr(economic.BudgetVerdictDeny, economic.SpendReasonInvalidAmount, err.Error())
	}
	// Max ceiling: the route's explicit cap when set, else the quoted amount.
	maxCents := quotedCents
	if route.MaxAmountCents > 0 {
		maxCents = route.MaxAmountCents
		if quotedCents > maxCents {
			return nil, quoteErr(economic.BudgetVerdictDeny, economic.SpendReasonPerRequestLimit, "quoted cost exceeds route max ceiling")
		}
	}

	decision := env.EvaluateSpend(maxCents, route.ProviderID, route.ModelID)
	evidenceRef := evidencePackRef(req.TenantID, req.IdempotencyKey, snapshot.ContentHash)
	intentID := spendIntentID(req.TenantID, req.IdempotencyKey)

	quote := economic.NewRouteQuote(
		quoteID(req.TenantID, req.IdempotencyKey), env.TenantID, intentID, env.ID, env.AgentID,
		route, quotedCents, maxCents, env.Currency, e.routePolicyHash,
		now.Add(e.cfg.QuoteTTL), decision,
	)
	quote.PrincipalID = req.PrincipalID
	quote.RequestedModelID = req.RequestedModelID
	quote.InputTokens = req.EstimatedInputTokens
	quote.OutputTokens = req.EstimatedOutputTokens
	quote.ModelSubstituted = substituted
	if substituted || fallbackUsed {
		quote.FallbackChain = fallbackChain
	}
	quote.CreatedAt = now
	quote.ExpiresAt = now.Add(e.cfg.QuoteTTL)
	quote.Metadata = map[string]string{"evidence_pack_ref": evidenceRef}
	if req.WorkspaceID != "" {
		quote.Metadata["workspace_id"] = req.WorkspaceID
	}
	quote.Reseal()

	if err := quote.Validate(); err != nil {
		return nil, quoteErr(economic.BudgetVerdictDeny, decision.ReasonCode, err.Error())
	}

	result := &QuoteResult{
		Decision:         decision,
		Quote:            quote,
		PriceSnapshot:    snapshot,
		ModelSubstituted: substituted,
		FallbackUsed:     fallbackUsed,
		EvidencePackRef:  evidenceRef,
	}

	// A non-ALLOW verdict is terminal: no signed dispatch receipt is issued and
	// no dispatch may proceed.
	if decision.Verdict != economic.BudgetVerdictAllow {
		return result, quoteErr(decision.Verdict, decision.ReasonCode, decision.Reason)
	}

	receipt := economic.NewBudgetVerdictReceipt(
		receiptID(req.TenantID, req.IdempotencyKey), env.TenantID, intentID, env.ID, env.AgentID,
		route.ProviderID, route.ModelID, quotedCents, maxCents, env.Currency,
		snapshot.ContentHash, e.routePolicyHash, evidenceRef, decision,
	)
	receipt.PrincipalID = req.PrincipalID
	// PrincipalID is part of the receipt's canonical hash, so reseal after
	// setting it; otherwise the stored ContentHash (computed pre-PrincipalID)
	// would not match the receipt body and the receipt would fail offline
	// canonical-hash verification. Bind the quote to the resealed hash.
	receipt.Reseal()
	quote.ReceiptHash = receipt.ContentHash
	quote.Reseal()
	result.Receipt = receipt
	return result, nil
}

// Settle records actual provider usage after dispatch, enforces quote expiry
// and the cost ceiling, posts the idempotent balanced debit, and returns the
// usage + settlement receipts. A replay of the same idempotency key (carried by
// the quote's spend intent) returns the committed receipts without debiting
// again.
func (e *Engine) Settle(
	quote *economic.RouteQuote,
	providerRequestID string,
	providerCostCents int64,
	actualInputTokens, actualOutputTokens int64,
) (*SettleResult, error) {
	if quote == nil {
		return nil, errors.New("inferencegateway: route quote is required to settle")
	}
	if err := quote.Validate(); err != nil {
		return nil, fmt.Errorf("inferencegateway: route quote invalid: %w", err)
	}
	idem := idempotencyFromIntent(quote.SpendIntentID)

	// Idempotent replay short-circuit: same key, same committed outcome.
	if rec, ok := e.cfg.Ledger.Lookup(idem); ok {
		return replayResult(rec), nil
	}

	now := e.cfg.Now()
	if quote.Expired(now) {
		return &SettleResult{ReasonCode: economic.SpendReasonRouteQuoteExpired},
			quoteErr(economic.BudgetVerdictDeny, economic.SpendReasonRouteQuoteExpired, "route quote expired before settlement")
	}
	if providerRequestID == "" {
		return nil, errors.New("inferencegateway: provider_request_id is required to settle")
	}
	if providerCostCents < 0 {
		return nil, errors.New("inferencegateway: provider cost cannot be negative")
	}

	platformFee := (providerCostCents * e.cfg.PlatformFeeBps) / 10_000
	actual := providerCostCents + platformFee

	capped := false
	// Enforce the quote ceiling: cap the debit or escalate per policy.
	if actual > quote.MaxAmountCents {
		if e.cfg.CostCap == CostCapEscalate {
			return &SettleResult{
					Escalated:         true,
					ReasonCode:        economic.SpendReasonPerRequestLimit,
					QuotedAmountCents: quote.QuotedAmountCents,
					ActualAmountCents: actual,
				},
				quoteErr(economic.BudgetVerdictEscalate, economic.SpendReasonPerRequestLimit, "actual cost exceeds quote ceiling; escalating")
		}
		// CostCapClamp: re-derive provider cost / fee so the receipt's internal
		// arithmetic (actual == provider + fee) stays exact at the ceiling.
		capped = true
		actual = quote.MaxAmountCents
		platformFee = (actual * e.cfg.PlatformFeeBps) / (10_000 + e.cfg.PlatformFeeBps)
		providerCostCents = actual - platformFee
	}

	usage := economic.NewUsageReceipt(
		usageReceiptID(quote.TenantID, idem), quote.TenantID, quote.ID, quote.SpendIntentID,
		quote.EnvelopeID, quote.AgentID, quote.SelectedProviderID, quote.SelectedModelID,
		quote.QuotedAmountCents, providerCostCents, platformFee, quote.Currency,
		e.routePolicyHash, e.quoteEvidenceRef(quote),
	)
	usage.ProviderRequestID = providerRequestID
	usage.ProviderPriceSnapshotHash = quote.ProviderPriceSnapshotHash
	usage.InputTokens = actualInputTokens
	usage.OutputTokens = actualOutputTokens

	settlement := e.buildSettlement(quote, usage)
	usage.LedgerEntryIDs = settlementEntryIDs(settlement)
	usage.SettlementReceiptHash = settlement.ContentHash
	usage.Reseal()
	settlement.SourceUsageReceiptHash = usage.ContentHash
	settlement.Reseal()

	// Drop any dispatch reservation for this quote so its hold is not
	// double-counted against the actual debit that follows. No-op when the
	// caller did not pre-reserve.
	e.cfg.Ledger.consumeReservationForDebit(quote.ID)

	rec, err := e.cfg.Ledger.commit(idem, usage, settlement)
	if err != nil {
		return nil, err
	}

	return &SettleResult{
		UsageReceipt:      rec.UsageReceipt,
		SettlementReceipt: rec.SettlementReceipt,
		Capped:            capped,
		ReasonCode:        rec.UsageReceipt.ReasonCode,
		QuotedAmountCents: rec.UsageReceipt.QuotedAmountCents,
		ActualAmountCents: rec.UsageReceipt.ActualAmountCents,
		BalanceDebitCents: rec.BalanceDebitCents,
		BalanceAfterCents: rec.BalanceAfterCents,
		EvidencePackRef:   rec.UsageReceipt.EvidencePackRef,
	}, nil
}

func replayResult(rec *SettlementRecord) *SettleResult {
	return &SettleResult{
		UsageReceipt:      rec.UsageReceipt,
		SettlementReceipt: rec.SettlementReceipt,
		ReasonCode:        rec.UsageReceipt.ReasonCode,
		QuotedAmountCents: rec.UsageReceipt.QuotedAmountCents,
		ActualAmountCents: rec.UsageReceipt.ActualAmountCents,
		BalanceDebitCents: rec.BalanceDebitCents,
		BalanceAfterCents: rec.BalanceAfterCents,
		Replayed:          true,
		EvidencePackRef:   rec.UsageReceipt.EvidencePackRef,
	}
}

// selectRoute resolves the requested model against the envelope allow-list and
// the fallback chain. Substitution is explicit: when the requested model is not
// directly allowed, the first allowed fallback wins and substituted is true.
func (e *Engine) selectRoute(env *economic.AgentSpendEnvelope, req RouteRequest) (economic.ModelRoute, []economic.ModelRoute, bool, bool, *QuoteError) {
	chain := env.FallbackModels

	// Direct hit: requested model is allowed and a snapshot exists for it under
	// one of the allowed providers.
	if env.AllowsModel(req.RequestedModelID) {
		if route, ok := e.resolveAllowedProvider(env, req.RequestedModelID); ok {
			return route, chain, false, false, nil
		}
	}

	// Substitution path: requires the envelope to permit substitution and a
	// fallback chain of allowed provider/model routes with live snapshots.
	if !env.AllowModelSubstitution {
		return economic.ModelRoute{}, nil, false, false,
			quoteErr(economic.BudgetVerdictDeny, economic.SpendReasonModelNotAllowed, "requested model is not allowed and substitution is disabled")
	}
	for _, candidate := range chain {
		if candidate.ProviderID == "" || candidate.ModelID == "" {
			continue
		}
		if !env.AllowsProvider(candidate.ProviderID) || !env.AllowsModel(candidate.ModelID) {
			continue
		}
		if _, ok := e.cfg.Prices.Snapshot(candidate.ProviderID, candidate.ModelID); !ok {
			continue
		}
		substituted := candidate.ModelID != req.RequestedModelID
		return candidate, chain, substituted, true, nil
	}
	return economic.ModelRoute{}, nil, false, false,
		quoteErr(economic.BudgetVerdictDeny, economic.SpendReasonModelNotAllowed, "no allowed fallback route satisfies the request")
}

// resolveAllowedProvider finds an allowed provider that has a price snapshot for
// the model, preferring providers named in the fallback chain.
func (e *Engine) resolveAllowedProvider(env *economic.AgentSpendEnvelope, modelID string) (economic.ModelRoute, bool) {
	for _, candidate := range env.FallbackModels {
		if candidate.ModelID != modelID || !env.AllowsProvider(candidate.ProviderID) {
			continue
		}
		if _, ok := e.cfg.Prices.Snapshot(candidate.ProviderID, modelID); ok {
			return candidate, true
		}
	}
	for _, providerID := range env.AllowedProviders {
		if _, ok := e.cfg.Prices.Snapshot(providerID, modelID); ok {
			return economic.ModelRoute{ProviderID: providerID, ModelID: modelID}, true
		}
	}
	return economic.ModelRoute{}, false
}

func (e *Engine) buildSettlement(quote *economic.RouteQuote, usage *economic.UsageReceipt) *economic.SettlementReceipt {
	entries := []economic.SettlementLedgerEntry{
		{
			ID:          fmt.Sprintf("sle-%s-debit", usage.ID),
			AccountID:   e.cfg.Ledger.account.ID,
			Direction:   economic.SettlementDebit,
			AmountCents: usage.BalanceDebitCents,
			Currency:    usage.Currency,
			Reference:   "balance:" + e.cfg.Ledger.account.ID,
		},
		{
			ID:          fmt.Sprintf("sle-%s-credit", usage.ID),
			AccountID:   e.cfg.TreasuryID,
			Direction:   economic.SettlementCredit,
			AmountCents: usage.BalanceDebitCents,
			Currency:    usage.Currency,
			Reference:   "treasury:" + e.cfg.TreasuryID,
		},
	}
	return economic.NewSettlementReceipt(
		fmt.Sprintf("settle-%s", usage.ID), usage.TenantID, usage.ID, quote.ID,
		e.cfg.TreasuryID, usage.ContentHash, usage.Currency, usage.EvidencePackRef, entries,
	)
}

func (e *Engine) quoteEvidenceRef(quote *economic.RouteQuote) string {
	if quote.Metadata != nil {
		if ref := quote.Metadata["evidence_pack_ref"]; ref != "" {
			return ref
		}
	}
	return evidencePackRef(quote.TenantID, idempotencyFromIntent(quote.SpendIntentID), quote.ProviderPriceSnapshotHash)
}
