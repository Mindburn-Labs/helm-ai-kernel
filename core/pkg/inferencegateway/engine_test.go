package inferencegateway

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/economic"
)

// fixedClock returns a controllable Clock for deterministic expiry tests.
func fixedClock(t *time.Time) Clock { return func() time.Time { return *t } }

type harness struct {
	engine *Engine
	ledger *BalanceLedger
	prices *MemoryPriceBook
	terms  *MemoryTermsBook
	clock  *time.Time
	env    *economic.AgentSpendEnvelope
	tenant string
	agent  string
	now    time.Time
}

func newHarness(t *testing.T, opts ...func(*EngineConfig)) *harness {
	t.Helper()
	now := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)
	clock := now

	prices := NewMemoryPriceBook()
	if err := prices.Put(buildSnapshot("price-openai-gpt", "openai", "gpt-4o", "terms-openai", "sha256:src-openai", now.Add(-time.Minute), now.Add(time.Hour), 500, 1500)); err != nil {
		t.Fatalf("put openai snapshot: %v", err)
	}
	if err := prices.Put(buildSnapshot("price-anthropic-haiku", "anthropic", "claude-haiku", "terms-anthropic", "sha256:src-anthropic", now.Add(-time.Minute), now.Add(time.Hour), 300, 900)); err != nil {
		t.Fatalf("put anthropic snapshot: %v", err)
	}

	terms := NewMemoryTermsBook()
	if err := terms.Put(economic.NewProviderTermsProfile("terms-openai", "openai", economic.ProviderAccountDirect, "2026-01-01", "legal-1")); err != nil {
		t.Fatalf("put openai terms: %v", err)
	}
	if err := terms.Put(economic.NewProviderTermsProfile("terms-anthropic", "anthropic", economic.ProviderAccountDirect, "2026-01-01", "legal-2")); err != nil {
		t.Fatalf("put anthropic terms: %v", err)
	}

	account := economic.NewBalanceAccount("balance-1", "tenant-1", "USD", 100_000, "evidence://balance-1")
	ledger, err := NewBalanceLedger(account)
	if err != nil {
		t.Fatalf("new ledger: %v", err)
	}

	cfg := EngineConfig{
		Prices:         prices,
		Terms:          terms,
		Ledger:         ledger,
		TreasuryID:     "treasury-1",
		RoutePolicyID:  "route-policy-default",
		QuoteTTL:       30 * time.Second,
		StalePrice:     StalePriceFailClosed,
		CostCap:        CostCapClamp,
		PlatformFeeBps: 1000, // 10%
		Now:            fixedClock(&clock),
	}
	for _, o := range opts {
		o(&cfg)
	}
	eng, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}

	return &harness{
		engine: eng, ledger: ledger, prices: prices, terms: terms,
		clock: &clock, env: buildEnvelope(), tenant: "tenant-1", agent: "agent-1", now: now,
	}
}

// buildSnapshot constructs a validated price snapshot with token pricing.
func buildSnapshot(id, provider, model, termsID, sourceHash string, effective, expires time.Time, inMicro, outMicro int64) *economic.ProviderPriceSnapshot {
	s := economic.NewProviderPriceSnapshot(id, provider, model, "USD", termsID, sourceHash, effective, expires)
	s.InputTokenMicroCents = inMicro
	s.OutputTokenMicroCents = outMicro
	s.ContentHash = ""
	rebuilt := economic.NewProviderPriceSnapshot(id, provider, model, "USD", termsID, sourceHash, effective, expires)
	rebuilt.InputTokenMicroCents = inMicro
	rebuilt.OutputTokenMicroCents = outMicro
	s.ContentHash = rebuilt.ContentHash
	return s
}

func buildEnvelope() *economic.AgentSpendEnvelope {
	env := economic.NewAgentSpendEnvelope("env-1", "tenant-1", "agent-1", "principal-1", "budget-1", "USD", economic.SpendPeriodDaily, 50_000, 10_000, "sha256:policy")
	env.AllowedProviders = []string{"openai", "anthropic"}
	env.AllowedModels = []string{"gpt-4o", "claude-haiku"}
	env.FallbackModels = []economic.ModelRoute{
		{ProviderID: "openai", ModelID: "gpt-4o", PriceSnapshotHash: "sha256:src-openai"},
		{ProviderID: "anthropic", ModelID: "claude-haiku", PriceSnapshotHash: "sha256:src-anthropic"},
	}
	return resealEnvelope(env)
}

func (h *harness) req(idem, model string, in, out int64) RouteRequest {
	return RouteRequest{
		TenantID: h.tenant, WorkspaceID: "ws-1", AgentID: h.agent, PrincipalID: "principal-1",
		IdempotencyKey: idem, RequestedModelID: model,
		EstimatedInputTokens: in, EstimatedOutputTokens: out,
	}
}

func (h *harness) advance(d time.Duration) { *h.clock = h.clock.Add(d) }

// resealEnvelope reconstructs the envelope through the public constructor so its
// ContentHash matches its mutated allow-lists.
func resealEnvelope(e *economic.AgentSpendEnvelope) *economic.AgentSpendEnvelope {
	rebuilt := economic.NewAgentSpendEnvelope(e.ID, e.TenantID, e.AgentID, e.PrincipalID, e.BudgetID, e.Currency, e.Period, e.MaxAmountCents, e.PerRequestMaxCents, e.PolicyHash)
	rebuilt.AllowedProviders = e.AllowedProviders
	rebuilt.AllowedModels = e.AllowedModels
	rebuilt.FallbackModels = e.FallbackModels
	rebuilt.AllowModelSubstitution = e.AllowModelSubstitution
	rebuilt.ApprovalRequiredAboveCents = e.ApprovalRequiredAboveCents
	rebuilt.UsedAmountCents = e.UsedAmountCents
	rebuilt.ReservedAmountCents = e.ReservedAmountCents
	rebuilt.EmergencyStop = e.EmergencyStop
	rebuilt.Active = e.Active
	return rebuilt
}

func requireErrContains(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error containing %q, got nil", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %q, want substring %q", err.Error(), want)
	}
}

func asQuote(t *testing.T, err error) *QuoteError {
	t.Helper()
	var qe *QuoteError
	if !errors.As(err, &qe) {
		t.Fatalf("expected *QuoteError, got %v", err)
	}
	return qe
}

// --- Successful governed route -------------------------------------------------

func TestQuoteAndSettleHappyPath(t *testing.T) {
	h := newHarness(t)
	res, err := h.engine.Quote(h.env, h.req("idem-ok", "gpt-4o", 1000, 500))
	if err != nil {
		t.Fatalf("Quote() = %v, want nil", err)
	}
	if res.Decision.Verdict != economic.BudgetVerdictAllow {
		t.Fatalf("verdict = %s, want ALLOW", res.Decision.Verdict)
	}
	if res.Quote.SelectedModelID != "gpt-4o" || res.Quote.SelectedProviderID != "openai" {
		t.Fatalf("route = %s/%s, want openai/gpt-4o", res.Quote.SelectedProviderID, res.Quote.SelectedModelID)
	}
	// 1000*500 + 500*1500 = 1_250_000 micro-cents -> ceil to 2 cents.
	if res.Quote.QuotedAmountCents != 2 {
		t.Fatalf("quoted = %d cents, want 2", res.Quote.QuotedAmountCents)
	}
	if res.Receipt == nil || res.Receipt.ContentHash == "" {
		t.Fatal("expected a dispatch receipt on ALLOW")
	}
	if res.Quote.ReceiptHash != res.Receipt.ContentHash {
		t.Fatal("quote must bind the dispatch receipt hash")
	}

	balBefore := h.ledger.BalanceCents()
	settle, err := h.engine.Settle(res.Quote, "prov-req-1", 2, 1000, 480)
	if err != nil {
		t.Fatalf("Settle() = %v, want nil", err)
	}
	if settle.ActualAmountCents != 2 {
		t.Fatalf("actual = %d, want 2", settle.ActualAmountCents)
	}
	if settle.BalanceAfterCents != balBefore-2 {
		t.Fatalf("balance after = %d, want %d", settle.BalanceAfterCents, balBefore-2)
	}
	if err := settle.UsageReceipt.Validate(); err != nil {
		t.Fatalf("usage receipt invalid: %v", err)
	}
	if err := settle.SettlementReceipt.Validate(); err != nil {
		t.Fatalf("settlement receipt invalid: %v", err)
	}
	if !settle.SettlementReceipt.Balanced() {
		t.Fatal("settlement must be balanced")
	}
}

// --- Quote expiry (financial invariant) ---------------------------------------

func TestSettleFailsOnExpiredQuote(t *testing.T) {
	h := newHarness(t)
	res, err := h.engine.Quote(h.env, h.req("idem-exp", "gpt-4o", 1000, 500))
	if err != nil {
		t.Fatalf("Quote() = %v", err)
	}
	h.advance(31 * time.Second)
	settle, err := h.engine.Settle(res.Quote, "prov-req-1", 2, 1000, 500)
	requireErrContains(t, err, "expired")
	if settle == nil || settle.ReasonCode != economic.SpendReasonRouteQuoteExpired {
		t.Fatalf("reason = %v, want %s", settle, economic.SpendReasonRouteQuoteExpired)
	}
	if h.ledger.BalanceCents() != 100_000 {
		t.Fatalf("balance = %d, want untouched 100000", h.ledger.BalanceCents())
	}
	if len(h.ledger.Entries()) != 0 {
		t.Fatalf("ledger entries = %d, want 0 on expiry", len(h.ledger.Entries()))
	}
}

func TestQuoteExpiresDeterministically(t *testing.T) {
	h := newHarness(t)
	res, err := h.engine.Quote(h.env, h.req("idem-det", "gpt-4o", 10, 10))
	if err != nil {
		t.Fatalf("Quote() = %v", err)
	}
	wantExpiry := h.now.Add(30 * time.Second)
	if !res.Quote.ExpiresAt.Equal(wantExpiry) {
		t.Fatalf("expires_at = %s, want %s", res.Quote.ExpiresAt, wantExpiry)
	}
	if res.Quote.Expired(h.now.Add(29 * time.Second)) {
		t.Fatal("quote must be live before TTL")
	}
	if !res.Quote.Expired(h.now.Add(30 * time.Second)) {
		t.Fatal("quote must be expired at exactly TTL boundary")
	}
}

// --- Stale provider price (fail closed / escalate) ----------------------------

func TestStalePriceFailsClosed(t *testing.T) {
	h := newHarness(t)
	stale := buildSnapshot("price-openai-gpt", "openai", "gpt-4o", "terms-openai", "sha256:src-openai", h.now.Add(-2*time.Hour), h.now.Add(-time.Hour), 500, 1500)
	if err := h.prices.Put(stale); err != nil {
		t.Fatalf("put stale: %v", err)
	}
	_, err := h.engine.Quote(h.env, h.req("idem-stale", "gpt-4o", 10, 10))
	requireErrContains(t, err, "stale")
	qe := asQuote(t, err)
	if qe.Verdict != economic.BudgetVerdictDeny || qe.ReasonCode != economic.SpendReasonProviderPriceStale {
		t.Fatalf("expected DENY/PROVIDER_PRICE_STALE, got %v", err)
	}
}

func TestStalePriceEscalates(t *testing.T) {
	h := newHarness(t, func(c *EngineConfig) { c.StalePrice = StalePriceEscalate })
	stale := buildSnapshot("price-openai-gpt", "openai", "gpt-4o", "terms-openai", "sha256:src-openai", h.now.Add(-2*time.Hour), h.now.Add(-time.Hour), 500, 1500)
	if err := h.prices.Put(stale); err != nil {
		t.Fatalf("put stale: %v", err)
	}
	_, err := h.engine.Quote(h.env, h.req("idem-stale-esc", "gpt-4o", 10, 10))
	if asQuote(t, err).Verdict != economic.BudgetVerdictEscalate {
		t.Fatalf("expected ESCALATE on stale price, got %v", err)
	}
}

// --- Terms block before dispatch ----------------------------------------------

func TestTermsBlockBeforeDispatch(t *testing.T) {
	h := newHarness(t)
	// Build a terms book lacking the openai profile.
	termsOnlyAnthropic := NewMemoryTermsBook()
	_ = termsOnlyAnthropic.Put(economic.NewProviderTermsProfile("terms-anthropic", "anthropic", economic.ProviderAccountDirect, "2026-01-01", "legal-2"))
	eng, err := NewEngine(EngineConfig{
		Prices: h.prices, Terms: termsOnlyAnthropic, Ledger: h.ledger,
		TreasuryID: "treasury-1", RoutePolicyID: "route-policy-default",
		QuoteTTL: 30 * time.Second, PlatformFeeBps: 1000, Now: fixedClock(h.clock),
	})
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	_, err = eng.Quote(h.env, h.req("idem-terms", "gpt-4o", 10, 10))
	requireErrContains(t, err, "terms profile is required")
	if asQuote(t, err).ReasonCode != economic.SpendReasonProviderContractNeeded {
		t.Fatalf("expected PROVIDER_CONTRACT_NEEDED, got %v", err)
	}
	if h.ledger.BalanceCents() != 100_000 {
		t.Fatal("balance must be untouched when terms block dispatch")
	}
}

func TestTermsSnapshotBindingMismatchBlocks(t *testing.T) {
	h := newHarness(t)
	// Overwrite openai terms with a different id than the snapshot binds.
	_ = h.terms.Put(economic.NewProviderTermsProfile("terms-openai-OTHER", "openai", economic.ProviderAccountDirect, "2026-01-01", "legal-x"))
	_, err := h.engine.Quote(h.env, h.req("idem-bind", "gpt-4o", 10, 10))
	requireErrContains(t, err, "not bound to the reviewed terms profile")
}

// --- Cost cap & escalation (actual > quote ceiling) ---------------------------

func TestActualCostCappedAtCeiling(t *testing.T) {
	h := newHarness(t)
	res, err := h.engine.Quote(h.env, h.req("idem-cap", "gpt-4o", 1000, 500))
	if err != nil {
		t.Fatalf("Quote() = %v", err)
	}
	ceiling := res.Quote.MaxAmountCents
	settle, err := h.engine.Settle(res.Quote, "prov-req-1", ceiling*100, 1000, 9999)
	if err != nil {
		t.Fatalf("Settle() = %v", err)
	}
	if !settle.Capped {
		t.Fatal("expected cost to be capped")
	}
	if settle.ActualAmountCents != ceiling {
		t.Fatalf("actual = %d, want capped at ceiling %d", settle.ActualAmountCents, ceiling)
	}
	if settle.BalanceDebitCents != ceiling {
		t.Fatalf("debit = %d, want ceiling %d", settle.BalanceDebitCents, ceiling)
	}
	if !settle.SettlementReceipt.Balanced() {
		t.Fatal("capped settlement must still balance")
	}
}

func TestActualCostEscalatesWhenPolicyEscalate(t *testing.T) {
	h := newHarness(t, func(c *EngineConfig) { c.CostCap = CostCapEscalate })
	res, err := h.engine.Quote(h.env, h.req("idem-esc", "gpt-4o", 1000, 500))
	if err != nil {
		t.Fatalf("Quote() = %v", err)
	}
	settle, err := h.engine.Settle(res.Quote, "prov-req-1", res.Quote.MaxAmountCents*100, 1000, 9999)
	if asQuote(t, err).Verdict != economic.BudgetVerdictEscalate {
		t.Fatalf("expected ESCALATE on cost overrun, got %v", err)
	}
	if settle == nil || !settle.Escalated {
		t.Fatal("settle result must record escalation")
	}
	if h.ledger.BalanceCents() != 100_000 {
		t.Fatalf("balance = %d, want untouched on escalation", h.ledger.BalanceCents())
	}
}

// --- Idempotent debit (financial invariant) -----------------------------------

func TestIdempotentDebitDoesNotDoubleCharge(t *testing.T) {
	h := newHarness(t)
	res, err := h.engine.Quote(h.env, h.req("idem-once", "gpt-4o", 1000, 500))
	if err != nil {
		t.Fatalf("Quote() = %v", err)
	}
	first, err := h.engine.Settle(res.Quote, "prov-req-1", 50, 1000, 500)
	if err != nil {
		t.Fatalf("first Settle() = %v", err)
	}
	balAfterFirst := h.ledger.BalanceCents()
	if first.Replayed {
		t.Fatal("first settle must not be a replay")
	}

	second, err := h.engine.Settle(res.Quote, "prov-req-1", 50, 1000, 500)
	if err != nil {
		t.Fatalf("second Settle() = %v", err)
	}
	if !second.Replayed {
		t.Fatal("second settle must be an idempotent replay")
	}
	if h.ledger.BalanceCents() != balAfterFirst {
		t.Fatalf("balance changed on replay: %d != %d", h.ledger.BalanceCents(), balAfterFirst)
	}
	if len(h.ledger.Entries()) != 1 {
		t.Fatalf("ledger entries = %d, want exactly 1 after replay", len(h.ledger.Entries()))
	}
	if second.UsageReceipt.ContentHash != first.UsageReceipt.ContentHash {
		t.Fatal("replay must return the identical usage receipt")
	}
}

// --- Ledger balancing invariant (direct) --------------------------------------

func TestLedgerRejectsUnbalancedSettlement(t *testing.T) {
	h := newHarness(t)
	usage := economic.NewUsageReceipt("ur-x", "tenant-1", "rq-x", "si-x", "env-1", "agent-1", "openai", "gpt-4o", 10, 5, 1, "USD", "sha256:policy", "evidence://x")
	usage.ProviderRequestID = "prov-x"
	usage.ProviderPriceSnapshotHash = "sha256:src-openai"
	usage.SettlementReceiptHash = "placeholder"
	usage.LedgerEntryIDs = []string{"e1", "e2"}
	usage.Reseal()

	bad := economic.NewSettlementReceipt("settle-x", "tenant-1", usage.ID, "rq-x", "treasury-1", usage.ContentHash, "USD", "evidence://x", []economic.SettlementLedgerEntry{
		{ID: "e1", AccountID: "balance-1", Direction: economic.SettlementDebit, AmountCents: 6, Currency: "USD"},
		{ID: "e2", AccountID: "treasury-1", Direction: economic.SettlementCredit, AmountCents: 5, Currency: "USD"},
	})
	_, err := h.ledger.commit("idem-bad", usage, bad)
	requireErrContains(t, err, "balanced")
	if h.ledger.BalanceCents() != 100_000 {
		t.Fatal("balance must be untouched when settlement is unbalanced")
	}
}

func TestLedgerConservationAcrossManyDebits(t *testing.T) {
	h := newHarness(t)
	start := h.ledger.BalanceCents()
	var totalDebit int64
	for i, idem := range []string{"a", "b", "c", "d"} {
		res, err := h.engine.Quote(h.env, h.req("idem-"+idem, "gpt-4o", int64(100*(i+1)), int64(50*(i+1))))
		if err != nil {
			t.Fatalf("Quote(%s) = %v", idem, err)
		}
		settle, err := h.engine.Settle(res.Quote, "prov-"+idem, res.Quote.QuotedAmountCents, 10, 10)
		if err != nil {
			t.Fatalf("Settle(%s) = %v", idem, err)
		}
		totalDebit += settle.BalanceDebitCents
	}
	if h.ledger.BalanceCents() != start-totalDebit {
		t.Fatalf("conservation violated: %d != %d - %d", h.ledger.BalanceCents(), start, totalDebit)
	}
	if len(h.ledger.Entries()) != 4 {
		t.Fatalf("ledger entries = %d, want 4", len(h.ledger.Entries()))
	}
}

// --- Fallback / model substitution (explicit in receipts) ---------------------

func TestFallbackSubstitutionIsExplicit(t *testing.T) {
	h := newHarness(t)
	h.env.AllowModelSubstitution = true
	h.env = resealEnvelope(h.env)

	// Request a model that is not on the allow-list; the engine must substitute
	// to the first allowed fallback route and mark it explicitly.
	res, err := h.engine.Quote(h.env, h.req("idem-fallback", "gpt-4o-mini", 1000, 500))
	if err != nil {
		t.Fatalf("Quote() = %v", err)
	}
	if !res.ModelSubstituted {
		t.Fatal("expected explicit model substitution")
	}
	if res.Quote.RequestedModelID != "gpt-4o-mini" {
		t.Fatalf("requested model not preserved: %s", res.Quote.RequestedModelID)
	}
	if res.Quote.SelectedModelID == "gpt-4o-mini" {
		t.Fatal("selected model must differ from the unsupported requested model")
	}
	if !h.env.AllowsModel(res.Quote.SelectedModelID) {
		t.Fatalf("substituted to a non-allowed model: %s", res.Quote.SelectedModelID)
	}
	if !res.Quote.ModelSubstituted || len(res.Quote.FallbackChain) == 0 {
		t.Fatal("quote must record substitution + fallback chain explicitly")
	}
	settle, err := h.engine.Settle(res.Quote, "prov-req-fb", res.Quote.QuotedAmountCents, 1000, 500)
	if err != nil {
		t.Fatalf("Settle() = %v", err)
	}
	if settle.UsageReceipt.ModelID != res.Quote.SelectedModelID {
		t.Fatalf("usage model = %s, want %s", settle.UsageReceipt.ModelID, res.Quote.SelectedModelID)
	}
}

// TestFallbackToSecondProviderWhenFirstUnpriced exercises a genuine
// cross-provider fallback: the requested model's primary provider has no live
// snapshot, so the engine must walk to the next allowed fallback route.
func TestFallbackToSecondProviderWhenFirstUnpriced(t *testing.T) {
	h := newHarness(t)
	h.env.AllowModelSubstitution = true
	h.env = resealEnvelope(h.env)
	// Request claude-haiku directly but make only the anthropic snapshot live
	// after forcing the requested model to require substitution: drop gpt-4o
	// from the price book so a request for gpt-4o substitutes to claude-haiku.
	prices := NewMemoryPriceBook()
	_ = prices.Put(buildSnapshot("price-anthropic-haiku", "anthropic", "claude-haiku", "terms-anthropic", "sha256:src-anthropic", h.now.Add(-time.Minute), h.now.Add(time.Hour), 300, 900))
	eng, err := NewEngine(EngineConfig{
		Prices: prices, Terms: h.terms, Ledger: h.ledger,
		TreasuryID: "treasury-1", RoutePolicyID: "route-policy-default",
		QuoteTTL: 30 * time.Second, PlatformFeeBps: 1000, Now: fixedClock(h.clock),
	})
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	res, err := eng.Quote(h.env, h.req("idem-cross", "gpt-4o", 1000, 500))
	if err != nil {
		t.Fatalf("Quote() = %v", err)
	}
	if res.Quote.SelectedModelID != "claude-haiku" || res.Quote.SelectedProviderID != "anthropic" {
		t.Fatalf("route = %s/%s, want anthropic/claude-haiku", res.Quote.SelectedProviderID, res.Quote.SelectedModelID)
	}
	if !res.ModelSubstituted {
		t.Fatal("cross-provider fallback must be marked as substituted")
	}
}

func TestSubstitutionDeniedWhenDisabled(t *testing.T) {
	h := newHarness(t)
	h.env.AllowModelSubstitution = false
	h.env = resealEnvelope(h.env)
	_, err := h.engine.Quote(h.env, h.req("idem-nosub", "gpt-4o-mini", 10, 10))
	if asQuote(t, err).ReasonCode != economic.SpendReasonModelNotAllowed {
		t.Fatalf("expected MODEL_NOT_ALLOWED with substitution disabled, got %v", err)
	}
}

// --- Denied route: insufficient balance ---------------------------------------

func TestDeniedWhenBalanceInsufficient(t *testing.T) {
	h := newHarness(t)
	h.env.MaxAmountCents = 1
	h.env.PerRequestMaxCents = 1
	h.env = resealEnvelope(h.env)
	_, err := h.engine.Quote(h.env, h.req("idem-poor", "gpt-4o", 100000, 100000))
	if asQuote(t, err).Verdict != economic.BudgetVerdictDeny {
		t.Fatalf("expected DENY on insufficient balance, got %v", err)
	}
}

// --- Approval escalation -------------------------------------------------------

func TestEscalatesWhenApprovalRequired(t *testing.T) {
	h := newHarness(t)
	h.env.ApprovalRequiredAboveCents = 1
	h.env = resealEnvelope(h.env)
	res, err := h.engine.Quote(h.env, h.req("idem-approve", "gpt-4o", 1000, 500))
	qe := asQuote(t, err)
	if qe.Verdict != economic.BudgetVerdictEscalate || qe.ReasonCode != economic.SpendReasonApprovalRequired {
		t.Fatalf("expected ESCALATE/APPROVAL_REQUIRED, got %v", err)
	}
	if res == nil || res.Quote == nil {
		t.Fatal("escalation must still return the quote for the audit trail")
	}
	if res.Receipt != nil {
		t.Fatal("no dispatch receipt may be issued on a non-ALLOW verdict")
	}
}
