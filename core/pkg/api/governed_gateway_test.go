package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/economic"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/inferencegateway"
)

// gatewayFixture builds a fully-wired governed gateway over an in-memory engine.
type gatewayFixture struct {
	mux      *http.ServeMux
	ledger   *inferencegateway.BalanceLedger
	env      *economic.AgentSpendEnvelope
	now      time.Time
	clk      *time.Time
	dispatch *spyDispatch
}

type spyDispatch struct {
	called int
	cost   int64
}

func newGatewayFixture(t *testing.T, stale inferencegateway.StalePricePolicy, costCap inferencegateway.CostCapPolicy, providerCost int64) *gatewayFixture {
	t.Helper()
	now := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)
	clk := now

	prices := inferencegateway.NewMemoryPriceBook()
	mustPut(t, prices, gwSnapshot("price-openai", "openai", "gpt-4o", "terms-openai", "sha256:src-openai", now.Add(-time.Minute), now.Add(time.Hour), 500, 1500))
	mustPut(t, prices, gwSnapshot("price-anthropic", "anthropic", "claude-haiku", "terms-anthropic", "sha256:src-anthropic", now.Add(-time.Minute), now.Add(time.Hour), 300, 900))

	terms := inferencegateway.NewMemoryTermsBook()
	if err := terms.Put(economic.NewProviderTermsProfile("terms-openai", "openai", economic.ProviderAccountDirect, "2026-01-01", "legal-1")); err != nil {
		t.Fatalf("terms openai: %v", err)
	}
	if err := terms.Put(economic.NewProviderTermsProfile("terms-anthropic", "anthropic", economic.ProviderAccountDirect, "2026-01-01", "legal-2")); err != nil {
		t.Fatalf("terms anthropic: %v", err)
	}

	account := economic.NewBalanceAccount("balance-1", "tenant-1", "USD", 100_000, "evidence://balance-1")
	ledger, err := inferencegateway.NewBalanceLedger(account)
	if err != nil {
		t.Fatalf("ledger: %v", err)
	}

	eng, err := inferencegateway.NewEngine(inferencegateway.EngineConfig{
		Prices: prices, Terms: terms, Ledger: ledger,
		TreasuryID: "treasury-1", RoutePolicyID: "route-policy", QuoteTTL: 30 * time.Second,
		StalePrice: stale, CostCap: costCap, PlatformFeeBps: 1000,
		Now: func() time.Time { return clk },
	})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}

	env := gwEnvelope()
	resolver := func(tenantID, envelopeID string) (*economic.AgentSpendEnvelope, bool) {
		if tenantID == "tenant-1" && envelopeID == env.ID {
			return env, true
		}
		return nil, false
	}
	spy := &spyDispatch{cost: providerCost}
	dispatch := func(r *http.Request, quote *economic.RouteQuote, body []byte) (DispatchOutcome, error) {
		spy.called++
		return DispatchOutcome{
			ResponseBody:      json.RawMessage(`{"id":"chatcmpl-1","object":"chat.completion","choices":[{"message":{"role":"assistant","content":"ok"}}]}`),
			ProviderRequestID: "prov-req-" + quote.ID,
			ProviderCostCents: spy.cost,
			InputTokens:       1000,
			OutputTokens:      480,
		}, nil
	}

	gw, err := NewGovernedGateway(GovernedGatewayConfig{
		Engine:   eng,
		Resolver: resolver,
		Dispatch: dispatch,
		TenantID: func(r *http.Request) string { return "tenant-1" },
		Models:   []GatewayModel{{ID: "gpt-4o", Object: "model", OwnedBy: "helm", Provider: "openai"}},
	})
	if err != nil {
		t.Fatalf("gateway: %v", err)
	}
	mux := http.NewServeMux()
	gw.Register(mux)

	return &gatewayFixture{mux: mux, ledger: ledger, env: env, now: now, clk: &clk, dispatch: spy}
}

func mustPut(t *testing.T, b *inferencegateway.MemoryPriceBook, s *economic.ProviderPriceSnapshot) {
	t.Helper()
	if err := b.Put(s); err != nil {
		t.Fatalf("price put: %v", err)
	}
}

func gwSnapshot(id, provider, model, termsID, sourceHash string, eff, exp time.Time, inMicro, outMicro int64) *economic.ProviderPriceSnapshot {
	s := economic.NewProviderPriceSnapshot(id, provider, model, "USD", termsID, sourceHash, eff, exp)
	s.InputTokenMicroCents = inMicro
	s.OutputTokenMicroCents = outMicro
	rebuilt := economic.NewProviderPriceSnapshot(id, provider, model, "USD", termsID, sourceHash, eff, exp)
	rebuilt.InputTokenMicroCents = inMicro
	rebuilt.OutputTokenMicroCents = outMicro
	s.ContentHash = rebuilt.ContentHash
	return s
}

func gwEnvelope() *economic.AgentSpendEnvelope {
	env := economic.NewAgentSpendEnvelope("env-1", "tenant-1", "agent-1", "principal-1", "budget-1", "USD", economic.SpendPeriodDaily, 50_000, 10_000, "sha256:policy")
	env.AllowedProviders = []string{"openai", "anthropic"}
	env.AllowedModels = []string{"gpt-4o", "claude-haiku"}
	env.FallbackModels = []economic.ModelRoute{
		{ProviderID: "openai", ModelID: "gpt-4o", PriceSnapshotHash: "sha256:src-openai"},
		{ProviderID: "anthropic", ModelID: "claude-haiku", PriceSnapshotHash: "sha256:src-anthropic"},
	}
	env.AllowModelSubstitution = true
	return rebuildEnvelope(env)
}

func rebuildEnvelope(e *economic.AgentSpendEnvelope) *economic.AgentSpendEnvelope {
	rebuilt := economic.NewAgentSpendEnvelope(e.ID, e.TenantID, e.AgentID, e.PrincipalID, e.BudgetID, e.Currency, e.Period, e.MaxAmountCents, e.PerRequestMaxCents, e.PolicyHash)
	rebuilt.AllowedProviders = e.AllowedProviders
	rebuilt.AllowedModels = e.AllowedModels
	rebuilt.FallbackModels = e.FallbackModels
	rebuilt.AllowModelSubstitution = e.AllowModelSubstitution
	rebuilt.ApprovalRequiredAboveCents = e.ApprovalRequiredAboveCents
	rebuilt.Active = e.Active
	return rebuilt
}

func (f *gatewayFixture) do(t *testing.T, method, path, model string, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var body []byte
	if model != "" {
		body, _ = json.Marshal(map[string]any{
			"model":    model,
			"messages": []map[string]string{{"role": "user", "content": "hello"}},
		})
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	f.mux.ServeHTTP(rr, req)
	return rr
}

func helmHeaders(idem, model string) map[string]string {
	return map[string]string{
		inferencegateway.HeaderWorkspace:      "ws-1",
		inferencegateway.HeaderAgent:          "agent-1",
		inferencegateway.HeaderPrincipal:      "principal-1",
		inferencegateway.HeaderSpendEnvelope:  "env-1",
		inferencegateway.HeaderIdempotencyKey: idem,
		inferencegateway.HeaderRoutePolicy:    "route-policy",
	}
}

func decodeHELM(t *testing.T, rr *httptest.ResponseRecorder) GatewayMetadata {
	t.Helper()
	var payload struct {
		HELM GatewayMetadata `json:"helm"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode body %q: %v", rr.Body.String(), err)
	}
	return payload.HELM
}

// --- Runtime smoke: 1 successful route ----------------------------------------

func TestGatewaySuccessfulRoute(t *testing.T) {
	f := newGatewayFixture(t, inferencegateway.StalePriceFailClosed, inferencegateway.CostCapClamp, 2)
	rr := f.do(t, http.MethodPost, "/v1/chat/completions", "gpt-4o", helmHeaders("idem-ok", "gpt-4o"))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	meta := decodeHELM(t, rr)
	if meta.Verdict != economic.BudgetVerdictAllow {
		t.Fatalf("verdict = %s, want ALLOW", meta.Verdict)
	}
	if meta.UsageReceipt == nil || meta.SettlementReceipt == nil || meta.RouteReceipt == nil || meta.Quote == nil {
		t.Fatal("successful response must carry quote + all three receipts")
	}
	if !meta.SettlementReceipt.Balanced() {
		t.Fatal("settlement must balance")
	}
	if rr.Header().Get("X-HELM-Usage-Receipt-Hash") == "" {
		t.Fatal("usage receipt hash header must be set")
	}
	if f.dispatch.called != 1 {
		t.Fatalf("dispatch called %d times, want 1", f.dispatch.called)
	}
}

// --- Runtime smoke: 1 denied route --------------------------------------------

func TestGatewayDeniedRoute(t *testing.T) {
	f := newGatewayFixture(t, inferencegateway.StalePriceFailClosed, inferencegateway.CostCapClamp, 2)
	// Model not allowed and not substitutable.
	f.env.AllowModelSubstitution = false
	*f.env = *rebuildEnvelope(f.env)
	rr := f.do(t, http.MethodPost, "/v1/chat/completions", "unknown-model", helmHeaders("idem-deny", "unknown-model"))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", rr.Code, rr.Body.String())
	}
	meta := decodeHELM(t, rr)
	if meta.Verdict != economic.BudgetVerdictDeny {
		t.Fatalf("verdict = %s, want DENY", meta.Verdict)
	}
	if f.dispatch.called != 0 {
		t.Fatal("no provider dispatch may occur on a denied route")
	}
}

// --- Runtime smoke: 1 escalation ----------------------------------------------

func TestGatewayEscalationRoute(t *testing.T) {
	f := newGatewayFixture(t, inferencegateway.StalePriceFailClosed, inferencegateway.CostCapClamp, 2)
	f.env.ApprovalRequiredAboveCents = 1
	*f.env = *rebuildEnvelope(f.env)
	rr := f.do(t, http.MethodPost, "/v1/chat/completions", "gpt-4o", helmHeaders("idem-esc", "gpt-4o"))
	if rr.Code != http.StatusPaymentRequired {
		t.Fatalf("status = %d, want 402; body=%s", rr.Code, rr.Body.String())
	}
	meta := decodeHELM(t, rr)
	if meta.Verdict != economic.BudgetVerdictEscalate || meta.ReasonCode != economic.SpendReasonApprovalRequired {
		t.Fatalf("verdict/reason = %s/%s, want ESCALATE/APPROVAL_REQUIRED", meta.Verdict, meta.ReasonCode)
	}
	if f.dispatch.called != 0 {
		t.Fatal("no provider dispatch may occur on escalation")
	}
}

// --- Runtime smoke: 1 stale-price failure -------------------------------------

func TestGatewayStalePriceFailure(t *testing.T) {
	f := newGatewayFixture(t, inferencegateway.StalePriceFailClosed, inferencegateway.CostCapClamp, 2)
	// Advance the clock past both snapshots' expiry so the live route is stale.
	*f.clk = f.now.Add(2 * time.Hour)
	rr := f.do(t, http.MethodPost, "/v1/chat/completions", "gpt-4o", helmHeaders("idem-stale", "gpt-4o"))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", rr.Code, rr.Body.String())
	}
	meta := decodeHELM(t, rr)
	if meta.ReasonCode != economic.SpendReasonProviderPriceStale {
		t.Fatalf("reason = %s, want PROVIDER_PRICE_STALE", meta.ReasonCode)
	}
	if f.dispatch.called != 0 {
		t.Fatal("no provider dispatch may occur on stale price")
	}
}

// --- Runtime smoke: 1 fallback receipt ----------------------------------------

func TestGatewayFallbackReceipt(t *testing.T) {
	f := newGatewayFixture(t, inferencegateway.StalePriceFailClosed, inferencegateway.CostCapClamp, 2)
	// Request a model not on the allow-list; substitution is enabled by default
	// in the fixture envelope, so the gateway substitutes and dispatches.
	rr := f.do(t, http.MethodPost, "/v1/chat/completions", "gpt-4o-mini", helmHeaders("idem-fallback", "gpt-4o-mini"))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	meta := decodeHELM(t, rr)
	if !meta.ModelSubstituted {
		t.Fatal("fallback response must mark model_substituted in the receipt metadata")
	}
	if meta.Quote == nil || len(meta.Quote.FallbackChain) == 0 {
		t.Fatal("fallback receipt must include the fallback chain")
	}
	if meta.UsageReceipt == nil || meta.UsageReceipt.ModelID == "gpt-4o-mini" {
		t.Fatal("usage receipt must record the substituted model, not the requested one")
	}
}

// --- Idempotent replay over HTTP ----------------------------------------------

func TestGatewayIdempotentReplayOverHTTP(t *testing.T) {
	f := newGatewayFixture(t, inferencegateway.StalePriceFailClosed, inferencegateway.CostCapClamp, 50)
	hdr := helmHeaders("idem-replay", "gpt-4o")

	first := f.do(t, http.MethodPost, "/v1/chat/completions", "gpt-4o", hdr)
	if first.Code != http.StatusOK {
		t.Fatalf("first status = %d; body=%s", first.Code, first.Body.String())
	}
	balAfterFirst := f.ledger.BalanceCents()

	second := f.do(t, http.MethodPost, "/v1/chat/completions", "gpt-4o", hdr)
	if second.Code != http.StatusOK {
		t.Fatalf("second status = %d; body=%s", second.Code, second.Body.String())
	}
	meta := decodeHELM(t, second)
	if !meta.Replayed {
		t.Fatal("second identical request must be an idempotent replay")
	}
	if f.ledger.BalanceCents() != balAfterFirst {
		t.Fatalf("balance changed on replay: %d != %d", f.ledger.BalanceCents(), balAfterFirst)
	}
	if len(f.ledger.Entries()) != 1 {
		t.Fatalf("ledger entries = %d, want 1 after replay", len(f.ledger.Entries()))
	}
}

// --- Header enforcement & endpoint coverage -----------------------------------

func TestGatewayMissingHeadersRejected(t *testing.T) {
	f := newGatewayFixture(t, inferencegateway.StalePriceFailClosed, inferencegateway.CostCapClamp, 2)
	hdr := helmHeaders("idem-x", "gpt-4o")
	delete(hdr, inferencegateway.HeaderSpendEnvelope)
	rr := f.do(t, http.MethodPost, "/v1/chat/completions", "gpt-4o", hdr)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for missing header", rr.Code)
	}
}

func TestGatewayModelsEndpoint(t *testing.T) {
	f := newGatewayFixture(t, inferencegateway.StalePriceFailClosed, inferencegateway.CostCapClamp, 2)
	rr := f.do(t, http.MethodGet, "/v1/models", "", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var out struct {
		Object string         `json:"object"`
		Data   []GatewayModel `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Object != "list" || len(out.Data) != 1 || out.Data[0].ID != "gpt-4o" {
		t.Fatalf("unexpected models payload: %s", rr.Body.String())
	}
}

func TestGatewayEmbeddingsAndResponsesRouted(t *testing.T) {
	f := newGatewayFixture(t, inferencegateway.StalePriceFailClosed, inferencegateway.CostCapClamp, 2)
	for i, path := range []string{"/v1/embeddings", "/v1/responses"} {
		idem := "idem-path-" + string(rune('a'+i))
		rr := f.do(t, http.MethodPost, path, "gpt-4o", helmHeaders(idem, "gpt-4o"))
		if rr.Code != http.StatusOK {
			t.Fatalf("%s status = %d, want 200; body=%s", path, rr.Code, rr.Body.String())
		}
	}
}
