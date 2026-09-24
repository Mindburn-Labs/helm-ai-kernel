package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/economic"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/inferencegateway"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/privacy"
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
	called        int
	cost          int64
	body          []byte
	responseBody  json.RawMessage
	requestID     string
	afterDispatch func()
}

type advancingPrivacyContext struct {
	context.Context
	armed   *bool
	advance func()
}

func (c advancingPrivacyContext) Err() error {
	if *c.armed {
		*c.armed = false
		c.advance()
	}
	return c.Context.Err()
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
		spy.body = append([]byte(nil), body...)
		if spy.afterDispatch != nil {
			spy.afterDispatch()
		}
		responseBody := spy.responseBody
		if responseBody == nil {
			responseBody = json.RawMessage(`{"id":"chatcmpl-1","object":"chat.completion","choices":[{"message":{"role":"assistant","content":"ok"}}]}`)
		}
		requestID := spy.requestID
		if requestID == "" {
			requestID = "prov-req-" + quote.ID
		}
		return DispatchOutcome{
			ResponseBody:      responseBody,
			ProviderRequestID: requestID,
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
		payload := map[string]any{
			"model":    model,
			"messages": []map[string]string{{"role": "user", "content": "hello"}},
		}
		switch path {
		case "/v1/chat/completions":
			payload["max_tokens"] = 64
		case "/v1/responses":
			payload["max_output_tokens"] = 64
		}
		body, _ = json.Marshal(payload)
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
	if meta.UsageReceiptView == nil || meta.SettlementReceipt == nil || meta.RouteReceipt == nil || meta.Quote == nil {
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

func TestGatewayProtectsProviderRequestAndResponse(t *testing.T) {
	f := newGatewayFixture(t, inferencegateway.StalePriceFailClosed, inferencegateway.CostCapClamp, 2)
	f.dispatch.responseBody = json.RawMessage(`{"id":"chatcmpl-privacy","choices":[{"message":{"role":"assistant","content":"reply to person@example.com"}}]}`)
	body := []byte(`{"model":"gpt-4o","max_tokens":64,"messages":[{"role":"user","content":"contact person@example.com"}]}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	for key, value := range helmHeaders("idem-privacy", "gpt-4o") {
		req.Header.Set(key, value)
	}
	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if bytes.Contains(f.dispatch.body, []byte("person@example.com")) || !bytes.Contains(f.dispatch.body, []byte("[REDACTED_EMAIL]")) {
		t.Fatalf("dispatch body was not protected: %s", f.dispatch.body)
	}
	if bytes.Contains(rec.Body.Bytes(), []byte("person@example.com")) || !bytes.Contains(rec.Body.Bytes(), []byte("[REDACTED_EMAIL]")) {
		t.Fatalf("response body was not protected: %s", rec.Body.String())
	}
}

func TestGatewayPrivacyFailuresDoNotLeakOrSkipSettlement(t *testing.T) {
	t.Run("request", func(t *testing.T) {
		f := newGatewayFixture(t, inferencegateway.StalePriceFailClosed, inferencegateway.CostCapClamp, 2)
		body := []byte(`{"model":"gpt-4o","max_tokens":64,"messages":[{"role":"user","content":"api_key=sk_live_example1234"}]}`)
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
		for key, value := range helmHeaders("idem-privacy-request", "gpt-4o") {
			req.Header.Set(key, value)
		}
		rec := httptest.NewRecorder()
		f.mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden || f.dispatch.called != 0 || bytes.Contains(rec.Body.Bytes(), []byte("sk_live")) {
			t.Fatalf("status=%d dispatch=%d body=%s", rec.Code, f.dispatch.called, rec.Body.String())
		}
	})

	t.Run("response", func(t *testing.T) {
		f := newGatewayFixture(t, inferencegateway.StalePriceFailClosed, inferencegateway.CostCapClamp, 2)
		f.dispatch.responseBody = json.RawMessage(`{"choices":[{"message":{"content":"api_key=sk_live_example1234"}}]}`)
		f.dispatch.requestID = "ghp_12345678901234567890"
		rec := f.do(t, http.MethodPost, "/v1/chat/completions", "gpt-4o", helmHeaders("idem-privacy-response", "gpt-4o"))
		if rec.Code != http.StatusBadGateway || f.dispatch.called != 1 || bytes.Contains(rec.Body.Bytes(), []byte("sk_live")) || bytes.Contains(rec.Body.Bytes(), []byte("ghp_")) {
			t.Fatalf("status=%d dispatch=%d body=%s", rec.Code, f.dispatch.called, rec.Body.String())
		}
		if debitEntries(f.ledger) != 1 {
			t.Fatalf("settlement entries = %d, want 1", debitEntries(f.ledger))
		}
		meta := decodeHELM(t, rec)
		if meta.Quote == nil || meta.RouteReceipt == nil || meta.UsageReceiptView == nil || meta.SettlementReceipt == nil {
			t.Fatal("blocked provider response must retain the complete settlement metadata")
		}
		if meta.UsageReceiptView.ProviderRequestID != "" || !strings.Contains(strings.Join(meta.UsageReceiptView.RedactedFields, ","), "provider_request_id") {
			t.Fatalf("public provider request id was not redacted: %+v", meta.UsageReceiptView)
		}
		internal := f.ledger.InternalUsageRecords()
		if len(internal) != 1 || internal[0].ProviderRequestID != f.dispatch.requestID {
			t.Fatalf("internal provider request id = %+v, want %q", internal, f.dispatch.requestID)
		}
	})
}

func TestGatewayAllowsRestrictedNamesOnlyInModelSchemas(t *testing.T) {
	f := newGatewayFixture(t, inferencegateway.StalePriceFailClosed, inferencegateway.CostCapClamp, 2)
	body := []byte(`{"model":"gpt-4o","max_tokens":64,"messages":[{"role":"user","content":"use the tool"}],"tools":[{"type":"function","function":{"name":"login","parameters":{"type":"object","properties":{"password":{"type":"string"},"api_key":{"type":"string"}},"required":["password"]}}}]}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	for key, value := range helmHeaders("idem-schema", "gpt-4o") {
		req.Header.Set(key, value)
	}
	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || f.dispatch.called != 1 || !bytes.Contains(f.dispatch.body, []byte(`"password"`)) || !bytes.Contains(f.dispatch.body, []byte(`"api_key"`)) {
		t.Fatalf("status=%d dispatch=%d provider_body=%s response=%s", rec.Code, f.dispatch.called, f.dispatch.body, rec.Body.String())
	}
}

func TestGatewaySettlesBeforeProviderResponsePrivacyScan(t *testing.T) {
	f := newGatewayFixture(t, inferencegateway.StalePriceFailClosed, inferencegateway.CostCapClamp, 2)
	armed := false
	f.dispatch.afterDispatch = func() { armed = true }
	ctx := advancingPrivacyContext{
		Context: context.Background(),
		armed:   &armed,
		advance: func() { *f.clk = f.now.Add(2 * time.Hour) },
	}
	body := []byte(`{"model":"gpt-4o","max_tokens":64,"messages":[{"role":"user","content":"hello"}]}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body)).WithContext(ctx)
	for key, value := range helmHeaders("idem-settle-before-privacy", "gpt-4o") {
		req.Header.Set(key, value)
	}
	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || f.dispatch.called != 1 || debitEntries(f.ledger) != 1 {
		t.Fatalf("status=%d dispatch=%d entries=%d body=%s", rec.Code, f.dispatch.called, debitEntries(f.ledger), rec.Body.String())
	}
}

func TestGatewayReturnsBadRequestForMalformedJSON(t *testing.T) {
	f := newGatewayFixture(t, inferencegateway.StalePriceFailClosed, inferencegateway.CostCapClamp, 2)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{`))
	for key, value := range helmHeaders("idem-malformed", "gpt-4o") {
		req.Header.Set(key, value)
	}
	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest || f.dispatch.called != 0 || strings.Contains(rec.Body.String(), privacy.ErrDataEgressBlocked.Error()) {
		t.Fatalf("status=%d dispatch=%d body=%s", rec.Code, f.dispatch.called, rec.Body.String())
	}
}

func TestGatewaySupportsBatchedEmbeddingsAndLogprobs(t *testing.T) {
	t.Run("embeddings", func(t *testing.T) {
		f := newGatewayFixture(t, inferencegateway.StalePriceFailClosed, inferencegateway.CostCapClamp, 2)
		vector := make([]float64, 1536)
		data := make([]any, 7)
		for index := range data {
			data[index] = map[string]any{"object": "embedding", "index": index, "embedding": vector}
		}
		f.dispatch.responseBody, _ = json.Marshal(map[string]any{"object": "list", "data": data})
		rec := f.do(t, http.MethodPost, "/v1/embeddings", "gpt-4o", helmHeaders("idem-embeddings", "gpt-4o"))
		if rec.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("logprobs", func(t *testing.T) {
		f := newGatewayFixture(t, inferencegateway.StalePriceFailClosed, inferencegateway.CostCapClamp, 2)
		f.dispatch.responseBody = json.RawMessage(`{"choices":[{"message":{"role":"assistant","content":"hello"},"logprobs":{"content":[{"token":"hello","logprob":-0.1,"bytes":[104,101,108,108,111],"top_logprobs":[]}]}}]}`)
		rec := f.do(t, http.MethodPost, "/v1/chat/completions", "gpt-4o", helmHeaders("idem-logprobs", "gpt-4o"))
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"token":"hello"`) {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
	})
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
	if meta.UsageReceiptView == nil || meta.UsageReceiptView.ModelID == "gpt-4o-mini" {
		t.Fatal("usage receipt must record the substituted model, not the requested one")
	}
}

// --- Idempotent replay over HTTP ----------------------------------------------

// TestGatewayIdempotentReplayOverHTTP covers audit finding 22-01: a replayed
// idempotency key is answered from the committed result and never reaches the
// provider a second time (the replay used to re-dispatch without a debit).
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
	if f.dispatch.called != 1 {
		t.Fatalf("provider dispatched %d times, want 1: a replay must not reach the provider", f.dispatch.called)
	}
	if f.ledger.BalanceCents() != balAfterFirst {
		t.Fatalf("balance changed on replay: %d != %d", f.ledger.BalanceCents(), balAfterFirst)
	}
	if debitEntries(f.ledger) != 1 {
		t.Fatalf("ledger entries = %d, want 1 after replay", debitEntries(f.ledger))
	}
	if got, want := decodeResponse(t, second), decodeResponse(t, first); !bytes.Equal(got, want) {
		t.Fatalf("replay response = %s, want the stored response %s", got, want)
	}
}

// TestGatewayReplayWithDifferentRequestConflicts binds the idempotency key to
// the request: reusing it for a new prompt or model is refused, not dispatched.
func TestGatewayReplayWithDifferentRequestConflicts(t *testing.T) {
	f := newGatewayFixture(t, inferencegateway.StalePriceFailClosed, inferencegateway.CostCapClamp, 2)
	hdr := helmHeaders("idem-reuse", "gpt-4o")
	if first := f.do(t, http.MethodPost, "/v1/chat/completions", "gpt-4o", hdr); first.Code != http.StatusOK {
		t.Fatalf("first status = %d; body=%s", first.Code, first.Body.String())
	}
	body := []byte(`{"model":"claude-haiku","max_tokens":64,"messages":[{"role":"user","content":"a different prompt"}]}`)
	rec := f.doBody(t, "/v1/chat/completions", body, hdr)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", rec.Code, rec.Body.String())
	}
	if f.dispatch.called != 1 {
		t.Fatalf("provider dispatched %d times, want 1", f.dispatch.called)
	}
	if bytes.Contains(rec.Body.Bytes(), []byte("chatcmpl-1")) {
		t.Fatalf("conflict must not disclose the stored response: %s", rec.Body.String())
	}
}

// TestGatewayConcurrentDuplicateKeyNeverDispatches: while one request holds the
// reservation for a key, a duplicate with the same key is refused.
func TestGatewayConcurrentDuplicateKeyNeverDispatches(t *testing.T) {
	f := newGatewayFixture(t, inferencegateway.StalePriceFailClosed, inferencegateway.CostCapClamp, 2)
	hdr := helmHeaders("idem-inflight", "gpt-4o")
	var nested *httptest.ResponseRecorder
	f.dispatch.afterDispatch = func() {
		if nested != nil {
			return
		}
		nested = httptest.NewRecorder()
		nested = f.do(t, http.MethodPost, "/v1/chat/completions", "gpt-4o", hdr)
	}
	first := f.do(t, http.MethodPost, "/v1/chat/completions", "gpt-4o", hdr)
	if first.Code != http.StatusOK {
		t.Fatalf("first status = %d; body=%s", first.Code, first.Body.String())
	}
	if nested == nil || nested.Code != http.StatusConflict {
		t.Fatalf("in-flight duplicate = %+v, want 409", nested)
	}
	if f.dispatch.called != 1 {
		t.Fatalf("provider dispatched %d times, want 1", f.dispatch.called)
	}
}

// --- Output-token ceiling (22-02 / 12-01) --------------------------------------

func TestGatewayRequiresOutputTokenLimit(t *testing.T) {
	for _, tc := range []struct {
		name, path, body, want string
	}{
		{"chat without max_tokens", "/v1/chat/completions", `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`, "max_tokens is required"},
		{"chat with zero max_tokens", "/v1/chat/completions", `{"model":"gpt-4o","max_tokens":0,"messages":[{"role":"user","content":"hi"}]}`, "max_tokens must be a positive integer"},
		{"responses without max_output_tokens", "/v1/responses", `{"model":"gpt-4o","input":"hi"}`, "max_output_tokens is required"},
		{"responses with the chat field only", "/v1/responses", `{"model":"gpt-4o","max_tokens":64,"input":"hi"}`, "max_output_tokens is required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newGatewayFixture(t, inferencegateway.StalePriceFailClosed, inferencegateway.CostCapClamp, 2)
			rec := f.doBody(t, tc.path, []byte(tc.body), helmHeaders("idem-limit", "gpt-4o"))
			if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), tc.want) {
				t.Fatalf("status = %d, body=%s; want 400 containing %q", rec.Code, rec.Body.String(), tc.want)
			}
			if f.dispatch.called != 0 {
				t.Fatal("no provider dispatch may occur without an output-token ceiling")
			}
		})
	}
}

func TestGatewayClampsAndForwardsOutputLimit(t *testing.T) {
	f := newGatewayFixture(t, inferencegateway.StalePriceFailClosed, inferencegateway.CostCapClamp, 2)
	// An absurd ceiling (the 12-01 double-wrap value) is clamped to what the
	// envelope's 10_000-cent per-request limit can pay for, then forwarded.
	body := []byte(`{"model":"gpt-4o","max_tokens":3443392227092449635,"max_completion_tokens":1000000000,"messages":[{"role":"user","content":"hello"}]}`)
	rec := f.doBody(t, "/v1/chat/completions", body, helmHeaders("idem-clamp", "gpt-4o"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", rec.Code, rec.Body.String())
	}
	quote := decodeHELM(t, rec).Quote
	const affordable = 10_000 * 1_000_000 / 1500 // gpt-4o output price, input ignored
	if quote == nil || quote.OutputTokens <= 0 || quote.OutputTokens > affordable {
		t.Fatalf("authorized output tokens = %+v, want 1..%d", quote, affordable)
	}
	if quote.MaxAmountCents > 10_000 {
		t.Fatalf("quote ceiling = %d cents, want within the 10000-cent per-request limit", quote.MaxAmountCents)
	}
	sent := sentOutputLimits(t, f.dispatch.body)
	if sent.MaxTokens != quote.OutputTokens || sent.MaxCompletionTokens != quote.OutputTokens {
		t.Fatalf("forwarded limits = %+v, want both %d", sent, quote.OutputTokens)
	}

	// A ceiling inside the mandate is forwarded unchanged.
	if rec := f.do(t, http.MethodPost, "/v1/chat/completions", "gpt-4o", helmHeaders("idem-small", "gpt-4o")); rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", rec.Code, rec.Body.String())
	}
	if sent := sentOutputLimits(t, f.dispatch.body); sent.MaxTokens != 64 {
		t.Fatalf("forwarded max_tokens = %d, want 64", sent.MaxTokens)
	}
}

// --- Reservation before dispatch ----------------------------------------------

func TestGatewayReservesBeforeDispatch(t *testing.T) {
	f := newGatewayFixture(t, inferencegateway.StalePriceFailClosed, inferencegateway.CostCapClamp, 2)
	var holdAtDispatch int64
	f.dispatch.afterDispatch = func() { holdAtDispatch = f.ledger.HoldCents() }
	rec := f.do(t, http.MethodPost, "/v1/chat/completions", "gpt-4o", helmHeaders("idem-hold", "gpt-4o"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", rec.Code, rec.Body.String())
	}
	quote := decodeHELM(t, rec).Quote
	if holdAtDispatch == 0 || holdAtDispatch != quote.MaxAmountCents {
		t.Fatalf("hold at dispatch = %d, want the quote ceiling %d", holdAtDispatch, quote.MaxAmountCents)
	}
	if f.ledger.HoldCents() != 0 {
		t.Fatalf("hold after settlement = %d, want 0", f.ledger.HoldCents())
	}
}

func TestGatewayInsufficientBalanceNeverDispatches(t *testing.T) {
	f := newGatewayFixture(t, inferencegateway.StalePriceFailClosed, inferencegateway.CostCapClamp, 2)
	if _, err := f.ledger.Reserve("other-dispatch", 100_000, "sha256:other"); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	rec := f.do(t, http.MethodPost, "/v1/chat/completions", "gpt-4o", helmHeaders("idem-broke", "gpt-4o"))
	if rec.Code != http.StatusForbidden || f.dispatch.called != 0 {
		t.Fatalf("status = %d, dispatch = %d; want 403 and no dispatch; body=%s", rec.Code, f.dispatch.called, rec.Body.String())
	}
	if meta := decodeHELM(t, rec); meta.ReasonCode != economic.SpendReasonBalanceInsufficient {
		t.Fatalf("reason = %s, want %s", meta.ReasonCode, economic.SpendReasonBalanceInsufficient)
	}
}

// TestGatewaySettlesDispatchThatOutlivesQuote covers finding 22-03: a quote that
// expires while the provider is still generating is settled, because the
// reservation proves the dispatch was authorized in time.
func TestGatewaySettlesDispatchThatOutlivesQuote(t *testing.T) {
	f := newGatewayFixture(t, inferencegateway.StalePriceFailClosed, inferencegateway.CostCapClamp, 2)
	f.dispatch.afterDispatch = func() { *f.clk = f.now.Add(10 * time.Minute) }
	rec := f.do(t, http.MethodPost, "/v1/chat/completions", "gpt-4o", helmHeaders("idem-slow", "gpt-4o"))
	if rec.Code != http.StatusOK || debitEntries(f.ledger) != 1 {
		t.Fatalf("status = %d, ledger entries = %d; want 200 and a settled debit; body=%s", rec.Code, debitEntries(f.ledger), rec.Body.String())
	}
}

// debitEntries counts posted balance debits; reservation holds and releases
// are ledger entries too, but they move no money.
func debitEntries(l *inferencegateway.BalanceLedger) int {
	n := 0
	for _, e := range l.Entries() {
		if e.Type == economic.UsageLedgerDebit {
			n++
		}
	}
	return n
}

func (f *gatewayFixture) doBody(t *testing.T, path string, body []byte, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	f.mux.ServeHTTP(rr, req)
	return rr
}

func decodeResponse(t *testing.T, rr *httptest.ResponseRecorder) json.RawMessage {
	t.Helper()
	var payload struct {
		Response json.RawMessage `json:"response"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode body %q: %v", rr.Body.String(), err)
	}
	return payload.Response
}

type outputLimits struct {
	MaxTokens           int64 `json:"max_tokens"`
	MaxCompletionTokens int64 `json:"max_completion_tokens"`
}

func sentOutputLimits(t *testing.T, body []byte) outputLimits {
	t.Helper()
	var sent outputLimits
	if err := json.Unmarshal(body, &sent); err != nil {
		t.Fatalf("decode dispatched body %q: %v", body, err)
	}
	return sent
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
