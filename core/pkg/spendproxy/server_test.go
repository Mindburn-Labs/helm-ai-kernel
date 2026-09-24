package spendproxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/inferencegateway"
)

// testConfigJSON is a full dogfood-shaped config against a mock provider:
// env-direct dispatches requested models as-is; env-sub allows only the
// substitute model and substitutes truthfully.
const testConfigJSON = `{
  "tenant_id": "tenant-test",
  "treasury_id": "treasury-test",
  "route_policy_id": "test-policy-v1",
  "currency": "USD",
  "platform_fee_bps": 0,
  "quote_ttl_seconds": 300,
  "price_ttl_hours": 24,
  "balance": {"account_id": "balance-test", "opening_cents": 2000},
  "request_defaults": {
    "workspace_id": "ws-test",
    "agent_id": "agent-live",
    "principal_id": "principal-test",
    "envelope_id": "env-direct"
  },
  "providers": [
    {"id": "mockai", "account_mode": "DIRECT", "terms_version": "2026-08-17", "legal_review_ref": "linear:HELM-615"}
  ],
  "prices": [
    {"provider_id": "mockai", "model_id": "base-model", "input_token_micro_cents": 5000, "output_token_micro_cents": 10000},
    {"provider_id": "mockai", "model_id": "mini-model", "input_token_micro_cents": 1000, "output_token_micro_cents": 2000}
  ],
  "envelopes": [
    {
      "id": "env-direct",
      "agent_id": "agent-live",
      "principal_id": "principal-test",
      "budget_id": "budget-direct",
      "max_amount_cents": 1000,
      "per_request_max_cents": 50,
      "allowed_providers": ["mockai"],
      "allowed_models": ["base-model", "mini-model"],
      "fallback_routes": [
        {"provider_id": "mockai", "model_id": "base-model"},
        {"provider_id": "mockai", "model_id": "mini-model"}
      ],
      "allow_model_substitution": false
    },
    {
      "id": "env-sub",
      "agent_id": "agent-replay",
      "principal_id": "principal-test",
      "budget_id": "budget-sub",
      "max_amount_cents": 1000,
      "per_request_max_cents": 50,
      "allowed_providers": ["mockai"],
      "allowed_models": ["mini-model"],
      "fallback_routes": [
        {"provider_id": "mockai", "model_id": "mini-model"}
      ],
      "allow_model_substitution": true
    }
  ]
}`

// mockUpstream is an OpenAI-compatible fake provider that records requests.
type mockUpstream struct {
	server          *httptest.Server
	calls           atomic.Int64
	lastBody        atomic.Value // []byte
	lastAuth        atomic.Value // string
	responseContent atomic.Value // string
	// completionTokens overrides the reported usage (default 20); a provider
	// that ignores the forwarded max_tokens reports more than it was allowed.
	completionTokens atomic.Int64
	delay            atomic.Int64 // time.Duration before responding
}

func newMockUpstream(t *testing.T) *mockUpstream {
	t.Helper()
	m := &mockUpstream{}
	mux := http.NewServeMux()
	handler := func(w http.ResponseWriter, r *http.Request) {
		n := m.calls.Add(1)
		time.Sleep(time.Duration(m.delay.Load()))
		body, _ := io.ReadAll(r.Body)
		m.lastBody.Store(body)
		m.lastAuth.Store(r.Header.Get("Authorization"))

		var req struct {
			Model  string `json:"model"`
			Stream bool   `json:"stream"`
		}
		_ = json.Unmarshal(body, &req)

		if req.Stream {
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			flusher := w.(http.Flusher)
			chunks := []string{
				`{"id":"cmpl-stream-1","object":"chat.completion.chunk","model":"` + req.Model + `","choices":[{"delta":{"content":"Hel"}}]}`,
				`{"id":"cmpl-stream-1","object":"chat.completion.chunk","model":"` + req.Model + `","choices":[{"delta":{"content":"lo"}}]}`,
				`{"id":"cmpl-stream-1","object":"chat.completion.chunk","model":"` + req.Model + `","choices":[],"usage":{"prompt_tokens":120,"completion_tokens":30}}`,
			}
			for _, c := range chunks {
				_, _ = fmt.Fprintf(w, "data: %s\n\n", c)
				flusher.Flush()
			}
			_, _ = fmt.Fprint(w, "data: [DONE]\n\n")
			flusher.Flush()
			return
		}

		content := "ok"
		if configured, _ := m.responseContent.Load().(string); configured != "" {
			content = configured
		}
		completion := m.completionTokens.Load()
		if completion == 0 {
			completion = 20
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"id":"cmpl-mock-%d","object":"chat.completion","model":%q,`+
			`"choices":[{"index":0,"message":{"role":"assistant","content":%q},"finish_reason":"stop"}],`+
			`"usage":{"prompt_tokens":100,"completion_tokens":%d}}`, n, req.Model, content, completion)
	}
	mux.HandleFunc("/v1/chat/completions", handler)
	mux.HandleFunc("/v1/responses", handler)
	m.server = httptest.NewServer(mux)
	t.Cleanup(m.server.Close)
	return m
}

// upstreamField decodes one integer field of the last forwarded request body.
func (m *mockUpstream) upstreamField(t *testing.T, field string) (int64, bool) {
	t.Helper()
	raw, _ := m.lastBody.Load().([]byte)
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("decode upstream body: %v", err)
	}
	v, ok := fields[field]
	if !ok {
		return 0, false
	}
	var n int64
	if err := json.Unmarshal(v, &n); err != nil {
		t.Fatalf("decode upstream %s: %v", field, err)
	}
	return n, true
}

func (m *mockUpstream) upstreamModel(t *testing.T) string {
	t.Helper()
	raw, _ := m.lastBody.Load().([]byte)
	var req struct {
		Model string `json:"model"`
	}
	if err := json.Unmarshal(raw, &req); err != nil {
		t.Fatalf("decode upstream body: %v", err)
	}
	return req.Model
}

type proxyFixture struct {
	server      *Server
	http        *httptest.Server
	upstream    *mockUpstream
	receiptsDir string
	configPath  string

	logMu sync.Mutex
	logs  []string
}

func newProxyFixture(t *testing.T) *proxyFixture {
	t.Helper()
	return newProxyFixtureWithConfig(t, testConfigJSON)
}

func newProxyFixtureWithConfig(t *testing.T, configJSON string) *proxyFixture {
	t.Helper()
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(configPath, []byte(configJSON), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	upstream := newMockUpstream(t)
	receiptsDir := filepath.Join(dir, "receipts")
	f := &proxyFixture{upstream: upstream, receiptsDir: receiptsDir, configPath: configPath}
	f.start(t)
	return f
}

func (f *proxyFixture) start(t *testing.T) {
	t.Helper()
	cfg, sourceHash, err := LoadConfig(f.configPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	server, err := NewServer(ServerOptions{
		Config:          cfg,
		SourceHash:      sourceHash,
		ReceiptsDir:     f.receiptsDir,
		UpstreamBaseURL: f.upstream.server.URL + "/v1",
		UpstreamAPIKey:  "test-key",
		SigningSecret:   "0101010101010101010101010101010101010101010101010101010101010101",
		Logf: func(format string, args ...any) {
			line := fmt.Sprintf(format, args...)
			f.logMu.Lock()
			f.logs = append(f.logs, line)
			f.logMu.Unlock()
			t.Log(line)
		},
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	f.server = server
	f.http = httptest.NewServer(server.Handler())
	t.Cleanup(func() {
		f.http.Close()
		_ = server.Close()
	})
}

func (f *proxyFixture) restart(t *testing.T) {
	t.Helper()
	f.http.Close()
	if err := f.server.Close(); err != nil {
		t.Fatalf("close server: %v", err)
	}
	f.start(t)
}

// alerts returns the logged lines that raise an operator alert.
func (f *proxyFixture) alerts() []string {
	f.logMu.Lock()
	defer f.logMu.Unlock()
	var out []string
	for _, line := range f.logs {
		if strings.Contains(line, "ALERT") {
			out = append(out, line)
		}
	}
	return out
}

// post sends an OpenAI-shaped request. It carries max_tokens 64 unless extra
// overrides it; an extra value of nil removes the field.
func (f *proxyFixture) post(t *testing.T, path, model, envelope, idem string, extra map[string]any) *http.Response {
	t.Helper()
	payload := map[string]any{
		"model":      model,
		"messages":   []map[string]string{{"role": "user", "content": "hello governed world"}},
		"max_tokens": 64,
	}
	for k, v := range extra {
		if v == nil {
			delete(payload, k)
			continue
		}
		payload[k] = v
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, f.http.URL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if envelope != "" {
		req.Header.Set(inferencegateway.HeaderAgent, agentForEnvelope(envelope))
		req.Header.Set(inferencegateway.HeaderSpendEnvelope, envelope)
		req.Header.Set(inferencegateway.HeaderPrincipal, "principal-test")
		req.Header.Set(inferencegateway.HeaderWorkspace, "ws-test")
	}
	if idem != "" {
		req.Header.Set(inferencegateway.HeaderIdempotencyKey, idem)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func agentForEnvelope(envelope string) string {
	if envelope == "env-sub" {
		return "agent-replay"
	}
	return "agent-live"
}

func (f *proxyFixture) records(t *testing.T) []*ReceiptRecord {
	t.Helper()
	records, err := LoadRecords(filepath.Join(f.receiptsDir, ReceiptLogName))
	if err != nil {
		t.Fatalf("load records: %v", err)
	}
	return records
}

func recordsByKind(records []*ReceiptRecord) map[RecordKind][]*ReceiptRecord {
	out := make(map[RecordKind][]*ReceiptRecord)
	for _, rec := range records {
		out[rec.Kind] = append(out[rec.Kind], rec)
	}
	return out
}

func TestGovernedRouteEndToEnd(t *testing.T) {
	f := newProxyFixture(t)
	resp := f.post(t, "/v1/chat/completions", "base-model", "env-direct", "idem-e2e", nil)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body=%s", resp.StatusCode, body)
	}
	if got := resp.Header.Get("X-HELM-Verdict"); got != "ALLOW" {
		t.Fatalf("verdict header = %q, want ALLOW", got)
	}
	if resp.Header.Get("X-HELM-Usage-Receipt-Hash") == "" {
		t.Fatal("usage receipt hash header must be set")
	}

	// The client must receive the RAW OpenAI body, not the governed envelope.
	var openAI struct {
		ID      string `json:"id"`
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Response json.RawMessage `json:"response"`
	}
	raw, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(raw, &openAI); err != nil {
		t.Fatalf("decode response: %v (%s)", err, raw)
	}
	if openAI.ID != "cmpl-mock-1" || len(openAI.Choices) != 1 {
		t.Fatalf("response is not the raw provider body: %s", raw)
	}
	if openAI.Response != nil {
		t.Fatalf("response still wrapped in governed envelope: %s", raw)
	}

	// All four receipts persisted; verdict receipt signed and trusted.
	byKind := recordsByKind(f.records(t))
	for _, kind := range []RecordKind{RecordRouteQuote, RecordBudgetVerdict, RecordUsage, RecordSettlement} {
		if len(byKind[kind]) != 1 {
			t.Fatalf("%s records = %d, want 1", kind, len(byKind[kind]))
		}
	}
	verdict := byKind[RecordBudgetVerdict][0].BudgetVerdict
	if verdict.Signature == "" || verdict.SignatureKeyID != f.server.SigningKeyID() {
		t.Fatalf("verdict receipt is not signed by the issuer: %+v", verdict.SignatureKeyID)
	}
	keys, err := OpenTrustedKeys(f.receiptsDir)
	if err != nil {
		t.Fatalf("open trusted keys: %v", err)
	}
	if err := keys.Verify(verdict); err != nil {
		t.Fatalf("verdict signature verification failed: %v", err)
	}

	// Usage 100 in + 20 out at 5000/10000 micro-cents = 700000 -> 1 cent.
	usage := byKind[RecordUsage][0].Usage
	if usage.ProviderCostCents != 1 || usage.BalanceDebitCents != 1 {
		t.Fatalf("usage cost = %d/%d, want 1/1", usage.ProviderCostCents, usage.BalanceDebitCents)
	}
	if got := f.server.BalanceCents(); got != 1999 {
		t.Fatalf("balance = %d, want 1999", got)
	}
	if f.upstream.calls.Load() != 1 {
		t.Fatalf("upstream calls = %d, want 1", f.upstream.calls.Load())
	}
	if auth, _ := f.upstream.lastAuth.Load().(string); auth != "Bearer test-key" {
		t.Fatalf("upstream auth = %q", auth)
	}
}

func TestDeniedRouteNoDispatchAndDurableAudit(t *testing.T) {
	f := newProxyFixture(t)
	// env-direct does not allow unknown models and has substitution disabled.
	resp := f.post(t, "/v1/chat/completions", "unknown-model", "env-direct", "idem-denied", nil)
	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 403; body=%s", resp.StatusCode, body)
	}
	if f.upstream.calls.Load() != 0 {
		t.Fatal("no provider dispatch may occur on a denied route")
	}
	if got := f.server.BalanceCents(); got != 2000 {
		t.Fatalf("balance = %d, want untouched 2000", got)
	}
}

func TestModelSubstitutionRoutesTruthfully(t *testing.T) {
	f := newProxyFixture(t)
	// env-sub allows only mini-model; requesting base-model substitutes.
	resp := f.post(t, "/v1/chat/completions", "base-model", "env-sub", "idem-sub", nil)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body=%s", resp.StatusCode, body)
	}
	// The upstream must have received the SUBSTITUTE model.
	if got := f.upstream.upstreamModel(t); got != "mini-model" {
		t.Fatalf("upstream model = %q, want mini-model", got)
	}
	byKind := recordsByKind(f.records(t))
	quote := byKind[RecordRouteQuote][0].RouteQuote
	if !quote.ModelSubstituted {
		t.Fatal("route quote must record model_substituted=true")
	}
	if quote.RequestedModelID != "base-model" || quote.SelectedModelID != "mini-model" {
		t.Fatalf("quote routes %s->%s, want base-model->mini-model", quote.RequestedModelID, quote.SelectedModelID)
	}
	usage := byKind[RecordUsage][0].Usage
	if usage.ModelID != "mini-model" {
		t.Fatalf("usage receipt model = %q, want mini-model", usage.ModelID)
	}
}

func TestStreamingRouteFailsClosedBeforeDispatch(t *testing.T) {
	f := newProxyFixture(t)
	resp := f.post(t, "/v1/chat/completions", "base-model", "env-direct", "idem-stream",
		map[string]any{"stream": true})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 403; body=%s", resp.StatusCode, body)
	}
	if f.upstream.calls.Load() != 0 {
		t.Fatalf("upstream calls = %d, want 0", f.upstream.calls.Load())
	}
	if len(f.records(t)) != 0 {
		t.Fatal("blocked stream must not create spend receipts")
	}
}

func TestHeaderlessTrafficGovernedByDefaults(t *testing.T) {
	f := newProxyFixture(t)
	// No X-HELM headers at all: a stock OpenAI client repointed via
	// OPENAI_BASE_URL. The configured defaults must govern it.
	resp := f.post(t, "/v1/chat/completions", "base-model", "", "", nil)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body=%s", resp.StatusCode, body)
	}
	byKind := recordsByKind(f.records(t))
	if len(byKind[RecordUsage]) != 1 {
		t.Fatalf("usage records = %d, want 1", len(byKind[RecordUsage]))
	}
	usage := byKind[RecordUsage][0].Usage
	if usage.EnvelopeID != "env-direct" || usage.AgentID != "agent-live" {
		t.Fatalf("header-less traffic governed under %s/%s, want env-direct/agent-live", usage.EnvelopeID, usage.AgentID)
	}

	// Defaults do not waive the output ceiling.
	resp = f.post(t, "/v1/chat/completions", "base-model", "", "", map[string]any{"max_tokens": nil})
	if resp.StatusCode != http.StatusBadRequest || f.upstream.calls.Load() != 1 {
		t.Fatalf("status = %d, upstream calls = %d; want 400 and no new dispatch", resp.StatusCode, f.upstream.calls.Load())
	}
}

func TestRestartRestoresBalanceAndIdempotency(t *testing.T) {
	f := newProxyFixture(t)
	first := f.post(t, "/v1/chat/completions", "base-model", "env-direct", "idem-restart", nil)
	if first.StatusCode != http.StatusOK {
		t.Fatalf("first status = %d", first.StatusCode)
	}
	if got := f.server.BalanceCents(); got != 1999 {
		t.Fatalf("balance after first = %d, want 1999", got)
	}

	f.restart(t)
	if got := f.server.BalanceCents(); got != 1999 {
		t.Fatalf("balance after restart = %d, want 1999 (durable debit replay)", got)
	}
	if sum := f.server.ReplaySummary(); sum.RestoredSettlements != 1 || sum.DebitedCents != 1 {
		t.Fatalf("replay summary = %+v, want 1 settlement / 1 cent", sum)
	}

	// Same idempotency key after restart: the settled key is refused without
	// a provider call (the response body is not retained across restarts), with
	// no double debit and no duplicate usage/settlement records.
	second := f.post(t, "/v1/chat/completions", "base-model", "env-direct", "idem-restart", nil)
	if second.StatusCode != http.StatusConflict {
		body, _ := io.ReadAll(second.Body)
		t.Fatalf("replay status = %d, want 409; body=%s", second.StatusCode, body)
	}
	if got := f.upstream.calls.Load(); got != 1 {
		t.Fatalf("upstream calls = %d, want 1: a settled key must not reach the provider", got)
	}
	if got := f.server.BalanceCents(); got != 1999 {
		t.Fatalf("balance after replay = %d, want 1999", got)
	}
	byKind := recordsByKind(f.records(t))
	if len(byKind[RecordUsage]) != 1 || len(byKind[RecordSettlement]) != 1 {
		t.Fatalf("replay duplicated receipts: %d usage / %d settlement",
			len(byKind[RecordUsage]), len(byKind[RecordSettlement]))
	}
}

func TestBlockedProviderResponsePersistsSettlementAcrossRestart(t *testing.T) {
	f := newProxyFixture(t)
	f.upstream.responseContent.Store("api_key=sk_live_example1234")
	resp := f.post(t, "/v1/chat/completions", "base-model", "env-direct", "idem-privacy-response", nil)
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusBadGateway || bytes.Contains(body, []byte("sk_live")) {
		t.Fatalf("status = %d, body=%s", resp.StatusCode, body)
	}
	byKind := recordsByKind(f.records(t))
	for _, kind := range []RecordKind{RecordRouteQuote, RecordBudgetVerdict, RecordUsage, RecordSettlement} {
		if len(byKind[kind]) != 1 {
			t.Fatalf("%s records = %d, want 1", kind, len(byKind[kind]))
		}
	}
	if got := f.server.BalanceCents(); got != 1999 {
		t.Fatalf("balance after blocked response = %d, want 1999", got)
	}

	f.restart(t)
	if got := f.server.BalanceCents(); got != 1999 {
		t.Fatalf("balance after restart = %d, want durable debit 1999", got)
	}
	if sum := f.server.ReplaySummary(); sum.RestoredSettlements != 1 || sum.DebitedCents != 1 {
		t.Fatalf("replay summary = %+v, want 1 settlement / 1 cent", sum)
	}
}

func TestExportEvidencePacksOfflineVerifiable(t *testing.T) {
	f := newProxyFixture(t)
	resp := f.post(t, "/v1/chat/completions", "base-model", "env-direct", "idem-export", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}

	outDir := filepath.Join(t.TempDir(), "packs")
	results, err := ExportEvidencePacks(f.receiptsDir, outDir, "")
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("export results = %d, want 1", len(results))
	}
	res := results[0]
	if !res.OfflineVerified {
		t.Fatalf("pack not offline-verified: %+v", res)
	}
	if !res.SignatureVerified || res.SignatureKeyID != f.server.SigningKeyID() {
		t.Fatalf("verdict signature not verified against registry: %+v", res)
	}
	if len(res.ReceiptsVerified) != 4 {
		t.Fatalf("receipts verified = %v, want all 4", res.ReceiptsVerified)
	}
	manifest := filepath.Join(res.OutputDir, "manifest.json")
	if _, err := os.Stat(manifest); err != nil {
		t.Fatalf("pack manifest missing: %v", err)
	}
}

func TestUnknownEnvelopeFailsClosed(t *testing.T) {
	f := newProxyFixture(t)
	resp := f.post(t, "/v1/chat/completions", "base-model", "env-missing", "idem-x", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if f.upstream.calls.Load() != 0 {
		t.Fatal("no dispatch may occur for an unknown envelope")
	}
}

func TestConfigRejectsUnroutedAllowedModel(t *testing.T) {
	dir := t.TempDir()
	var cfg map[string]any
	if err := json.Unmarshal([]byte(testConfigJSON), &cfg); err != nil {
		t.Fatalf("parse test config: %v", err)
	}
	envelopes := cfg["envelopes"].([]any)
	first := envelopes[0].(map[string]any)
	first["fallback_routes"] = []any{
		map[string]any{"provider_id": "mockai", "model_id": "mini-model"},
	}
	raw, _ := json.Marshal(cfg)
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if _, _, err := LoadConfig(path); err == nil ||
		!strings.Contains(err.Error(), "not in fallback_routes") {
		t.Fatalf("expected unrouted-model config error, got %v", err)
	}
}

func TestIssuerDeterministicFromSeed(t *testing.T) {
	seed := "0202020202020202020202020202020202020202020202020202020202020202"
	a, fromPass, err := NewIssuer(seed)
	if err != nil || fromPass {
		t.Fatalf("issuer a: err=%v fromPassphrase=%v", err, fromPass)
	}
	b, _, err := NewIssuer(seed)
	if err != nil {
		t.Fatalf("issuer b: %v", err)
	}
	if a.KeyID() != b.KeyID() {
		t.Fatalf("same seed must yield same key id: %s != %s", a.KeyID(), b.KeyID())
	}
	if _, fromPass, err = NewIssuer("not-a-seed-passphrase"); err != nil || !fromPass {
		t.Fatalf("passphrase derivation: err=%v fromPassphrase=%v", err, fromPass)
	}
}

func TestTrustedKeysRefuseRebinding(t *testing.T) {
	dir := t.TempDir()
	keys, err := OpenTrustedKeys(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	a, _, err := NewIssuer("0303030303030303030303030303030303030303030303030303030303030303")
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	b, _, err := NewIssuer("0404040404040404040404040404040404040404040404040404040404040404")
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	if err := keys.Register("key-1", a.PublicKey()); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := keys.Register("key-1", a.PublicKey()); err != nil {
		t.Fatalf("idempotent re-register: %v", err)
	}
	if err := keys.Register("key-1", b.PublicKey()); err == nil {
		t.Fatal("re-binding a key id to a different key must fail")
	}
	// Registry survives reopen.
	reopened, err := OpenTrustedKeys(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if _, ok := reopened.PublicKeyFor("key-1"); !ok {
		t.Fatal("registered key lost on reopen")
	}
}

func TestFileStoreRejectsCorruptLog(t *testing.T) {
	dir := t.TempDir()
	store, err := OpenFileStore(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := store.Append(&ReceiptRecord{Kind: RecordRouteQuote, TenantID: "t"}); err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	path := filepath.Join(dir, ReceiptLogName)
	if err := os.WriteFile(path, []byte("{\"kind\":\"route_quote\"}\nnot-json\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := LoadRecords(path); err == nil {
		t.Fatal("corrupt log line must fail loading")
	}
}

func readBody(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return body
}

// TestReplayedKeyNeverReachesProvider is audit verifier VE's 22-01 PoC as a
// regression test. With an opening balance of 1 cent, one committed request
// used to buy unlimited provider calls: replays of its key (new prompt, new
// model, after a restart) all re-dispatched at a zero balance.
func TestReplayedKeyNeverReachesProvider(t *testing.T) {
	cfg := strings.Replace(testConfigJSON, `"opening_cents": 2000`, `"opening_cents": 1`, 1)
	f := newProxyFixtureWithConfig(t, cfg)

	first := f.post(t, "/v1/chat/completions", "base-model", "env-direct", "K", nil)
	firstBody := readBody(t, first)
	if first.StatusCode != http.StatusOK || f.server.BalanceCents() != 0 {
		t.Fatalf("first status = %d, balance = %d; want 200 and 0", first.StatusCode, f.server.BalanceCents())
	}

	// A fresh key at a zero balance: the reservation is refused before dispatch.
	if resp := f.post(t, "/v1/chat/completions", "base-model", "env-direct", "K2", nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("fresh key at zero balance: status = %d, want 403", resp.StatusCode)
	}

	// An identical replay returns the stored response.
	replay := f.post(t, "/v1/chat/completions", "base-model", "env-direct", "K", nil)
	if body := readBody(t, replay); replay.StatusCode != http.StatusOK || !bytes.Equal(body, firstBody) {
		t.Fatalf("identical replay: status = %d, body = %s; want 200 with the stored response %s", replay.StatusCode, body, firstBody)
	}

	// Reusing the key for a different prompt or model is refused.
	for i, model := range []string{"base-model", "mini-model", "base-model"} {
		resp := f.post(t, "/v1/chat/completions", model, "env-direct", "K", map[string]any{
			"messages": []map[string]string{{"role": "user", "content": fmt.Sprintf("completely different prompt %d", i)}},
		})
		if resp.StatusCode != http.StatusConflict {
			t.Fatalf("reused key %d: status = %d, want 409", i, resp.StatusCode)
		}
	}

	f.restart(t)
	if resp := f.post(t, "/v1/chat/completions", "base-model", "env-direct", "K", nil); resp.StatusCode != http.StatusConflict {
		t.Fatalf("replay after restart: status = %d, want 409", resp.StatusCode)
	}

	byKind := recordsByKind(f.records(t))
	if got := f.upstream.calls.Load(); got != 1 {
		t.Fatalf("upstream calls = %d, want 1: only the committed request may reach the provider", got)
	}
	if len(byKind[RecordUsage]) != 1 || f.server.BalanceCents() != 0 {
		t.Fatalf("usage records = %d, balance = %d; want 1 and 0", len(byKind[RecordUsage]), f.server.BalanceCents())
	}
}

// TestOutputLimitRequiredClampedAndForwarded is VE's 22-02 PoC: the output
// ceiling was optional, defaulted to 256 in the quote and was never sent to the
// provider, so the quote bounded nothing.
func TestOutputLimitRequiredClampedAndForwarded(t *testing.T) {
	// env-direct allows 50 cents per request; base-model output is 10000 µ¢
	// per token, so no request may authorize more than 5000 output tokens.
	const mandateTokens = 50 * 1_000_000 / 10_000

	for _, tc := range []struct {
		name, path, field string
		extra             map[string]any
	}{
		{"chat max_tokens", "/v1/chat/completions", "max_tokens", map[string]any{"max_tokens": 40000}},
		{"chat max_completion_tokens", "/v1/chat/completions", "max_completion_tokens", map[string]any{"max_tokens": nil, "max_completion_tokens": 40000}},
		{"responses max_output_tokens", "/v1/responses", "max_output_tokens", map[string]any{"max_tokens": nil, "max_output_tokens": 40000}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newProxyFixture(t)
			resp := f.post(t, tc.path, "base-model", "env-direct", "idem-limit", tc.extra)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, body=%s", resp.StatusCode, readBody(t, resp))
			}
			sent, ok := f.upstream.upstreamField(t, tc.field)
			if !ok || sent <= 0 || sent > mandateTokens {
				t.Fatalf("forwarded %s = %d (present %v), want 1..%d", tc.field, sent, ok, mandateTokens)
			}
			quote := recordsByKind(f.records(t))[RecordRouteQuote][0].RouteQuote
			if quote.OutputTokens != sent {
				t.Fatalf("quoted output tokens = %d, forwarded %d; they must match", quote.OutputTokens, sent)
			}
		})
	}

	for _, tc := range []struct {
		name, path string
		extra      map[string]any
	}{
		{"chat without a ceiling", "/v1/chat/completions", map[string]any{"max_tokens": nil}},
		{"responses without a ceiling", "/v1/responses", map[string]any{"max_tokens": nil}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newProxyFixture(t)
			resp := f.post(t, tc.path, "base-model", "env-direct", "idem-nolimit", tc.extra)
			if resp.StatusCode != http.StatusBadRequest || f.upstream.calls.Load() != 0 {
				t.Fatalf("status = %d, upstream calls = %d; want 400 and no dispatch", resp.StatusCode, f.upstream.calls.Load())
			}
		})
	}
}

// TestOverageIsDebitedRecordedAndAlerted is VE's 22-02 settlement half: a
// provider that bills 40000 output tokens (401 cents here) used to be debited
// at the 1-cent quote, with the clamped cost in the receipt.
func TestOverageIsDebitedRecordedAndAlerted(t *testing.T) {
	f := newProxyFixture(t)
	f.upstream.completionTokens.Store(40000)
	resp := f.post(t, "/v1/chat/completions", "base-model", "env-direct", "idem-overage", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body=%s", resp.StatusCode, readBody(t, resp))
	}
	// 100 in * 5000 + 40000 out * 10000 = 400_500_000 µ¢ -> 401 cents.
	const actual = 401
	byKind := recordsByKind(f.records(t))
	usageRec := byKind[RecordUsage][0]
	if usageRec.Usage.BalanceDebitCents != actual || usageRec.Usage.ProviderCostCents != actual {
		t.Fatalf("usage debit/provider cost = %d/%d, want %d", usageRec.Usage.BalanceDebitCents, usageRec.Usage.ProviderCostCents, actual)
	}
	if got := f.server.BalanceCents(); got != 2000-actual {
		t.Fatalf("balance = %d, want %d", got, 2000-actual)
	}
	if !strings.Contains(usageRec.Note, "overage") || usageRec.Usage.Metadata["overage_cents"] == "" {
		t.Fatalf("overage not recorded: note=%q metadata=%v", usageRec.Note, usageRec.Usage.Metadata)
	}
	if len(f.alerts()) != 1 {
		t.Fatalf("alerts = %v, want one overage alert", f.alerts())
	}

	// The debit survives a restart.
	f.restart(t)
	if got := f.server.BalanceCents(); got != 2000-actual {
		t.Fatalf("balance after restart = %d, want %d", got, 2000-actual)
	}
}

// TestUndebitableOverageIsRecordedAndAlerted: when the balance cannot absorb
// the overage, settlement fails closed and leaves a signed settle_failed line
// and an alert instead of a silent gap.
func TestUndebitableOverageIsRecordedAndAlerted(t *testing.T) {
	cfg := strings.Replace(testConfigJSON, `"opening_cents": 2000`, `"opening_cents": 5`, 1)
	f := newProxyFixtureWithConfig(t, cfg)
	f.upstream.completionTokens.Store(40000)
	resp := f.post(t, "/v1/chat/completions", "base-model", "env-direct", "idem-undebitable", nil)
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("status = 200; a settlement the balance cannot cover must not succeed")
	}
	byKind := recordsByKind(f.records(t))
	if len(byKind[RecordSettleFailed]) != 1 || !strings.Contains(byKind[RecordSettleFailed][0].Note, "401") {
		t.Fatalf("settle_failed records = %+v, want one naming the 401-cent actual cost", byKind[RecordSettleFailed])
	}
	if byKind[RecordSettleFailed][0].PayloadSignature == "" {
		t.Fatal("settle_failed record must be signed")
	}
	if len(f.alerts()) != 1 {
		t.Fatalf("alerts = %v, want one settlement-failure alert", f.alerts())
	}
}

// TestDispatchOutlivingQuoteTTLStillSettles is the 22-03 PoC: a dispatch that
// outlived the quote TTL was billed upstream but answered 403 and never debited
// or recorded.
func TestDispatchOutlivingQuoteTTLStillSettles(t *testing.T) {
	cfg := strings.Replace(testConfigJSON, `"quote_ttl_seconds": 300`, `"quote_ttl_seconds": 1`, 1)
	f := newProxyFixtureWithConfig(t, cfg)
	f.upstream.delay.Store(int64(1200 * time.Millisecond))
	resp := f.post(t, "/v1/chat/completions", "base-model", "env-direct", "idem-slow", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body=%s", resp.StatusCode, readBody(t, resp))
	}
	byKind := recordsByKind(f.records(t))
	if len(byKind[RecordUsage]) != 1 || len(byKind[RecordSettlement]) != 1 || f.server.BalanceCents() != 1999 {
		t.Fatalf("usage = %d, settlement = %d, balance = %d; want 1, 1, 1999",
			len(byKind[RecordUsage]), len(byKind[RecordSettlement]), f.server.BalanceCents())
	}
}
