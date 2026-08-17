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
	"sync/atomic"
	"testing"

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
	server   *httptest.Server
	calls    atomic.Int64
	lastBody atomic.Value // []byte
	lastAuth atomic.Value // string
}

func newMockUpstream(t *testing.T) *mockUpstream {
	t.Helper()
	m := &mockUpstream{}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		m.calls.Add(1)
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

		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"id":"cmpl-mock-1","object":"chat.completion","model":%q,`+
			`"choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],`+
			`"usage":{"prompt_tokens":100,"completion_tokens":20}}`, req.Model)
	})
	m.server = httptest.NewServer(mux)
	t.Cleanup(m.server.Close)
	return m
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
}

func newProxyFixture(t *testing.T) *proxyFixture {
	t.Helper()
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(configPath, []byte(testConfigJSON), 0o600); err != nil {
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
		Logf:            t.Logf,
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

func (f *proxyFixture) post(t *testing.T, path, model, envelope, idem string, extra map[string]any) *http.Response {
	t.Helper()
	payload := map[string]any{
		"model":    model,
		"messages": []map[string]string{{"role": "user", "content": "hello governed world"}},
	}
	for k, v := range extra {
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

func TestStreamingRouteSettlesAndPersists(t *testing.T) {
	f := newProxyFixture(t)
	resp := f.post(t, "/v1/chat/completions", "base-model", "env-direct", "idem-stream",
		map[string]any{"stream": true})
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body=%s", resp.StatusCode, body)
	}
	if resp.Header.Get("X-HELM-Route-Quote-Hash") == "" {
		t.Fatal("streaming response must carry the route quote hash header")
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read stream: %v", err)
	}
	streamText := string(raw)
	if !strings.Contains(streamText, `"content":"Hel"`) || !strings.Contains(streamText, "data: [DONE]") {
		t.Fatalf("SSE stream did not pass through verbatim: %s", streamText)
	}

	// The proxy must have asked the upstream for the usage chunk.
	upstreamBody, _ := f.upstream.lastBody.Load().([]byte)
	if !strings.Contains(string(upstreamBody), `"include_usage":true`) {
		t.Fatalf("upstream request missing stream_options.include_usage: %s", upstreamBody)
	}

	byKind := recordsByKind(f.records(t))
	for _, kind := range []RecordKind{RecordRouteQuote, RecordBudgetVerdict, RecordUsage, RecordSettlement} {
		if len(byKind[kind]) != 1 {
			t.Fatalf("%s records = %d, want 1", kind, len(byKind[kind]))
		}
	}
	usage := byKind[RecordUsage][0].Usage
	if usage.InputTokens != 120 || usage.OutputTokens != 30 {
		t.Fatalf("usage tokens = %d/%d, want 120/30 from the usage chunk", usage.InputTokens, usage.OutputTokens)
	}
	// 120*5000 + 30*10000 = 900000 micro-cents -> 1 cent.
	if usage.BalanceDebitCents != 1 {
		t.Fatalf("stream debit = %d, want 1", usage.BalanceDebitCents)
	}
	if got := f.server.BalanceCents(); got != 1999 {
		t.Fatalf("balance = %d, want 1999", got)
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

	// Same idempotency key after restart: replay, no double debit, no
	// duplicate usage/settlement records.
	second := f.post(t, "/v1/chat/completions", "base-model", "env-direct", "idem-restart", nil)
	if second.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(second.Body)
		t.Fatalf("replay status = %d, body=%s", second.StatusCode, body)
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
