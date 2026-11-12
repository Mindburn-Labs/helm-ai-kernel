// quantum_posture: these tests verify the spend proxy's classical Ed25519
// receipt signatures against a pinned key and generate a throwaway Ed25519 key
// to show a foreign key verifies nothing; no post-quantum primitive is used.

package spendproxy

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
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

// newProxyFixtureWithUpstream runs the proxy against a provider the test
// scripts, instead of the well-behaved mock.
func newProxyFixtureWithUpstream(t *testing.T, configJSON string, handler http.HandlerFunc) *proxyFixture {
	t.Helper()
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(configPath, []byte(configJSON), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	upstream := httptest.NewServer(handler)
	t.Cleanup(upstream.Close)
	f := &proxyFixture{upstream: &mockUpstream{server: upstream}, receiptsDir: filepath.Join(dir, "receipts"), configPath: configPath}
	f.start(t)
	return f
}

// twoCentConfig is the test config with env-direct limited to 2 cents in all.
func twoCentConfig() string {
	return strings.Replace(testConfigJSON, `"max_amount_cents": 1000,
      "per_request_max_cents": 50,`, `"max_amount_cents": 2,
      "per_request_max_cents": 2,`, 1)
}

// providerReply answers like the mock provider: 100 input and 20 output tokens.
func providerReply(w http.ResponseWriter, model string, n int64) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = fmt.Fprintf(w, `{"id":"cmpl-%d","object":"chat.completion","model":%q,`+
		`"choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],`+
		`"usage":{"prompt_tokens":100,"completion_tokens":20}}`, n, model)
}

func requestModel(r *http.Request) string {
	body, _ := io.ReadAll(r.Body)
	var req struct {
		Model string `json:"model"`
	}
	_ = json.Unmarshal(body, &req)
	return req.Model
}

// held reports the cents the proxy keeps from the balance for its dispatches:
// debited or still reserved.
func (f *proxyFixture) held() int64 {
	return 2000 - f.server.BalanceCents() + f.server.ledger.HoldCents()
}

// TestEnvelopeLimitStopsSpendThroughTheProxy (helm-tracker#313, audit H7): an
// envelope's max_amount_cents is spent by the requests it admits. Each request
// here holds and costs 1 cent, so a 2-cent envelope admits two of ten.
func TestEnvelopeLimitStopsSpendThroughTheProxy(t *testing.T) {
	for _, concurrent := range []bool{false, true} {
		t.Run(fmt.Sprintf("concurrent=%v", concurrent), func(t *testing.T) {
			f := newProxyFixtureWithConfig(t, twoCentConfig())
			var ok atomic.Int64
			var wg sync.WaitGroup
			for i := range 10 {
				send := func() {
					resp := f.post(t, "/v1/chat/completions", "base-model", "env-direct", fmt.Sprintf("idem-env-%d", i), nil)
					if resp.StatusCode == http.StatusOK {
						ok.Add(1)
					}
				}
				if concurrent {
					wg.Add(1)
					go func() { defer wg.Done(); send() }()
				} else {
					send()
				}
			}
			wg.Wait()
			if ok.Load() > 2 || f.upstream.calls.Load() > 2 || 2000-f.server.BalanceCents() > 2 {
				t.Fatalf("a 2-cent envelope admitted %d requests, dispatched %d and debited %d cents",
					ok.Load(), f.upstream.calls.Load(), 2000-f.server.BalanceCents())
			}
			if ok.Load() == 0 {
				t.Fatal("the envelope admitted nothing")
			}
		})
	}
}

// TestDispatchThatMayHaveReachedTheProviderIsNeverReleased (audit H8): once
// the request may have reached the provider, its hold is debited or kept, and
// its idempotency key never dispatches again.
func TestDispatchThatMayHaveReachedTheProviderIsNeverReleased(t *testing.T) {
	for name, reply := range map[string]func(w http.ResponseWriter, r *http.Request){
		"a body cut after the status line": func(w http.ResponseWriter, r *http.Request) {
			conn, buf, err := w.(http.Hijacker).Hijack()
			if err != nil {
				return
			}
			_, _ = buf.WriteString("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 4096\r\n\r\n{\"id\":\"cmpl-cut\",")
			_ = buf.Flush()
			_ = conn.Close()
		},
		"a connection closed before the status line": func(w http.ResponseWriter, r *http.Request) {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				_ = conn.Close()
			}
		},
		"usage the proxy cannot price": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"id":"cmpl-neg","model":"base-model","usage":{"prompt_tokens":-5,"completion_tokens":10}}`)
		},
		"an upstream error status": func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, `{"error":{"message":"overloaded"}}`, http.StatusInternalServerError)
		},
	} {
		t.Run(name, func(t *testing.T) {
			var calls atomic.Int64
			f := newProxyFixtureWithUpstream(t, testConfigJSON, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				_, _ = io.Copy(io.Discard, r.Body)
				reply(w, r)
			})
			resp := f.post(t, "/v1/chat/completions", "base-model", "env-direct", "idem-h8", nil)
			if resp.StatusCode == http.StatusOK {
				body, _ := io.ReadAll(resp.Body)
				t.Logf("first answer: %s", body)
			}
			if f.held() == 0 {
				t.Errorf("the dispatch reached the provider, but its hold was released: balance %d, hold %d",
					f.server.BalanceCents(), f.server.ledger.HoldCents())
			}
			_ = f.post(t, "/v1/chat/completions", "base-model", "env-direct", "idem-h8", nil)
			if calls.Load() != 1 {
				t.Errorf("the same idempotency key reached the provider %d times", calls.Load())
			}
		})
	}
}

// TestClientThatLeavesDoesNotFreeTheHold: a client that disconnects while the
// provider works does not release what the call may cost.
func TestClientThatLeavesDoesNotFreeTheHold(t *testing.T) {
	var calls atomic.Int64
	f := newProxyFixtureWithUpstream(t, testConfigJSON, func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		model := requestModel(r)
		select {
		case <-time.After(300 * time.Millisecond):
		case <-r.Context().Done():
			return
		}
		providerReply(w, model, n)
	})
	body := `{"model":"base-model","max_tokens":64,"messages":[{"role":"user","content":"hello"}]}`
	req, _ := http.NewRequest(http.MethodPost, f.http.URL+"/v1/chat/completions", strings.NewReader(body))
	req.Header.Set(inferencegateway.HeaderAgent, "agent-live")
	req.Header.Set(inferencegateway.HeaderSpendEnvelope, "env-direct")
	req.Header.Set(inferencegateway.HeaderIdempotencyKey, "idem-leave")
	client := &http.Client{Timeout: 50 * time.Millisecond}
	if resp, err := client.Do(req); err == nil {
		_ = resp.Body.Close()
		t.Fatal("the client was meant to give up first")
	}
	// Wait for the proxy to finish with the call: its reservation is either
	// gone (settled or released) or kept.
	deadline := time.Now().Add(3 * time.Second)
	for calls.Load() == 0 || f.server.ledger.HoldCents() != 0 {
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if f.held() == 0 {
		t.Fatalf("the client left after the request reached the provider, and the hold was released")
	}
	_ = f.post(t, "/v1/chat/completions", "base-model", "env-direct", "idem-leave", nil)
	if calls.Load() != 1 {
		t.Fatalf("the same idempotency key reached the provider %d times", calls.Load())
	}
}

// TestRestartRecoversAnUnsettledDispatchAsReserved (audit M18): a dispatch
// journalled before the provider call and never settled, because the process
// stopped, is held again on start and its key cannot dispatch again.
func TestRestartRecoversAnUnsettledDispatchAsReserved(t *testing.T) {
	release := make(chan struct{})
	reached := make(chan struct{}, 1)
	var calls atomic.Int64
	f := newProxyFixtureWithUpstream(t, testConfigJSON, func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		model := requestModel(r)
		if n == 1 {
			reached <- struct{}{}
			<-release
		}
		providerReply(w, model, n)
	})
	t.Cleanup(func() { close(release) })
	go func() {
		body := `{"model":"base-model","max_tokens":64,"messages":[{"role":"user","content":"hello"}]}`
		req, _ := http.NewRequest(http.MethodPost, f.http.URL+"/v1/chat/completions", strings.NewReader(body))
		req.Header.Set(inferencegateway.HeaderAgent, "agent-live")
		req.Header.Set(inferencegateway.HeaderSpendEnvelope, "env-direct")
		req.Header.Set(inferencegateway.HeaderIdempotencyKey, "idem-crash")
		if resp, err := http.DefaultClient.Do(req); err == nil {
			_ = resp.Body.Close()
		}
	}()
	select {
	case <-reached:
	case <-time.After(5 * time.Second):
		t.Fatal("the dispatch never reached the provider")
	}
	// The first process is stuck in its provider call: start a second one on
	// the same receipts, as after a crash.
	f.start(t)
	if f.held() == 0 {
		t.Errorf("after a restart the unsettled dispatch holds nothing: balance %d, hold %d",
			f.server.BalanceCents(), f.server.ledger.HoldCents())
	}
	_ = f.post(t, "/v1/chat/completions", "base-model", "env-direct", "idem-crash", nil)
	if calls.Load() != 1 {
		t.Errorf("after a restart the unsettled key reached the provider %d times", calls.Load())
	}
}

// TestRoutingMembersAreRefused (audit M18): members that let the provider
// pick another model, or bill more than one completion, are refused before any
// quote; the provider never sees them.
func TestRoutingMembersAreRefused(t *testing.T) {
	for member, value := range map[string]any{
		"models":   []string{"base-model", "mini-model"},
		"provider": map[string]any{"order": []string{"x"}},
		"plugins":  []map[string]string{{"id": "web"}},
		"route":    "fallback",
		"n":        2,
	} {
		t.Run(member, func(t *testing.T) {
			f := newProxyFixture(t)
			resp := f.post(t, "/v1/chat/completions", "mini-model", "env-direct", "idem-"+member, map[string]any{member: value})
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(body), member) {
				t.Errorf("status %d (%s), want 400 naming %q", resp.StatusCode, body, member)
			}
			if f.upstream.calls.Load() != 0 {
				t.Errorf("the provider received a request carrying %q", member)
			}
		})
	}
}

// TestResponseModelMismatchIsDebitedAtTheHigherPrice (audit M18): a provider
// that answers with another model than the quoted one is debited at the dearer
// of the two prices, and the mismatch is recorded.
func TestResponseModelMismatchIsDebitedAtTheHigherPrice(t *testing.T) {
	f := newProxyFixtureWithUpstream(t, testConfigJSON, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"cmpl-swap","object":"chat.completion","model":"base-model",`+
			`"choices":[{"index":0,"message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":100,"completion_tokens":2000}}`)
	})
	resp := f.post(t, "/v1/chat/completions", "mini-model", "env-direct", "idem-swap", nil)
	_, _ = io.Copy(io.Discard, resp.Body)
	// 100 x 5000 + 2000 x 10000 micro-cents at base-model's price: 20.5, so 21
	// cents; at mini-model's price it would be 5.
	if debited := 2000 - f.server.BalanceCents(); debited != 21 {
		t.Fatalf("debited %d cents, want 21 (the base-model price the provider answered with)", debited)
	}
	var recorded bool
	for _, rec := range f.records(t) {
		if rec.Kind == RecordUsage && rec.Usage != nil && rec.Usage.Metadata["response_model"] == "base-model" {
			recorded = true
		}
	}
	if !recorded {
		t.Fatal("the usage receipt does not record the model the provider answered with")
	}
}

// TestHeaderCannotAssertTheSealedPrincipal (audit M17 and the connectors
// note): the principal in a signed spend receipt is the configured one, never a
// request header.
func TestHeaderCannotAssertTheSealedPrincipal(t *testing.T) {
	f := newProxyFixture(t)
	body := `{"model":"base-model","max_tokens":64,"messages":[{"role":"user","content":"hello"}]}`
	req, _ := http.NewRequest(http.MethodPost, f.http.URL+"/v1/chat/completions", bytes.NewReader([]byte(body)))
	req.Header.Set(inferencegateway.HeaderAgent, "agent-live")
	req.Header.Set(inferencegateway.HeaderSpendEnvelope, "env-direct")
	req.Header.Set(inferencegateway.HeaderPrincipal, "principal-mallory")
	req.Header.Set(inferencegateway.HeaderIdempotencyKey, "idem-mallory")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	for _, rec := range f.records(t) {
		raw, _ := json.Marshal(rec)
		if strings.Contains(string(raw), "principal-mallory") {
			t.Fatalf("a %s record carries the principal the request header asserted: %s", rec.Kind, raw)
		}
	}
	if resp.StatusCode == http.StatusOK && f.upstream.calls.Load() != 0 {
		t.Log("served under the configured principal")
	}
}

// TestExportDoesNotClaimSignaturesItDidNotCheck (audit M18): export reports a
// signature as verified only when it checked it against a key that does not
// come from the directory it verifies.
func TestExportDoesNotClaimSignaturesItDidNotCheck(t *testing.T) {
	f := newProxyFixture(t)
	resp := f.post(t, "/v1/chat/completions", "base-model", "env-direct", "idem-export", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	results, err := ExportEvidencePacks(ExportOptions{ReceiptsDir: f.receiptsDir, OutDir: filepath.Join(t.TempDir(), "out")})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	for _, res := range results {
		if res.SignatureVerified || len(res.SignaturesChecked) != 0 {
			t.Fatalf("%s: signature_verified=%v, checked %v, with no key from outside %s", res.SpendIntentID, res.SignatureVerified, res.SignaturesChecked, f.receiptsDir)
		}
	}

	pub, err := ParsePublicKey(f.server.SigningPublicKey())
	if err != nil {
		t.Fatal(err)
	}
	// A key other than the issuer's verifies nothing.
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := ExportEvidencePacks(ExportOptions{ReceiptsDir: f.receiptsDir, OutDir: filepath.Join(t.TempDir(), "other"), PublicKey: otherPub}); err == nil {
		t.Fatal("export verified the receipts against a key that did not sign them")
	}
	// A rewritten usage record fails, though its pack's content hashes hold.
	logPath := filepath.Join(f.receiptsDir, ReceiptLogName)
	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(raw), `"output_tokens":20`, `"output_tokens":2`, 1)
	if tampered == string(raw) {
		t.Fatal("the usage record was not found to tamper with")
	}
	if err := os.WriteFile(logPath, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ExportEvidencePacks(ExportOptions{ReceiptsDir: f.receiptsDir, OutDir: filepath.Join(t.TempDir(), "tampered"), PublicKey: pub}); err == nil || !strings.Contains(err.Error(), "usage") {
		t.Fatalf("export of a rewritten usage record = %v, want a usage signature failure", err)
	}
}

// TestDispatchThatNeverLeftReleasesTheHold: a dispatch that failed before any
// byte of its request left the proxy frees its hold and journals the release,
// so neither this run nor a restart holds it.
func TestDispatchThatNeverLeftReleasesTheHold(t *testing.T) {
	f := newProxyFixtureWithUpstream(t, testConfigJSON, func(w http.ResponseWriter, r *http.Request) {
		providerReply(w, requestModel(r), 1)
	})
	f.upstream.server.Close() // nothing listens: the dial fails
	resp := f.post(t, "/v1/chat/completions", "base-model", "env-direct", "idem-unsent", nil)
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
	if f.held() != 0 {
		t.Fatalf("a dispatch that never left holds %d cents", f.held())
	}
	if byKind := recordsByKind(f.records(t)); len(byKind[RecordDispatchReleased]) != 1 {
		t.Fatalf("release records = %d, want 1", len(byKind[RecordDispatchReleased]))
	}
	f.restart(t)
	if f.held() != 0 || f.server.ReplaySummary().PendingDispatches != 0 {
		t.Fatalf("after a restart the released dispatch holds %d cents", f.held())
	}
}

// TestRestoreHoldsAJournalAfterARelease: a key released once and journalled
// again by a retry that never settled is held on start; a released journal is
// not.
func TestRestoreHoldsAJournalAfterARelease(t *testing.T) {
	f := newProxyFixture(t)
	resp := f.post(t, "/v1/chat/completions", "base-model", "env-direct", "idem-journal", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var journal *ReceiptRecord
	for _, rec := range f.records(t) {
		if isDispatchJournal(rec) {
			journal = rec
		}
	}
	if journal == nil || journal.Note != NoteDispatchJournal {
		t.Fatalf("no dispatch journal line: %+v", journal)
	}
	other := *journal.RouteQuote
	other.SpendIntentID, other.ID = "si-retried", "rq-retried"
	other.Reseal()
	retried := []*ReceiptRecord{
		{Kind: RecordRouteQuote, SpendIntentID: other.SpendIntentID, Note: NoteDispatchJournal, RouteQuote: &other},
		releaseRecord(&other, "no byte of the request left the proxy"),
		{Kind: RecordRouteQuote, SpendIntentID: other.SpendIntentID, Note: NoteDispatchJournal, RouteQuote: &other},
	}
	held, err := RestorePendingDispatches(append(f.records(t), retried...), f.server.engine, f.server.envelopes)
	if err != nil || len(held) != 1 || held[0].Key != other.ID {
		t.Fatalf("held = %v, %v; want only the retried journal", held, err)
	}
	if held, err := RestorePendingDispatches(append(f.records(t), retried[:2]...), f.server.engine, f.server.envelopes); err != nil || len(held) != 0 {
		t.Fatalf("held = %v, %v; want nothing for a released journal", held, err)
	}
}
