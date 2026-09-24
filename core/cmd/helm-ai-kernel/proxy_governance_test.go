package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
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

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/prg"
)

// proxyUpstreamReply is what the fake OpenAI-compatible upstream answers.
type proxyUpstreamReply struct {
	contentType string
	body        string
}

func chatToolCallReply(toolName, arguments string) proxyUpstreamReply {
	body, _ := json.Marshal(map[string]any{
		"id":    "chatcmpl-test",
		"model": "gpt-test",
		"choices": []any{map[string]any{
			"finish_reason": "tool_calls",
			"message": map[string]any{
				"role": "assistant",
				"tool_calls": []any{map[string]any{
					"id":   "call_1",
					"type": "function",
					"function": map[string]any{
						"name":      toolName,
						"arguments": arguments,
					},
				}},
			},
		}},
		"usage": map[string]any{"prompt_tokens": 12, "completion_tokens": 34},
	})
	return proxyUpstreamReply{contentType: "application/json", body: string(body)}
}

// newFakeUpstream serves reply for every request, gzip-compressing it when the
// request asks for gzip, and counts the requests it received.
func newFakeUpstream(t *testing.T, reply proxyUpstreamReply) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", reply.contentType)
		if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			w.Header().Set("Content-Encoding", "gzip")
			zw := gzip.NewWriter(w)
			_, _ = zw.Write([]byte(reply.body))
			_ = zw.Close()
			return
		}
		_, _ = w.Write([]byte(reply.body))
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// allowPolicyGraph compiles a serve policy that allows exactly the given
// tools, through the same loader `proxy --policy` uses.
func allowPolicyGraph(t *testing.T, tools ...string) *prg.Graph {
	t.Helper()
	actions := make([]map[string]any, 0, len(tools))
	for _, tool := range tools {
		actions = append(actions, map[string]any{"action": tool, "expression": "true"})
	}
	pack, err := json.Marshal(map[string]any{"pack_id": "proxy-test", "version": 1, "runtime_actions": actions})
	if err != nil {
		t.Fatal(err)
	}
	policyPath, _ := writeMountedServePolicyFixture(t, t.TempDir(), string(pack))
	runtimePolicy, err := loadServePolicyRuntime(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	return runtimePolicy.Graph
}

// startTestProxy builds the proxy exactly as runProxyCmd does and serves it.
func startTestProxy(t *testing.T, upstreamURL string, policy *prg.Graph, mutate func(*proxyConfig)) (*httptest.Server, *proxyRuntime) {
	t.Helper()
	t.Setenv("HELM_DATA_DIR", t.TempDir())
	cfg := proxyConfig{
		upstream:      upstreamURL + "/v1",
		receiptsDir:   t.TempDir(),
		tenantID:      "proxy-test",
		policyGraph:   policy,
		maxIterations: 10,
		maxWallclock:  2 * time.Minute,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	rt, err := newProxyRuntime(cfg, io.Discard)
	if err != nil {
		t.Fatalf("newProxyRuntime: %v", err)
	}
	t.Cleanup(rt.close)
	srv := httptest.NewServer(rt.handler)
	t.Cleanup(srv.Close)
	return srv, rt
}

type proxyTestResponse struct {
	status int
	header http.Header
	body   string
}

func postToProxy(t *testing.T, proxyURL, body string, headers map[string]string) proxyTestResponse {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, proxyURL+"/v1/chat/completions", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	// Send Accept-Encoding explicitly, as the OpenAI SDKs do, so Go's client
	// does not transparently decompress on the test's behalf.
	if req.Header.Get("Accept-Encoding") == "" {
		req.Header.Set("Accept-Encoding", "identity")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return proxyTestResponse{status: resp.StatusCode, header: resp.Header, body: string(data)}
}

func readProxyReceipts(t *testing.T, rt *proxyRuntime) []proxyReceipt {
	t.Helper()
	data, err := os.ReadFile(rt.receiptPath)
	if err != nil {
		t.Fatalf("read receipts: %v", err)
	}
	var out []proxyReceipt
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var r proxyReceipt
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("decode receipt: %v", err)
		}
		out = append(out, r)
	}
	return out
}

const toolRequest = `{"model":"gpt-test","messages":[{"role":"user","content":"weather?"}],"tools":[{"type":"function","function":{"name":"get_weather"}}]}`

// TestProxyNonStreamingToolCallGetsPolicyVerdict converts the VA overlay
// (07-01): with the proxy's own wiring, a tool call the policy allows is
// allowed, and one it does not name is denied by policy — not by BUDGET_ERROR
// or a missing-identity isolation denial.
func TestProxyNonStreamingToolCallGetsPolicyVerdict(t *testing.T) {
	policy := allowPolicyGraph(t, "get_weather")

	t.Run("allowed by policy", func(t *testing.T) {
		upstream, _ := newFakeUpstream(t, chatToolCallReply("get_weather", `{"city":"Berlin"}`))
		proxySrv, rt := startTestProxy(t, upstream.URL, policy, nil)

		resp := postToProxy(t, proxySrv.URL, toolRequest, nil)
		if resp.status != http.StatusOK || resp.header.Get("X-Helm-Status") != "APPROVED" {
			t.Fatalf("allowed tool call: status=%d X-Helm-Status=%q reason=%q body=%s",
				resp.status, resp.header.Get("X-Helm-Status"), resp.header.Get("X-Helm-Reason-Code"), resp.body)
		}
		if !strings.Contains(resp.body, "get_weather") || resp.header.Get("X-Helm-Decision-ID") == "" {
			t.Fatalf("allowed tool call lost its body or decision id: %v %s", resp.header, resp.body)
		}
		receipts := readProxyReceipts(t, rt)
		if len(receipts) != 1 || receipts[0].Status != "APPROVED" || receipts[0].DecisionID == "" {
			t.Fatalf("receipt = %+v", receipts)
		}
	})

	t.Run("not named by policy", func(t *testing.T) {
		upstream, _ := newFakeUpstream(t, chatToolCallReply("delete_repo", `{}`))
		proxySrv, _ := startTestProxy(t, upstream.URL, policy, nil)

		resp := postToProxy(t, proxySrv.URL, toolRequest, nil)
		if resp.status != http.StatusForbidden || resp.header.Get("X-Helm-Status") != "DENIED" {
			t.Fatalf("unlisted tool: status=%d X-Helm-Status=%q body=%s", resp.status, resp.header.Get("X-Helm-Status"), resp.body)
		}
		if got := resp.header.Get("X-Helm-Reason-Code"); got != "NO_POLICY_DEFINED" {
			t.Fatalf("unlisted tool reason = %q, want NO_POLICY_DEFINED", got)
		}
	})
}

// TestProxyGovernsGzipEncodedResponse: the OpenAI SDKs send Accept-Encoding.
// A compressed upstream body must still be parsed and governed, never passed
// through as an unreadable (and therefore approved) blob.
func TestProxyGovernsGzipEncodedResponse(t *testing.T) {
	upstream, _ := newFakeUpstream(t, chatToolCallReply("delete_repo", `{}`))
	proxySrv, _ := startTestProxy(t, upstream.URL, allowPolicyGraph(t, "get_weather"), nil)

	resp := postToProxy(t, proxySrv.URL, toolRequest, map[string]string{"Accept-Encoding": "gzip"})
	if resp.status != http.StatusForbidden || resp.header.Get("X-Helm-Status") != "DENIED" {
		t.Fatalf("gzip tool call: status=%d X-Helm-Status=%q", resp.status, resp.header.Get("X-Helm-Status"))
	}
	if strings.Contains(resp.body, "delete_repo\",\"arguments") {
		t.Fatalf("denied gzip response leaked the tool call: %s", resp.body)
	}
}

// TestProxyRefusesStreamingRequestThatDeclaresTools (03-02): the proxy cannot
// parse a stream, so a streamed request that offers tools never reaches the
// upstream.
func TestProxyRefusesStreamingRequestThatDeclaresTools(t *testing.T) {
	upstream, hits := newFakeUpstream(t, proxyUpstreamReply{contentType: "text/event-stream", body: "data: {}\n\n"})
	proxySrv, _ := startTestProxy(t, upstream.URL, allowPolicyGraph(t, "get_weather"), nil)

	streamed := strings.Replace(toolRequest, `"model":"gpt-test"`, `"model":"gpt-test","stream":true`, 1)
	resp := postToProxy(t, proxySrv.URL, streamed, nil)
	if resp.status != http.StatusBadRequest {
		t.Fatalf("streamed tool request status = %d, want 400: %s", resp.status, resp.body)
	}
	if !strings.Contains(resp.body, "PROXY_STREAMING_TOOLS_REFUSED") || !strings.Contains(resp.body, `\"stream\": false`) {
		t.Fatalf("refusal does not explain itself: %s", resp.body)
	}
	if hits.Load() != 0 {
		t.Fatalf("upstream was called %d times for a refused request", hits.Load())
	}
}

// TestProxyStreamWithoutToolsPassesThroughHonestly: a stream that was offered
// no tools cannot carry a tool call, so it passes through, and the proxy no
// longer claims to govern it afterwards.
func TestProxyStreamWithoutToolsPassesThroughHonestly(t *testing.T) {
	upstream, _ := newFakeUpstream(t, proxyUpstreamReply{contentType: "text/event-stream", body: "data: {\"x\":1}\n\n"})
	proxySrv, _ := startTestProxy(t, upstream.URL, nil, nil)

	resp := postToProxy(t, proxySrv.URL, `{"model":"gpt-test","stream":true,"messages":[]}`, nil)
	if resp.status != http.StatusOK || !strings.Contains(resp.body, `"x":1`) {
		t.Fatalf("tool-less stream: status=%d body=%s", resp.status, resp.body)
	}
	if got := resp.header.Get("X-Helm-SSE"); got != "passthrough-no-tools" {
		t.Fatalf("X-Helm-SSE = %q, want passthrough-no-tools", got)
	}
}

// TestProxyRefusesUngovernableResponseWhenToolsDeclared: when tools were
// offered, a response the proxy cannot inspect (a stream the request did not
// ask for, or a non-Chat-Completions body) is withheld, not forwarded.
func TestProxyRefusesUngovernableResponseWhenToolsDeclared(t *testing.T) {
	cases := map[string]proxyUpstreamReply{
		"unrequested stream": {contentType: "text/event-stream", body: `data: {"choices":[{"delta":{"tool_calls":[{"function":{"name":"delete_repo"}}]}}]}` + "\n\n"},
		"anthropic tool_use": {contentType: "application/json", body: `{"type":"message","content":[{"type":"tool_use","name":"delete_repo","input":{}}]}`},
		"non-JSON body":      {contentType: "application/octet-stream", body: "\x00\x01delete_repo"},
	}
	for name, reply := range cases {
		t.Run(name, func(t *testing.T) {
			upstream, _ := newFakeUpstream(t, reply)
			proxySrv, rt := startTestProxy(t, upstream.URL, allowPolicyGraph(t, "get_weather"), nil)

			resp := postToProxy(t, proxySrv.URL, toolRequest, nil)
			if resp.status != http.StatusForbidden || resp.header.Get("X-Helm-Status") != "UNGOVERNABLE_RESPONSE" {
				t.Fatalf("status=%d X-Helm-Status=%q body=%s", resp.status, resp.header.Get("X-Helm-Status"), resp.body)
			}
			if strings.Contains(resp.body, "delete_repo") {
				t.Fatalf("ungovernable upstream body leaked: %s", resp.body)
			}
			if receipts := readProxyReceipts(t, rt); len(receipts) != 1 || receipts[0].Status != "UNGOVERNABLE_RESPONSE" {
				t.Fatalf("receipts = %+v", receipts)
			}
		})
	}
}

// TestProxyMalformedToolCallFailsClosed: a tool call whose name or arguments
// cannot be read is never approved.
func TestProxyMalformedToolCallFailsClosed(t *testing.T) {
	bodies := map[string]string{
		"object arguments": `{"choices":[{"message":{"tool_calls":[{"function":{"name":"get_weather","arguments":{"city":"Berlin"}}}]}}]}`,
		"missing function": `{"choices":[{"message":{"tool_calls":[{"id":"call_1"}]}}]}`,
		"empty name":       `{"choices":[{"message":{"tool_calls":[{"function":{"name":"","arguments":"{}"}}]}}]}`,
		"legacy function":  `{"choices":[{"message":{"function_call":{"name":"delete_repo","arguments":"{}"}}}]}`,
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			upstream, _ := newFakeUpstream(t, proxyUpstreamReply{contentType: "application/json", body: body})
			proxySrv, _ := startTestProxy(t, upstream.URL, allowPolicyGraph(t, "get_weather"), nil)

			resp := postToProxy(t, proxySrv.URL, toolRequest, nil)
			if resp.status != http.StatusForbidden {
				t.Fatalf("status=%d X-Helm-Status=%q body=%s", resp.status, resp.header.Get("X-Helm-Status"), resp.body)
			}
		})
	}
}

// TestProxySessionLimitsArePerSession (03-15): one session exhausting its
// iterations does not deny another session's tool calls.
func TestProxySessionLimitsArePerSession(t *testing.T) {
	upstream, _ := newFakeUpstream(t, chatToolCallReply("get_weather", `{}`))
	proxySrv, _ := startTestProxy(t, upstream.URL, allowPolicyGraph(t, "get_weather"), func(cfg *proxyConfig) {
		cfg.maxIterations = 1
	})
	sessionA := map[string]string{"X-Helm-Session-ID": "11111111-1111-4111-8111-111111111111"}
	sessionB := map[string]string{"X-Helm-Session-ID": "22222222-2222-4222-8222-222222222222"}

	if resp := postToProxy(t, proxySrv.URL, toolRequest, sessionA); resp.header.Get("X-Helm-Status") != "APPROVED" {
		t.Fatalf("session A first call: %q", resp.header.Get("X-Helm-Status"))
	}
	if resp := postToProxy(t, proxySrv.URL, toolRequest, sessionA); resp.header.Get("X-Helm-Status") != "PROXY_ITERATION_LIMIT" {
		t.Fatalf("session A second call: %q", resp.header.Get("X-Helm-Status"))
	}
	if resp := postToProxy(t, proxySrv.URL, toolRequest, sessionB); resp.header.Get("X-Helm-Status") != "APPROVED" {
		t.Fatalf("session B was limited by session A: %q", resp.header.Get("X-Helm-Status"))
	}
}

func TestProxySessionLimitsWallclockStartsPerSession(t *testing.T) {
	now := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	limits := newProxySessionLimits(0, time.Minute, func() time.Time { return now })

	if got := limits.admit("a"); got != "" {
		t.Fatalf("first call in session a: %q", got)
	}
	now = now.Add(2 * time.Minute)
	if got := limits.admit("a"); got != "PROXY_WALLCLOCK_LIMIT" {
		t.Fatalf("session a after its wallclock: %q", got)
	}
	if got := limits.admit("b"); got != "" {
		t.Fatalf("new session b inherited process uptime: %q", got)
	}
}

func TestProxySessionLimitsStayBounded(t *testing.T) {
	now := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	limits := newProxySessionLimits(1, 0, func() time.Time { return now })
	for i := 0; i < maxProxySessions+10; i++ {
		now = now.Add(time.Millisecond)
		limits.admit(fmt.Sprintf("s-%d", i))
	}
	if n := len(limits.sessions); n > maxProxySessions {
		t.Fatalf("session table grew to %d, cap %d", n, maxProxySessions)
	}
}

// TestReceiptStoreSerializesConcurrentAppends converts the VA overlay for
// 03-01: the clock is assigned under the store lock, so concurrent requests
// can no longer take clocks out of order and wedge the chain.
func TestReceiptStoreSerializesConcurrentAppends(t *testing.T) {
	path := filepath.Join(t.TempDir(), "r.jsonl")
	store, err := newReceiptStore(path)
	if err != nil {
		t.Fatal(err)
	}
	const n = 64
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- store.Append(&proxyReceipt{Status: "APPROVED"}, nil)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent append failed: %v", err)
		}
	}
	if store.LastLamport() != n {
		t.Fatalf("lastLamport = %d, want %d", store.LastLamport(), n)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, last, err := recoverReceiptStoreState(path); err != nil || last != n {
		t.Fatalf("chain after concurrent appends: last=%d err=%v", last, err)
	}
}

func TestReceiptStoreFailedSealDoesNotAdvanceChain(t *testing.T) {
	store, err := newReceiptStore(filepath.Join(t.TempDir(), "r.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Append(&proxyReceipt{}, func(*proxyReceipt) error { return errors.New("signer down") }); err == nil {
		t.Fatal("failed seal must fail the append")
	}
	rcpt := &proxyReceipt{}
	if err := store.Append(rcpt, nil); err != nil {
		t.Fatal(err)
	}
	if rcpt.LamportClock != 1 || rcpt.PrevHash != "GENESIS" {
		t.Fatalf("failed seal advanced the chain: clock=%d prev=%q", rcpt.LamportClock, rcpt.PrevHash)
	}
}

// TestProxyReceiptWriteFailureFailsRequest (03-01): a response whose receipt
// cannot be persisted is not delivered.
func TestProxyReceiptWriteFailureFailsRequest(t *testing.T) {
	upstream, _ := newFakeUpstream(t, chatToolCallReply("get_weather", `{}`))
	proxySrv, rt := startTestProxy(t, upstream.URL, allowPolicyGraph(t, "get_weather"), nil)
	if err := rt.store.Close(); err != nil {
		t.Fatal(err)
	}

	resp := postToProxy(t, proxySrv.URL, toolRequest, nil)
	if resp.status != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 when the receipt cannot be written", resp.status)
	}
	if strings.Contains(resp.body, "get_weather") || resp.header.Get("X-Helm-Receipt-ID") != "" {
		t.Fatalf("unreceipted response was delivered: %v %s", resp.header, resp.body)
	}
}

func TestProxyRefusesUnpricedBudgetFlags(t *testing.T) {
	for _, flagName := range []string{"--daily-limit", "--monthly-limit"} {
		var stdout, stderr bytes.Buffer
		code := runProxyCmd([]string{flagName, "500", "--receipts-dir", t.TempDir()}, &stdout, &stderr)
		if code != 2 || !strings.Contains(stderr.String(), "BUDGET_ERROR") {
			t.Fatalf("%s: exit=%d stderr=%s", flagName, code, stderr.String())
		}
	}
}
