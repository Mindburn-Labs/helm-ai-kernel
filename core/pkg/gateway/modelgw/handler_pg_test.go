package modelgw

// quantum_posture: computes SHA-256 digests to compare with stored ones; signs
// nothing.

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/admission"
)

// The provider streams the stubs write. Each is what the provider's own API
// sends, event for event, so a test can compare what a client receives with it
// byte for byte.
const (
	anthropicStream = "event: message_start\n" +
		`data: {"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","model":"claude-sonnet-5-5","content":[],"usage":{"input_tokens":25,"output_tokens":1}}}` + "\n\n" +
		"event: ping\n" + `data: {"type": "ping"}` + "\n\n" +
		"event: content_block_start\n" + `data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}` + "\n\n" +
		"event: content_block_delta\n" + `data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello"}}` + "\n\n" +
		"event: ping\n" + `data: {"type": "ping"}` + "\n\n" +
		"event: content_block_stop\n" + `data: {"type":"content_block_stop","index":0}` + "\n\n" +
		"event: message_delta\n" + `data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":15}}` + "\n\n" +
		"event: message_stop\n" + `data: {"type":"message_stop"}` + "\n\n"
	// anthropicStreamCost: 25 input and 15 output tokens on the sonnet tariff.
	anthropicStreamCost = 300

	chatStreamChunks = `data: {"id":"c1","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","content":"Hel"}}]}` + "\n\n" +
		`data: {"id":"c1","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"lo"},"finish_reason":"stop"}]}` + "\n\n"
	chatUsageChunk = `data: {"id":"c1","object":"chat.completion.chunk","choices":[],"usage":{"prompt_tokens":100,"completion_tokens":20,"total_tokens":120,"prompt_tokens_details":{"cached_tokens":40}}}` + "\n\n"
	chatDone       = "data: [DONE]\n\n"
	// chatStreamCost: 60 input, 40 cached and 20 output tokens on the gpt-6-sol tariff.
	chatStreamCost = 60*2 + 40*1/2 + 20*8 // 120 + 20 + 160 = 300 (cache read is 0.5 per token)

	responsesStream = "event: response.created\n" + `data: {"type":"response.created","response":{"id":"resp_1","status":"in_progress"}}` + "\n\n" +
		"event: response.output_text.delta\n" + `data: {"type":"response.output_text.delta","delta":"Hi"}` + "\n\n" +
		"event: response.completed\n" + `data: {"type":"response.completed","response":{"id":"resp_1","status":"completed","usage":{"input_tokens":100,"output_tokens":20,"total_tokens":120,"input_tokens_details":{"cached_tokens":40}}}}` + "\n\n"
)

func sseHandler(chunks ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Request-Id", "req_upstream_1")
		w.WriteHeader(http.StatusOK)
		for _, c := range chunks {
			_, _ = io.WriteString(w, c)
			w.(http.Flusher).Flush()
		}
	}
}

func jsonHandler(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Request-Id", "req_upstream_2")
		_, _ = io.WriteString(w, body)
	}
}

const messagesRequest = `{"model":"claude-sonnet-5-5","stream":true,"messages":[{"role":"user","content":"hi"}],"tools":[{"name":"get","input_schema":{"type":"object"}}]}`

func workerHeaders(token string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + token, "Anthropic-Version": "2023-06-01", "Anthropic-Beta": "claude-code-20250219"}
}

func sha256hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// onlyAttempt returns the one attempt the ledger holds.
func (e *env) onlyAttempt() admission.Attempt {
	e.t.Helper()
	all := e.attempts()
	if len(all) != 1 {
		e.t.Fatalf("the ledger holds %d attempts, want 1: %+v", len(all), all)
	}
	return all[0]
}

func TestPostgresAnthropicStreamPassesThroughAndSettles(t *testing.T) {
	e := newEnv(t, 1_000_000)
	// The provider sends its first events, then waits for the client to have
	// read them: the gateway must relay as the events arrive, not at the end.
	firstRead, release := make(chan struct{}), make(chan struct{})
	e.anthropic.on(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Request-Id", "req_upstream_1")
		w.WriteHeader(http.StatusOK)
		events := strings.SplitAfter(anthropicStream, "\n\n")
		_, _ = io.WriteString(w, events[0])
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-time.After(10 * time.Second):
		}
		for _, ev := range events[1:] {
			_, _ = io.WriteString(w, ev)
			w.(http.Flusher).Flush()
		}
		close(firstRead)
	})

	req, err := http.NewRequest(http.MethodPost, e.worker.URL+"/v1/messages?beta=true", strings.NewReader(messagesRequest))
	must(t, err)
	req.Header.Set("Content-Type", "application/json")
	for k, v := range workerHeaders(tokenAgent) {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	must(t, err)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "text/event-stream" || resp.Header.Get("Request-Id") != "req_upstream_1" {
		t.Fatalf("status %d headers %v", resp.StatusCode, resp.Header)
	}
	reader := bufio.NewReader(resp.Body)
	first, err := reader.ReadString('\n')
	must(t, err)
	if first != "event: message_start\n" {
		t.Fatalf("first line = %q", first)
	}
	close(release) // the client has the first event; the provider may go on
	rest, err := io.ReadAll(reader)
	must(t, err)
	<-firstRead
	if got := first + string(rest); got != anthropicStream {
		t.Fatalf("the client's stream is not the provider's:\n%q\n%q", got, anthropicStream)
	}

	// What the provider saw: the gateway's key, the client's headers that
	// matter, the beta query and the request with its maximum injected; never
	// the client's token.
	got := e.anthropic.last(t)
	if got.Path != "/v1/messages" || got.Query != "beta=true" || got.Header.Get("X-Api-Key") != keyAnthropic ||
		got.Header.Get("Authorization") != "" || got.Header.Get("Anthropic-Version") != "2023-06-01" ||
		got.Header.Get("Anthropic-Beta") != "claude-code-20250219" {
		t.Fatalf("the provider saw %s?%s %v", got.Path, got.Query, got.Header)
	}
	wantBody := `{"model":"claude-sonnet-5-5","stream":true,"messages":[{"role":"user","content":"hi"}],"tools":[{"name":"get","input_schema":{"type":"object"}}],"max_tokens":8192}`
	if string(got.Body) != wantBody {
		t.Fatalf("the provider's body:\n%s\nwant\n%s", got.Body, wantBody)
	}
	for _, header := range got.Header {
		for _, v := range header {
			if strings.Contains(v, "canary-episode-token") {
				t.Fatalf("the caller's token reached the provider: %v", got.Header)
			}
		}
	}

	// One settled attempt: the reported usage consumed, the rest released.
	a := e.onlyAttempt()
	digest := sha256hex([]byte(wantBody))
	if a.State != "SETTLED" || a.Outcome != "SUCCEEDED" || a.EffectType != "model.inference" || a.Target != routeSonnet ||
		a.RequesterPrincipalID != "agt:seat-1" || a.RequesterActorID != cpActor || a.CaseID != "work-ep-1" ||
		a.IdempotencyKey != "mi:ep-1:"+digest+":0" {
		t.Fatalf("attempt = %+v", a)
	}
	sonnet, _ := e.cfg.Resolve("anthropic-messages", "claude-sonnet-5-5")
	held, err := sonnet.Quote(int64(len(wantBody)), 8192, false) // the input bytes and the injected maximum
	must(t, err)
	mc := a.ModelCall
	if mc == nil || mc.State != admission.SettlementConfirmed || mc.HeldMicros != held || *mc.ConfirmedMicros != anthropicStreamCost ||
		mc.BillableMicros != anthropicStreamCost || mc.Route != routeSonnet || mc.API != "anthropic-messages" {
		t.Fatalf("model call = %+v, want held %d", mc, held)
	}
	if mc.BillableMicros > mc.HeldMicros {
		t.Fatalf("billable %d exceeds held %d", mc.BillableMicros, mc.HeldMicros)
	}
	if used, reserved := e.counters(); used != anthropicStreamCost || reserved != 0 {
		t.Fatalf("counters: used %d reserved %d", used, reserved)
	}
	e.ledgerBalances()
	if resp.Header.Get("X-Helm-Attempt-Id") != a.ID || !strings.HasPrefix(resp.Header.Get("Server-Timing"), "helm-predispatch;dur=") {
		t.Fatalf("headers %v", resp.Header)
	}
	// The stored arguments hold the digest and the size, never the prompt.
	content, err := e.svc.GetContent(context.Background(), admission.Caller{TenantID: tenantA, WorkspaceID: workspace, PrincipalID: "x"}, a.ID)
	must(t, err)
	wantArgs := fmt.Sprintf(`{"schema":"model.inference.v1","api":"anthropic-messages","route":%q,"request_sha256":%q,"input_bytes":%d,"max_output_tokens":8192,"stream":true}`,
		routeSonnet, digest, len(wantBody))
	if string(content) != wantArgs {
		t.Fatalf("attempt content:\n%s\nwant\n%s", content, wantArgs)
	}
	// No credential reaches a log.
	for _, secret := range []string{keyAnthropic, keyOpenAI, keyOpenRouter, "canary-episode-token"} {
		if strings.Contains(e.logs.String(), secret) {
			t.Fatalf("a log holds %q:\n%s", secret, e.logs.String())
		}
	}
}

func TestPostgresChatStreamStripsTheUsageChunkTheGatewayAskedFor(t *testing.T) {
	e := newEnv(t, 1_000_000)
	e.openai.on(sseHandler(chatStreamChunks, chatUsageChunk, chatDone))
	body := `{"model":"gpt-6-sol","stream":true,"messages":[{"role":"user","content":"hi"}]}`
	r := post(t, e.worker.URL, "/v1/chat/completions", bearerHeader(tokenAgent), body)
	if r.Status != 200 || string(r.Body) != chatStreamChunks+chatDone {
		t.Fatalf("the client's stream must be the provider's without the usage chunk it did not ask for:\n%s", r)
	}
	got := e.openai.last(t)
	if got.Path != "/v1/chat/completions" || got.Header.Get("Authorization") != "Bearer "+keyOpenAI || got.Header.Get("X-Api-Key") != "" ||
		!strings.Contains(string(got.Body), `"stream_options":{"include_usage":true}`) || !strings.Contains(string(got.Body), `"max_completion_tokens":8192`) {
		t.Fatalf("the provider saw %s %v %s", got.Path, got.Header, got.Body)
	}
	a := e.onlyAttempt()
	if a.State != "SETTLED" || a.ModelCall.State != admission.SettlementConfirmed || *a.ModelCall.ConfirmedMicros != chatStreamCost {
		t.Fatalf("attempt = %+v model call %+v, want confirmed %d", a, a.ModelCall, chatStreamCost)
	}
	e.ledgerBalances()

	// A client that asked for the usage chunk gets it, and the request is untouched.
	e2 := newEnv(t, 1_000_000)
	e2.openai.on(sseHandler(chatStreamChunks, chatUsageChunk, chatDone))
	asked := `{"model":"gpt-6-sol","stream":true,"stream_options":{"include_usage":true},"max_completion_tokens":100,"messages":[]}`
	r = post(t, e2.worker.URL, "/v1/chat/completions", bearerHeader(tokenAgent), asked)
	if r.Status != 200 || string(r.Body) != chatStreamChunks+chatUsageChunk+chatDone {
		t.Fatalf("a client that asked must get the usage chunk:\n%s", r)
	}
	if string(e2.openai.last(t).Body) != asked {
		t.Fatalf("the request was changed: %s", e2.openai.last(t).Body)
	}
}

func TestPostgresResponsesStreamAndBodiesSettleFromReportedUsage(t *testing.T) {
	e := newEnv(t, 1_000_000)
	// Responses, streamed: the gpt-6-sol tariff, 60 input + 40 cached + 20 output.
	e.openai.on(sseHandler(responsesStream))
	r := post(t, e.worker.URL, "/v1/responses", bearerHeader(tokenAgent), `{"model":"gpt-6-sol","stream":true,"input":"hi","tools":[{"type":"function","name":"f"},{"type":"local_shell"}]}`)
	if r.Status != 200 || string(r.Body) != responsesStream {
		t.Fatalf("responses stream: %s", r)
	}
	if got := e.openai.last(t); got.Path != "/v1/responses" || !strings.Contains(string(got.Body), `"max_output_tokens":8192`) {
		t.Fatalf("the provider saw %s %s", got.Path, got.Body)
	}
	// Anthropic, not streamed.
	e.anthropic.on(jsonHandler(`{"id":"msg_9","type":"message","content":[{"type":"text","text":"hi"}],"usage":{"input_tokens":100,"output_tokens":50,"cache_read_input_tokens":1000}}`))
	r = post(t, e.worker.URL, "/v1/messages", workerHeaders(tokenAgent), `{"model":"claude-sonnet-5-5","messages":[{"role":"user","content":"hi"}]}`)
	if r.Status != 200 || r.Header.Get("Content-Type") != "application/json" || r.Header.Get("Request-Id") != "req_upstream_2" ||
		!strings.Contains(string(r.Body), `"msg_9"`) || r.Header.Get("Content-Length") != fmt.Sprint(len(r.Body)) {
		t.Fatalf("anthropic body: %s %v", r, r.Header)
	}
	// Chat, not streamed, on an OpenAI-compatible upstream: the maximum is the
	// legacy max_tokens field, and the key is the upstream's own.
	e.openrouter.on(jsonHandler(`{"id":"gen-1","choices":[{"message":{"role":"assistant","content":"hi"}}],"usage":{"prompt_tokens":1000,"completion_tokens":200}}`))
	r = post(t, e.worker.URL, "/v1/chat/completions", bearerHeader(tokenAgent), `{"model":"deepseek/deepseek-chat","messages":[{"role":"user","content":"hi"}]}`)
	if r.Status != 200 || !strings.Contains(string(r.Body), `"gen-1"`) {
		t.Fatalf("openrouter chat: %s", r)
	}
	if got := e.openrouter.last(t); got.Path != "/api/v1/chat/completions" || got.Header.Get("Authorization") != "Bearer "+keyOpenRouter || !strings.Contains(string(got.Body), `"max_tokens":4096`) {
		t.Fatalf("the upstream saw %s %v %s", got.Path, got.Header, got.Body)
	}

	all := e.attempts()
	if len(all) != 3 {
		t.Fatalf("%d attempts, want 3", len(all))
	}
	// gpt-6-sol streamed: 60*2 + 40*0.5 + 20*8 = 300; sonnet: 100*3 + 1000*0.3 + 50*15 = 1350;
	// the OpenRouter route: (1000*0.042 + 200*0.11) rounded up = 42 + 22 = 64.
	for i, want := range []int64{300, 1350, 64} {
		a := all[i]
		if a.State != "SETTLED" || a.ModelCall.State != admission.SettlementConfirmed || *a.ModelCall.ConfirmedMicros != want || a.ModelCall.BillableMicros != want {
			t.Errorf("attempt %d = %s, model call %+v, want confirmed %d", i, a.State, a.ModelCall, want)
		}
	}
	e.ledgerBalances()
}

func TestPostgresReplayMakesNoSecondProviderCall(t *testing.T) {
	e := newEnv(t, 1_000_000)
	e.anthropic.on(sseHandler(anthropicStream))
	first := post(t, e.worker.URL, "/v1/messages", workerHeaders(tokenAgent), messagesRequest)
	if first.Status != 200 {
		t.Fatal(first)
	}
	// The same request in the same episode: the stored bytes, no provider call,
	// no new attempt.
	again := post(t, e.worker.URL, "/v1/messages", workerHeaders(tokenAgent), messagesRequest)
	if again.Status != 200 || string(again.Body) != anthropicStream || again.Header.Get("X-Helm-Replayed") != "true" ||
		again.Header.Get("Content-Type") != "text/event-stream" || again.Header.Get("Request-Id") != "req_upstream_1" {
		t.Fatalf("replay = %s %v", again, again.Header)
	}
	if n := e.anthropic.calls.Load(); n != 1 {
		t.Fatalf("%d provider calls for one request sent twice", n)
	}
	a := e.onlyAttempt()
	if again.Header.Get("X-Helm-Attempt-Id") != a.ID || a.State != "SETTLED" {
		t.Fatalf("the replay names %s; attempt %+v", again.Header.Get("X-Helm-Attempt-Id"), a)
	}
	if used, _ := e.counters(); used != anthropicStreamCost {
		t.Fatalf("a replay spent budget: used %d", used)
	}

	// Another episode is another scope: it calls the provider and gets its own attempt.
	other := post(t, e.worker.URL, "/v1/messages", workerHeaders(tokenAgentEp2), messagesRequest)
	if other.Status != 200 || other.Header.Get("X-Helm-Replayed") != "" || e.anthropic.calls.Load() != 2 {
		t.Fatalf("another episode: %s, %d calls", other, e.anthropic.calls.Load())
	}
	if len(e.attempts()) != 2 {
		t.Fatalf("%d attempts", len(e.attempts()))
	}
	// A different request in the same episode is a different call.
	post(t, e.worker.URL, "/v1/messages", workerHeaders(tokenAgent), strings.Replace(messagesRequest, `"hi"`, `"bye"`, 1))
	if e.anthropic.calls.Load() != 3 {
		t.Fatalf("a different request was replayed: %d calls", e.anthropic.calls.Load())
	}

	// The main listener scopes a call by a header, else by the token.
	e.anthropic.on(sseHandler(anthropicStream))
	headers := map[string]string{"Authorization": "Bearer " + tokenService, "X-Helm-Idempotency-Scope": "compile-job-1", "X-Helm-Case-Id": "org-compile-7", "Anthropic-Version": "2023-06-01"}
	before := e.anthropic.calls.Load()
	one := post(t, e.main.URL, "/v1/messages", headers, messagesRequest)
	two := post(t, e.main.URL, "/v1/messages", headers, messagesRequest)
	if one.Status != 200 || two.Status != 200 || two.Header.Get("X-Helm-Replayed") != "true" || e.anthropic.calls.Load() != before+1 {
		t.Fatalf("main listener replay: %s / %s, %d calls", one, two, e.anthropic.calls.Load()-before)
	}
	last := e.attempts()[len(e.attempts())-1]
	if last.CaseID != "org-compile-7" || last.RequesterPrincipalID != "svc:helm-org-compiler" || !strings.HasPrefix(last.IdempotencyKey, "mi:compile-job-1:") {
		t.Fatalf("main listener attempt = %+v", last)
	}
	e.ledgerBalances()
}

func TestPostgresConcurrentIdenticalRequestsCallTheProviderOnce(t *testing.T) {
	e := newEnv(t, 1_000_000)
	entered, release := make(chan struct{}, 1), make(chan struct{})
	e.anthropic.on(func(w http.ResponseWriter, r *http.Request) {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
		sseHandler(anthropicStream)(w, r)
	})
	var wg sync.WaitGroup
	results := make([]reply, 6)
	wg.Add(1)
	go func() {
		defer wg.Done()
		results[0] = post(t, e.worker.URL, "/v1/messages", workerHeaders(tokenAgent), messagesRequest)
	}()
	<-entered // the first call is with the provider
	for i := 1; i < len(results); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = post(t, e.worker.URL, "/v1/messages", workerHeaders(tokenAgent), messagesRequest)
		}()
	}
	time.Sleep(200 * time.Millisecond)
	close(release)
	wg.Wait()
	if n := e.anthropic.calls.Load(); n != 1 {
		t.Fatalf("%d provider calls for one request sent %d times at once", n, len(results))
	}
	ok, conflicts := 0, 0
	for _, r := range results {
		switch r.Status {
		case 200:
			ok++
		case 409:
			conflicts++
			if !strings.Contains(string(r.Body), "request_in_flight") && !strings.Contains(string(r.Body), "already") {
				t.Errorf("a conflict that does not say why: %s", r)
			}
		default:
			t.Errorf("unexpected reply %s", r)
		}
	}
	if ok < 1 || ok+conflicts != len(results) {
		t.Fatalf("%d ok, %d conflicts of %d", ok, conflicts, len(results))
	}
	if a := e.onlyAttempt(); a.State != "SETTLED" {
		t.Fatalf("attempt = %+v", a)
	}
	e.ledgerBalances()
	// Once settled, the same request replays.
	if r := post(t, e.worker.URL, "/v1/messages", workerHeaders(tokenAgent), messagesRequest); r.Header.Get("X-Helm-Replayed") != "true" {
		t.Fatalf("after settlement: %s", r)
	}
}

func TestPostgresDeniedCallsReachNoProvider(t *testing.T) {
	e := newEnv(t, 1_000_000)
	e.anthropic.on(sseHandler(anthropicStream))
	e.openai.on(sseHandler(chatDone))

	// A budget that cannot cover the worst case: 403 with the registry reason,
	// and the denial is an attempt on the record.
	small := newEnv(t, 1000) // the worst case of a default call is far above 1000 micros
	small.anthropic.on(sseHandler(anthropicStream))
	r := post(t, small.worker.URL, "/v1/messages", workerHeaders(tokenAgent), messagesRequest)
	if r.Status != 403 || r.Header.Get("X-Helm-Reason-Code") != string(contracts.ReasonBudgetExceeded) ||
		!strings.Contains(string(r.Body), `"type":"error"`) || !strings.Contains(string(r.Body), `"permission_error"`) || !strings.Contains(string(r.Body), "BUDGET_EXCEEDED") {
		t.Fatalf("budget: %s %v", r, r.Header)
	}
	if small.anthropic.calls.Load() != 0 {
		t.Fatal("a denied call reached the provider")
	}
	if a := small.onlyAttempt(); a.State != "DENIED" || a.ReasonCode != string(contracts.ReasonBudgetExceeded) || a.ModelCall != nil {
		t.Fatalf("denied attempt = %+v", a)
	}
	if used, reserved := small.counters(); used != 0 || reserved != 0 {
		t.Fatalf("a denial held budget: used %d reserved %d", used, reserved)
	}
	// The same on an OpenAI API: OpenAI's error shape, the reason as the code.
	r = post(t, small.worker.URL, "/v1/chat/completions", bearerHeader(tokenAgent), `{"model":"gpt-6-sol","messages":[]}`)
	if r.Status != 403 || !strings.Contains(string(r.Body), `"code":"BUDGET_EXCEEDED"`) || !strings.HasPrefix(string(r.Body), `{"error":{`) {
		t.Fatalf("budget on chat: %s", r)
	}

	// A per-call limit under the worst case.
	r = post(t, e.worker.URL, "/v1/messages", workerHeaders(tokenLimited), messagesRequest)
	if r.Status != 403 || r.Header.Get("X-Helm-Reason-Code") != string(contracts.ReasonPerCallLimit) || !strings.Contains(string(r.Body), "per-call limit") {
		t.Fatalf("per-call limit: %s %v", r, r.Header)
	}
	// A route the mandate's targets do not name.
	r = post(t, e.worker.URL, "/v1/messages", workerHeaders(tokenHaiku), messagesRequest)
	if r.Status != 403 || r.Header.Get("X-Helm-Reason-Code") != string(contracts.ReasonEffectOutOfScope) {
		t.Fatalf("route outside the mandate: %s %v", r, r.Header)
	}
	// A mandate that asks for an approval: model calls have no approver, so the
	// escalation is cancelled and the caller told what to change.
	r = post(t, e.worker.URL, "/v1/messages", workerHeaders(tokenApproval), messagesRequest)
	if r.Status != 403 || r.Header.Get("X-Helm-Reason-Code") != string(contracts.ReasonApprovalRequired) || !strings.Contains(string(r.Body), "change the mandate") {
		t.Fatalf("approval required: %s %v", r, r.Header)
	}
	states := map[string]int{}
	for _, a := range e.attempts() {
		states[a.State]++
		if a.State == "CANCELLED" && a.ReasonCode != "" {
			t.Errorf("a cancelled escalation carries a reason: %+v", a)
		}
	}
	if states["DENIED"] != 2 || states["CANCELLED"] != 1 || e.anthropic.calls.Load() != 0 {
		t.Fatalf("attempts by state %v, %d provider calls", states, e.anthropic.calls.Load())
	}
	if used, reserved := e.counters(); used != 0 || reserved != 0 {
		t.Fatalf("denials and a cancelled escalation left used %d reserved %d", used, reserved)
	}
	e.ledgerBalances()
}

func TestPostgresProviderExecutedToolsAreRefusedWithNoAttempt(t *testing.T) {
	e := newEnv(t, 1_000_000)
	e.openai.on(sseHandler(responsesStream))
	e.anthropic.on(sseHandler(anthropicStream))
	for name, test := range map[string]struct {
		path, body string
		headers    map[string]string
	}{
		"responses web search": {"/v1/responses", `{"model":"gpt-6-sol","input":"x","tools":[{"type":"web_search_preview"}]}`, bearerHeader(tokenAgent)},
		"responses mcp":        {"/v1/responses", `{"model":"gpt-6-sol","input":"x","tools":[{"type":"mcp","server_label":"s","server_url":"https://x"}]}`, bearerHeader(tokenAgent)},
		"responses background": {"/v1/responses", `{"model":"gpt-6-sol","input":"x","background":true}`, bearerHeader(tokenAgent)},
		"chat web search":      {"/v1/chat/completions", `{"model":"gpt-6-sol","messages":[],"web_search_options":{}}`, bearerHeader(tokenAgent)},
		"messages web search":  {"/v1/messages", `{"model":"claude-sonnet-5-5","max_tokens":9,"messages":[],"tools":[{"type":"web_search_20250305","name":"web_search"}]}`, workerHeaders(tokenAgent)},
		"messages mcp servers": {"/v1/messages", `{"model":"claude-sonnet-5-5","max_tokens":9,"messages":[],"mcp_servers":[{"type":"url","url":"https://x","name":"x"}]}`, workerHeaders(tokenAgent)},
	} {
		r := post(t, e.worker.URL, test.path, test.headers, test.body)
		if r.Status != 400 || !strings.Contains(string(r.Body), "unsupported_") && !strings.Contains(string(r.Body), "invalid_request_error") {
			t.Errorf("%s: %s", name, r)
		}
		if strings.HasPrefix(test.path, "/v1/messages") && !strings.Contains(string(r.Body), `"type":"error"`) {
			t.Errorf("%s: not Anthropic's error shape: %s", name, r)
		}
	}
	if n := len(e.attempts()); n != 0 {
		t.Fatalf("a refused request left %d attempts", n)
	}
	if e.openai.calls.Load()+e.anthropic.calls.Load() != 0 {
		t.Fatal("a refused request reached a provider")
	}
	if used, reserved := e.counters(); used != 0 || reserved != 0 {
		t.Fatalf("a refusal held budget: %d %d", used, reserved)
	}
	// Client-executed tools pass.
	if r := post(t, e.worker.URL, "/v1/responses", bearerHeader(tokenAgent), `{"model":"gpt-6-sol","stream":true,"input":"x","tools":[{"type":"function","name":"f"},{"type":"custom","name":"apply_patch"},{"type":"local_shell"}]}`); r.Status != 200 {
		t.Fatalf("function tools: %s", r)
	}
}

func TestPostgresProviderFailuresSettleWhatHappened(t *testing.T) {
	e := newEnv(t, 1_000_000)

	// A provider error before any generation: relayed as the provider wrote it,
	// and the hold released. Each retry is a new attempt under the next key.
	e.anthropic.on(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Retry-After", "7")
		w.Header().Set("Request-Id", "req_rate")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, `{"type":"error","error":{"type":"rate_limit_error","message":"slow down"}}`)
	})
	r := post(t, e.worker.URL, "/v1/messages", workerHeaders(tokenAgent), messagesRequest)
	if r.Status != 429 || r.Header.Get("Retry-After") != "7" || string(r.Body) != `{"type":"error","error":{"type":"rate_limit_error","message":"slow down"}}` {
		t.Fatalf("a provider's rate limit is relayed as it is: %s %v", r, r.Header)
	}
	a := e.attempts()[0]
	if a.State != "OBSERVED" || a.Outcome != "FAILED" || a.ReasonCode != string(contracts.ReasonProviderError) || a.ModelCall.State != admission.SettlementReleased {
		t.Fatalf("after a 429: %+v %+v", a, a.ModelCall)
	}
	if used, reserved := e.counters(); used != 0 || reserved != 0 {
		t.Fatalf("a refused call kept its hold: %d %d", used, reserved)
	}
	e.anthropic.on(sseHandler(anthropicStream))
	r = post(t, e.worker.URL, "/v1/messages", workerHeaders(tokenAgent), messagesRequest)
	if r.Status != 200 || r.Header.Get("X-Helm-Replayed") != "" {
		t.Fatalf("the retry after a failure must call the provider again: %s", r)
	}
	all := e.attempts()
	if len(all) != 2 || !strings.HasSuffix(all[0].IdempotencyKey, ":0") || !strings.HasSuffix(all[1].IdempotencyKey, ":1") || all[1].State != "SETTLED" {
		t.Fatalf("attempts = %+v", all)
	}
	e.ledgerBalances()

	// A key the provider rejects is the operator's problem, not the caller's:
	// a 502 the caller can tell from its own token failing, and no leak.
	e.openai.on(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":{"message":"Incorrect API key provided: `+keyOpenAI+`"}}`)
	})
	r = post(t, e.worker.URL, "/v1/chat/completions", bearerHeader(tokenAgent), `{"model":"gpt-6-sol","messages":[]}`)
	if r.Status != 502 || r.Header.Get("X-Helm-Reason-Code") != string(contracts.ReasonProviderCredentialRejected) || strings.Contains(string(r.Body), keyOpenAI) {
		t.Fatalf("a rejected provider key: %s %v", r, r.Header)
	}
	last := e.attempts()[len(e.attempts())-1]
	if last.State != "OBSERVED" || last.ReasonCode != string(contracts.ReasonProviderCredentialRejected) {
		t.Fatalf("attempt = %+v", last)
	}

	// A provider that cannot be reached: nothing was sent, the hold is released.
	dead := newStubProvider(t)
	deadURL := dead.URL
	dead.Close()
	cfg, err := ParseConfig([]byte(routesJSON(e.anthropic.URL, deadURL+"/v1", e.openrouter.URL, e.keys)))
	must(t, err)
	unreachable := *e.gw
	unreachable.Config = cfg
	srv := servedHandler(t, &unreachable, e)
	r = post(t, srv, "/v1/chat/completions", bearerHeader(tokenAgent), `{"model":"gpt-6-sol","messages":[]}`)
	if r.Status != 502 || !strings.Contains(string(r.Body), "provider_unavailable") {
		t.Fatalf("an unreachable provider: %s", r)
	}
	last = e.attempts()[len(e.attempts())-1]
	if last.State != "OBSERVED" || last.Outcome != "FAILED" || last.ModelCall.State != admission.SettlementReleased {
		t.Fatalf("an unreachable provider: %+v %+v", last, last.ModelCall)
	}
	if used, reserved := e.counters(); reserved != 0 || used != anthropicStreamCost {
		t.Fatalf("counters after failures: used %d reserved %d", used, reserved)
	}
	e.ledgerBalances()
}

// servedHandler serves g's worker handler on a fresh server that shares e's
// authentication.
func servedHandler(t *testing.T, g *Gateway, e *env) string {
	t.Helper()
	h := g.Handler(Listener{Name: "worker", Auth: e.workerAuth(), Worker: true})
	srv := newTestServer(t, h)
	return srv
}

func TestPostgresACutStreamIsUnknownWithItsHoldAsAnEstimate(t *testing.T) {
	e := newEnv(t, 1_000_000)
	cut := anthropicStream[:strings.Index(anthropicStream, "event: message_delta")]
	e.anthropic.on(sseHandler(cut)) // the provider ends the stream before message_stop
	resp, err := requestOnce(e.worker.URL+"/v1/messages", workerHeaders(tokenAgent), messagesRequest)
	if err == nil {
		// The connection was severed after part of the stream: the client
		// must see an error, not a finished stream.
		body, rerr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if rerr == nil {
			t.Fatalf("a stream cut at the provider reached the client as complete: %q", body)
		}
	}
	a := e.onlyAttempt()
	if a.State != "UNKNOWN" || a.ReasonCode != string(contracts.ReasonProviderError) || a.ModelCall.State != admission.SettlementEstimated {
		t.Fatalf("a cut stream: %+v %+v", a, a.ModelCall)
	}
	held := a.ModelCall.HeldMicros
	if *a.ModelCall.EstimatedMicros != held {
		t.Fatalf("estimated %d, held %d", *a.ModelCall.EstimatedMicros, held)
	}
	if used, reserved := e.counters(); used != held || reserved != 0 {
		t.Fatalf("a cut stream: used %d reserved %d, want the hold counted as used (%d)", used, reserved, held)
	}
	e.ledgerBalances()

	// The retry is a new attempt: the unknown one keeps its estimate and is
	// never sent again.
	e.anthropic.on(sseHandler(anthropicStream))
	r := post(t, e.worker.URL, "/v1/messages", workerHeaders(tokenAgent), messagesRequest)
	if r.Status != 200 || r.Header.Get("X-Helm-Replayed") != "" {
		t.Fatalf("retry: %s", r)
	}
	all := e.attempts()
	if len(all) != 2 || all[0].State != "UNKNOWN" || all[1].State != "SETTLED" || !strings.HasSuffix(all[1].IdempotencyKey, ":1") {
		t.Fatalf("attempts = %+v", all)
	}
	if used, _ := e.counters(); used != held+anthropicStreamCost {
		t.Fatalf("used %d, want the estimate and the settled call: %d", used, held+anthropicStreamCost)
	}
	e.ledgerBalances()
}

func TestPostgresAClientThatLeavesCancelsTheProviderCall(t *testing.T) {
	e := newEnv(t, 1_000_000)
	started, canceled := make(chan struct{}), make(chan struct{})
	e.anthropic.on(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		events := strings.SplitAfter(anthropicStream, "\n\n")
		_, _ = io.WriteString(w, events[0])
		w.(http.Flusher).Flush()
		close(started)
		select {
		case <-r.Context().Done():
			close(canceled)
		case <-time.After(10 * time.Second):
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.worker.URL+"/v1/messages", strings.NewReader(messagesRequest))
	must(t, err)
	req.Header.Set("Content-Type", "application/json")
	for k, v := range workerHeaders(tokenAgent) {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	must(t, err)
	<-started
	if _, err := bufio.NewReader(resp.Body).ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	cancel() // the agent gave up
	_ = resp.Body.Close()
	select {
	case <-canceled:
	case <-time.After(5 * time.Second):
		t.Fatal("the provider call was not cancelled when the client left")
	}
	waitFor(t, "the cut call to settle", func() bool {
		all := e.attempts()
		return len(all) == 1 && all[0].State == "UNKNOWN"
	})
	a := e.onlyAttempt()
	if a.ModelCall.State != admission.SettlementEstimated {
		t.Fatalf("model call = %+v", a.ModelCall)
	}
	e.ledgerBalances()
}

func TestPostgresAStalledStreamEndsAtItsIdleTimeout(t *testing.T) {
	e := newEnv(t, 1_000_000) // idle_timeout is 1s in the test routes
	e.anthropic.on(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		_, _ = io.WriteString(w, strings.SplitAfter(anthropicStream, "\n\n")[0])
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	})
	start := time.Now()
	resp, err := requestOnce(e.worker.URL+"/v1/messages", workerHeaders(tokenAgent), messagesRequest)
	if err == nil {
		_, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
	}
	if elapsed := time.Since(start); elapsed > 8*time.Second {
		t.Fatalf("the stalled stream took %s", elapsed)
	}
	waitFor(t, "the stalled call to settle", func() bool { all := e.attempts(); return len(all) == 1 && all[0].State == "UNKNOWN" })
	e.ledgerBalances()
}

func TestPostgresAnOverageIsRecordedAsReportedAndNeverBilledPastTheHold(t *testing.T) {
	e := newEnv(t, 1_000_000)
	// A provider that ignores the maximum and reports far more output than the
	// gateway allowed: the counter takes what was reported.
	e.anthropic.on(jsonHandler(`{"id":"m","type":"message","usage":{"input_tokens":10,"output_tokens":9999999}}`))
	r := post(t, e.worker.URL, "/v1/messages", workerHeaders(tokenAgent), `{"model":"claude-sonnet-5-5","max_tokens":10,"messages":[]}`)
	if r.Status != 200 {
		t.Fatal(r)
	}
	a := e.onlyAttempt()
	mc := a.ModelCall
	if mc.State != admission.SettlementConfirmed || *mc.ConfirmedMicros <= mc.HeldMicros || mc.BillableMicros != mc.HeldMicros {
		t.Fatalf("overage: %+v (confirmed must exceed held; billable is held)", mc)
	}
	if used, _ := e.counters(); used != *mc.ConfirmedMicros {
		t.Fatalf("the counter holds %d, the provider reported %d", used, *mc.ConfirmedMicros)
	}
	if !strings.Contains(e.logs.String(), "overage") {
		t.Fatal("an overage was not logged")
	}
	e.ledgerBalances()
	// The next call is refused: the counter shows the overrun.
	r = post(t, e.worker.URL, "/v1/messages", workerHeaders(tokenAgent), messagesRequest)
	if r.Status != 403 || r.Header.Get("X-Helm-Reason-Code") != string(contracts.ReasonBudgetExceeded) {
		t.Fatalf("after an overage: %s", r)
	}
}

func TestPostgresTheProviderKeyIsReadPerCallSoARotationIsUsedAtOnce(t *testing.T) {
	e := newEnv(t, 1_000_000)
	e.anthropic.on(jsonHandler(`{"usage":{"input_tokens":1,"output_tokens":1}}`))
	post(t, e.worker.URL, "/v1/messages", workerHeaders(tokenAgent), messagesRequest)
	if got := e.anthropic.last(t).Header.Get("X-Api-Key"); got != keyAnthropic {
		t.Fatalf("key = %q", got)
	}
	rotated := "canary-anthropic-api-key-rotated"
	writeFile(t, e.keys+"/anthropic", rotated+"\n")
	post(t, e.worker.URL, "/v1/messages", workerHeaders(tokenAgent), strings.Replace(messagesRequest, `"hi"`, `"again"`, 1))
	if got := e.anthropic.last(t).Header.Get("X-Api-Key"); got != rotated {
		t.Fatalf("after a rotation the provider saw %q", got)
	}
}
