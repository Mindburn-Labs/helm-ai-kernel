package mcpserver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"connectrpc.com/connect"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/admission"
)

// fakeBackend stands in for the gateway: the protocol tests run without a
// database and assert what the transport lets through to it.
type fakeBackend struct {
	calls, lists int
	call         Call
	caller       Caller
	tools        []Tool
	result       Result
	err          error
}

func (b *fakeBackend) Tools(_ context.Context, c Caller) ([]Tool, error) {
	b.lists++
	b.caller = c
	return b.tools, b.err
}

func (b *fakeBackend) Call(_ context.Context, c Caller, call Call) (Result, error) {
	b.calls++
	b.caller, b.call = c, call
	return b.result, b.err
}

func workerCaller() Caller {
	return Caller{Caller: admission.Caller{TenantID: "tenant", WorkspaceID: "workspace", PrincipalID: "agt:seat",
		ActorID: "cp", Episode: &admission.Episode{EpisodeID: "episode", WorkItemID: "work", OrganizationVersionID: "version"}}, Scope: "helm.gateway.propose"}
}

func newHandler(b *fakeBackend) *Handler {
	return &Handler{Backend: b, Version: "test", Authenticate: func(context.Context, http.Header) (Caller, error) { return workerCaller(), nil }}
}

func newFake() *fakeBackend {
	return &fakeBackend{
		tools:  []Tool{{Name: "helm_work_report", InputSchema: json.RawMessage(`{"type":"object"}`)}, {Name: "github_repository_get", InputSchema: json.RawMessage(`{"type":"object"}`)}},
		result: Result{StructuredContent: map[string]any{"status": "escalated", "attempt_id": "attempt-1"}},
	}
}

// legacy builds a POST of the initialization-based revisions: no per-request
// metadata, and the protocol version in a header once a handshake has named it.
func legacy(body string, version string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "https://gateway.test/mcp", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	if version != "" {
		r.Header.Set("MCP-Protocol-Version", version)
	}
	return r
}

// modern builds a POST of 2026-07-28: the version in the header and in _meta, the
// method mirrored in a header, and the tool name too for a call.
func modern(id any, method string, params map[string]any) *http.Request {
	if params == nil {
		params = map[string]any{}
	}
	params["_meta"] = map[string]any{
		"io.modelcontextprotocol/protocolVersion":    ProtocolModern,
		"io.modelcontextprotocol/clientInfo":         map[string]string{"name": "native-client", "version": "1"},
		"io.modelcontextprotocol/clientCapabilities": map[string]any{},
	}
	raw, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
	r := legacy(string(raw), ProtocolModern)
	r.Header.Set("Mcp-Method", method)
	if name, ok := params["name"].(string); ok {
		r.Header.Set("Mcp-Name", name)
	}
	return r
}

type response struct {
	Code   int
	Header http.Header
	Body   map[string]any
}

func serve(t *testing.T, h *Handler, r *http.Request) response {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	out := response{Code: w.Code, Header: w.Header()}
	if w.Body.Len() > 0 && strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") {
		if err := json.Unmarshal(w.Body.Bytes(), &out.Body); err != nil {
			t.Fatalf("response is not JSON: %s", w.Body.String())
		}
	}
	return out
}

func (r response) result(t *testing.T) map[string]any {
	t.Helper()
	m, ok := r.Body["result"].(map[string]any)
	if r.Code != http.StatusOK || !ok {
		t.Fatalf("not a result: %d %v", r.Code, r.Body)
	}
	return m
}

// failure asserts a JSON-RPC error answer with its HTTP status and code.
func (r response) failure(t *testing.T, status, code int) map[string]any {
	t.Helper()
	e, ok := r.Body["error"].(map[string]any)
	if r.Code != status || !ok || int(e["code"].(float64)) != code {
		t.Fatalf("want error %d (HTTP %d), got HTTP %d %v", code, status, r.Code, r.Body)
	}
	return e
}

// The handshake of the initialization-based revisions, which nothing is kept
// from: each of the three revisions is answered with itself, an unknown one with
// the newest, and the session id the client is given is a fresh random one the
// server never looks up.
func TestLegacyHandshakeNegotiatesAndKeepsNothing(t *testing.T) {
	b := newFake()
	h := newHandler(b)
	sessions := map[string]bool{}
	for _, version := range []string{"2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05", "2026-07-28", "2099-01-01"} {
		want := version
		if !strings.HasPrefix(version, "2025-") {
			want = "2025-11-25"
		}
		r := legacy(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"`+version+`","capabilities":{},"clientInfo":{"name":"c","version":"1"}}}`, "")
		r.Header.Set("Mcp-Session-Id", "client-made-up")
		got := serve(t, h, r)
		result := got.result(t)
		if session := got.Header.Get("Mcp-Session-Id"); !sessionIDPattern.MatchString(session) || session == "client-made-up" || sessions[session] {
			t.Errorf("session id %q is not a fresh one of the server's own", session)
		} else {
			sessions[session] = true
		}
		if result["protocolVersion"] != want {
			t.Errorf("initialize %s answered %v, want %s", version, result["protocolVersion"], want)
		}
		if _, ok := result["resultType"]; ok {
			t.Error("a legacy result carries resultType")
		}
		if info := result["serverInfo"].(map[string]any); info["name"] != "helm-gateway" || info["version"] != "test" {
			t.Errorf("serverInfo = %v", info)
		}
		tools := result["capabilities"].(map[string]any)["tools"].(map[string]any)
		if tools["listChanged"] != false {
			t.Errorf("tools capability = %v", tools)
		}
	}
	// notifications/initialized is accepted and answered with nothing.
	got := serve(t, h, legacy(`{"jsonrpc":"2.0","method":"notifications/initialized"}`, "2025-11-25"))
	if got.Code != http.StatusAccepted || got.Body != nil {
		t.Fatalf("notification: %d %v", got.Code, got.Body)
	}
	// ping answers an empty result, and only in this era.
	if r := serve(t, h, legacy(`{"jsonrpc":"2.0","id":2,"method":"ping"}`, "2025-11-25")).result(t); len(r) != 0 {
		t.Fatalf("ping = %v", r)
	}
	// A request with no header at all is the oldest revision's.
	if r := serve(t, h, legacy(`{"jsonrpc":"2.0","id":3,"method":"tools/list"}`, "")).result(t); r["tools"] == nil {
		t.Fatalf("tools/list without a header = %v", r)
	}
	// Initialization is refused a bad params object, and a modern client that
	// sends it is told the method does not exist in its revision.
	serve(t, h, legacy(`{"jsonrpc":"2.0","id":4,"method":"initialize","params":{}}`, "")).failure(t, http.StatusOK, codeInvalidParams)
	serve(t, h, legacy(`{"jsonrpc":"2.0","id":5,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}`, ProtocolModern)).failure(t, http.StatusNotFound, codeMethodNotFound)
	if b.calls != 0 {
		t.Fatalf("the handshake reached the backend %d times", b.calls)
	}
}

func TestLegacyToolsAreListedSortedAndPlain(t *testing.T) {
	b := newFake()
	result := serve(t, newHandler(b), legacy(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`, "2025-11-25")).result(t)
	tools := result["tools"].([]any)
	if len(tools) != 2 || tools[0].(map[string]any)["name"] != "github_repository_get" || tools[1].(map[string]any)["name"] != "helm_work_report" {
		t.Fatalf("tools = %v", tools)
	}
	for _, key := range []string{"resultType", "ttlMs", "cacheScope", "_meta"} {
		if _, ok := result[key]; ok {
			t.Errorf("a legacy list carries %s", key)
		}
	}
	// An empty list is a list.
	b.tools = nil
	if tools := serve(t, newHandler(b), legacy(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, "2025-11-25")).result(t)["tools"].([]any); tools == nil || len(tools) != 0 {
		t.Fatalf("an empty tool list = %v", tools)
	}
	// There is no paging: a cursor is not one this server issued.
	serve(t, newHandler(b), legacy(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"cursor":"x"}}`, "2025-11-25")).failure(t, http.StatusOK, codeInvalidParams)
}

// server/discover of the stateless revision: versions, capabilities, identity,
// the instructions a model reads, and a freshness hint that is public because
// nothing in the answer depends on who asks.
func TestModernDiscoveryAndDeterministicPrivateList(t *testing.T) {
	b := newFake()
	h := newHandler(b)
	discover := serve(t, h, modern("discover-1", "server/discover", nil)).result(t)
	if discover["resultType"] != "complete" || discover["cacheScope"] != "public" || discover["ttlMs"].(float64) <= 0 {
		t.Fatalf("discovery = %v", discover)
	}
	versions := discover["supportedVersions"].([]any)
	if versions[0] != ProtocolModern || len(versions) != 4 {
		t.Fatalf("supportedVersions = %v", versions)
	}
	meta := discover["_meta"].(map[string]any)["io.modelcontextprotocol/serverInfo"].(map[string]any)
	if meta["name"] != "helm-gateway" || discover["instructions"] == "" || discover["capabilities"] == nil {
		t.Fatalf("discovery = %v", discover)
	}

	list := serve(t, h, modern(7, "tools/list", nil)).result(t)
	if list["resultType"] != "complete" || list["cacheScope"] != "private" || list["ttlMs"].(float64) < 0 {
		t.Fatalf("tools/list = %v", list)
	}
	tools := list["tools"].([]any)
	if tools[0].(map[string]any)["name"] != "github_repository_get" {
		t.Fatalf("the list is not in name order: %v", tools)
	}
	if b.caller.PrincipalID != "agt:seat" || b.caller.Episode.EpisodeID != "episode" || b.lists != 1 {
		t.Fatalf("the backend saw %+v", b.caller)
	}
}

func TestModernCallAnswersEscalationAsASuccessWithATextFallback(t *testing.T) {
	b := newFake()
	h := newHandler(b)
	call := serve(t, h, modern("call-1", "tools/call", map[string]any{"name": "helm_work_report", "arguments": map[string]any{"target": "work:1"}})).result(t)
	if call["resultType"] != "complete" || call["isError"] != false {
		t.Fatalf("an escalation is not a success: %v", call)
	}
	structured := call["structuredContent"].(map[string]any)
	if structured["status"] != "escalated" || structured["attempt_id"] != "attempt-1" {
		t.Fatalf("structuredContent = %v", structured)
	}
	content := call["content"].([]any)
	if len(content) != 1 || content[0].(map[string]any)["type"] != "text" {
		t.Fatalf("content = %v", content)
	}
	var fallback map[string]any
	if json.Unmarshal([]byte(content[0].(map[string]any)["text"].(string)), &fallback) != nil || fallback["attempt_id"] != "attempt-1" {
		t.Fatal("the text is not the structured result serialized, which older clients read")
	}
	if b.calls != 1 || b.call.Name != "helm_work_report" || string(b.call.RequestID) != `"call-1"` || string(b.call.Arguments) != `{"target":"work:1"}` {
		t.Fatalf("the backend got %+v", b.call)
	}
	// A tool error is a result with isError, not a protocol error.
	b.result = Result{StructuredContent: map[string]any{"status": "denied", "reason_code": "EFFECT_OUT_OF_SCOPE"}, IsError: true}
	denied := serve(t, h, modern(2, "tools/call", map[string]any{"name": "github_repository_get"})).result(t)
	if denied["isError"] != true || denied["structuredContent"].(map[string]any)["reason_code"] != "EFFECT_OUT_OF_SCOPE" {
		t.Fatalf("denial = %v", denied)
	}
	// No arguments is an empty object, which the backend refuses in its own terms.
	if string(b.call.Arguments) != `{}` {
		t.Fatalf("missing arguments reached the backend as %q", b.call.Arguments)
	}
}

// What the stateless revision asks of a request is checked before any
// credential is read: each failure is 400 with its own code, and none reaches
// the backend or the authenticator.
func TestModernRequestValidation(t *testing.T) {
	good := func() *http.Request {
		return modern(1, "tools/call", map[string]any{"name": "helm_work_report", "arguments": map[string]any{}})
	}
	for name, test := range map[string]struct {
		edit   func(*http.Request) *http.Request
		status int
		code   int
	}{
		"no _meta": {func(*http.Request) *http.Request {
			r := legacy(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`, ProtocolModern)
			r.Header.Set("Mcp-Method", "tools/list")
			return r
		}, http.StatusBadRequest, codeInvalidParams},
		"no params at all": {func(*http.Request) *http.Request {
			r := legacy(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, ProtocolModern)
			r.Header.Set("Mcp-Method", "tools/list")
			return r
		}, http.StatusBadRequest, codeInvalidParams},
		"no protocol version in _meta": {func(*http.Request) *http.Request {
			r := legacy(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/clientCapabilities":{}}}}`, ProtocolModern)
			r.Header.Set("Mcp-Method", "tools/list")
			return r
		}, http.StatusBadRequest, codeInvalidParams},
		"no client capabilities": {func(*http.Request) *http.Request {
			r := legacy(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`, ProtocolModern)
			r.Header.Set("Mcp-Method", "tools/list")
			return r
		}, http.StatusBadRequest, codeInvalidParams},
		"capabilities that are not an object": {func(*http.Request) *http.Request {
			r := legacy(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":[]}}}`, ProtocolModern)
			r.Header.Set("Mcp-Method", "tools/list")
			return r
		}, http.StatusBadRequest, codeInvalidParams},
		"_meta names another version than the header": {func(*http.Request) *http.Request {
			r := legacy(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2025-11-25","io.modelcontextprotocol/clientCapabilities":{}}}}`, ProtocolModern)
			r.Header.Set("Mcp-Method", "tools/list")
			return r
		}, http.StatusBadRequest, codeHeaderMismatch},
		"a modern body under a legacy header": {func(r *http.Request) *http.Request {
			r.Header.Set("MCP-Protocol-Version", "2025-11-25")
			return r
		}, http.StatusBadRequest, codeHeaderMismatch},
		"a modern body under no header": {func(r *http.Request) *http.Request {
			r.Header.Del("MCP-Protocol-Version")
			return r
		}, http.StatusBadRequest, codeHeaderMismatch},
		"no Mcp-Method": {func(r *http.Request) *http.Request { r.Header.Del("Mcp-Method"); return r }, http.StatusBadRequest, codeHeaderMismatch},
		"Mcp-Method of another method": {func(r *http.Request) *http.Request {
			r.Header.Set("Mcp-Method", "tools/list")
			return r
		}, http.StatusBadRequest, codeHeaderMismatch},
		"no Mcp-Name on a call": {func(r *http.Request) *http.Request { r.Header.Del("Mcp-Name"); return r }, http.StatusBadRequest, codeHeaderMismatch},
		"Mcp-Name of another tool": {func(r *http.Request) *http.Request {
			r.Header.Set("Mcp-Name", "github_repository_get")
			return r
		}, http.StatusBadRequest, codeHeaderMismatch},
		"Mcp-Name in a broken sentinel": {func(r *http.Request) *http.Request {
			r.Header.Set("Mcp-Name", "=?base64?!!!?=")
			return r
		}, http.StatusBadRequest, codeHeaderMismatch},
		"a version the server does not speak": {func(r *http.Request) *http.Request {
			r.Header.Set("MCP-Protocol-Version", "2099-01-01")
			return r
		}, http.StatusBadRequest, codeUnsupportedVersion},
	} {
		t.Run(name, func(t *testing.T) {
			b, authenticated := newFake(), false
			h := newHandler(b)
			h.Authenticate = func(context.Context, http.Header) (Caller, error) { authenticated = true; return workerCaller(), nil }
			serve(t, h, test.edit(good())).failure(t, test.status, test.code)
			if b.calls+b.lists != 0 || authenticated {
				t.Fatalf("a malformed request reached the backend (%d) or the authenticator (%v)", b.calls+b.lists, authenticated)
			}
		})
	}
	// The unsupported-version answer lists what is supported and what was asked.
	r := good()
	r.Header.Set("MCP-Protocol-Version", "1900-01-01")
	e := serve(t, newHandler(newFake()), r).failure(t, http.StatusBadRequest, codeUnsupportedVersion)
	data := e["data"].(map[string]any)
	if data["requested"] != "1900-01-01" || len(data["supported"].([]any)) != 4 || data["supported"].([]any)[0] != ProtocolModern {
		t.Fatalf("data = %v", data)
	}
}

func TestModernNameHeaderMayBeBase64Encoded(t *testing.T) {
	b := newFake()
	name := "outil_été"
	r := modern(1, "tools/call", map[string]any{"name": name, "arguments": map[string]any{}})
	r.Header.Set("Mcp-Name", "=?base64?"+base64.StdEncoding.EncodeToString([]byte(name))+"?=")
	serve(t, newHandler(b), r).result(t)
	if b.call.Name != name {
		t.Fatalf("the backend got %q", b.call.Name)
	}
}

func TestModernKnowsNoMethodsOfTheOlderRevisions(t *testing.T) {
	h := newHandler(newFake())
	// ping and the handshake belong to the initialization-based revisions, and a
	// method that does not exist is 404 with -32601.
	for _, method := range []string{"ping", "initialize", "prompts/list", "resources/list", "logging/setLevel", "subscriptions/listen", "nope"} {
		serve(t, h, modern(1, method, nil)).failure(t, http.StatusNotFound, codeMethodNotFound)
	}
	// The older revisions answer an unknown method inside a 200, as they did.
	serve(t, h, legacy(`{"jsonrpc":"2.0","id":1,"method":"server/discover"}`, "2025-11-25")).failure(t, http.StatusOK, codeMethodNotFound)
	serve(t, h, legacy(`{"jsonrpc":"2.0","id":1,"method":"prompts/list"}`, "2025-11-25")).failure(t, http.StatusOK, codeMethodNotFound)
}

func TestTransportRefusesSmuggledIdentityAndAmbiguousJSON(t *testing.T) {
	b := newFake()
	h := newHandler(b)
	for name, body := range map[string]string{
		"body work binding":    `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"helm_work_report","arguments":{},"work_ref":{"case_id":"foreign"}}}`,
		"episode in params":    `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"helm_work_report","arguments":{},"episode_id":"other"}}`,
		"duplicate method":     `{"jsonrpc":"2.0","id":1,"method":"ping","method":"tools/call","params":{"name":"helm_work_report","arguments":{}}}`,
		"escaped duplicate":    `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"helm_work_report","arguments":{"x":1,"x":2}}}`,
		"null id":              `{"jsonrpc":"2.0","id":null,"method":"tools/call","params":{"name":"helm_work_report","arguments":{}}}`,
		"empty string id":      `{"jsonrpc":"2.0","id":"","method":"tools/call","params":{"name":"helm_work_report","arguments":{}}}`,
		"fractional id":        `{"jsonrpc":"2.0","id":1.5,"method":"tools/call","params":{"name":"helm_work_report","arguments":{}}}`,
		"object id":            `{"jsonrpc":"2.0","id":{},"method":"tools/call","params":{"name":"helm_work_report","arguments":{}}}`,
		"second envelope":      `{"jsonrpc":"2.0","id":1,"method":"ping"} {"jsonrpc":"2.0","id":2,"method":"ping"}`,
		"a batch":              `[{"jsonrpc":"2.0","id":1,"method":"ping"}]`,
		"a response":           `{"jsonrpc":"2.0","id":1,"result":{}}`,
		"wrong jsonrpc":        `{"jsonrpc":"1.0","id":1,"method":"ping"}`,
		"no method":            `{"jsonrpc":"2.0","id":1}`,
		"arguments an array":   `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"helm_work_report","arguments":[]}}`,
		"no tool name":         `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"arguments":{}}}`,
		"unknown notification": `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"helm_work_report"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, legacy(body, "2025-11-25"))
			if !strings.Contains(w.Body.String(), `"error"`) || w.Code == http.StatusAccepted {
				t.Fatalf("request accepted: %d %s", w.Code, w.Body.String())
			}
		})
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, legacy(`{"jsonrpc":"2.0","id":1,`, "2025-11-25"))
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), `"code":-32700`) {
		t.Fatalf("broken JSON: %d %s", w.Code, w.Body.String())
	}
	if b.calls != 0 {
		t.Fatalf("refused requests reached the backend %d times", b.calls)
	}
	// A request id is a string or an integer, and either is accepted and passed
	// through as sent.
	for _, id := range []string{`"a"`, `7`, `-3`} {
		serve(t, h, legacy(`{"jsonrpc":"2.0","id":`+id+`,"method":"tools/call","params":{"name":"helm_work_report","arguments":{}}}`, "2025-11-25")).result(t)
		if string(b.call.RequestID) != id {
			t.Errorf("id %s reached the backend as %s", id, b.call.RequestID)
		}
	}
}

func TestTransportChecksOriginMethodAuthenticationAndBounds(t *testing.T) {
	for name, test := range map[string]struct {
		edit func(*http.Request)
		code int
	}{
		"foreign origin": {func(r *http.Request) { r.Header.Set("Origin", "https://evil.test") }, http.StatusForbidden},
		"null origin":    {func(r *http.Request) { r.Header.Set("Origin", "null") }, http.StatusForbidden},
		"two origins": {func(r *http.Request) {
			r.Header.Add("Origin", "https://gateway.test")
			r.Header.Add("Origin", "https://gateway.test")
		}, http.StatusForbidden},
		"unsupported version":   {func(r *http.Request) { r.Header.Set("MCP-Protocol-Version", "next") }, http.StatusBadRequest},
		"missing accept":        {func(r *http.Request) { r.Header.Del("Accept") }, http.StatusNotAcceptable},
		"accept without stream": {func(r *http.Request) { r.Header.Set("Accept", "application/json") }, http.StatusNotAcceptable},
		"not JSON":              {func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }, http.StatusUnsupportedMediaType},
		"compressed":            {func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") }, http.StatusUnsupportedMediaType},
		"GET":                   {func(r *http.Request) { r.Method = http.MethodGet }, http.StatusMethodNotAllowed},
		"DELETE":                {func(r *http.Request) { r.Method = http.MethodDelete }, http.StatusMethodNotAllowed},
	} {
		t.Run(name, func(t *testing.T) {
			authenticated := false
			h := &Handler{Backend: newFake(), Authenticate: func(context.Context, http.Header) (Caller, error) { authenticated = true; return workerCaller(), nil }}
			r := legacy(`{"jsonrpc":"2.0","id":1,"method":"ping"}`, "2025-11-25")
			test.edit(r)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != test.code || authenticated {
				t.Fatalf("code=%d authenticated=%v", w.Code, authenticated)
			}
			if test.code == http.StatusMethodNotAllowed && w.Header().Get("Allow") != "POST" {
				t.Fatalf("Allow = %q", w.Header().Get("Allow"))
			}
		})
	}
	count := 0
	h := &Handler{Backend: newFake(), Authenticate: func(context.Context, http.Header) (Caller, error) { count++; return workerCaller(), nil }}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, legacy(strings.Repeat("x", MaxRequestBytes+1), "2025-11-25"))
	if w.Code != http.StatusRequestEntityTooLarge || count != 0 {
		t.Fatal("oversized input reached authentication")
	}
	// An origin that is the server's own is a browser page of the same origin.
	r := legacy(`{"jsonrpc":"2.0","id":1,"method":"ping"}`, "2025-11-25")
	r.Header.Set("Origin", "https://gateway.test")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("the server's own origin was refused: %d", w.Code)
	}
}

func TestAuthenticationFailuresAreHTTPStatusesNotToolResults(t *testing.T) {
	for name, test := range map[string]struct {
		auth   func(context.Context, http.Header) (Caller, error)
		status int
	}{
		"invalid credentials": {func(context.Context, http.Header) (Caller, error) {
			return Caller{}, connect.NewError(connect.CodeUnauthenticated, nil)
		}, http.StatusUnauthorized},
		"a token that does not cover it": {func(context.Context, http.Header) (Caller, error) {
			return Caller{}, connect.NewError(connect.CodePermissionDenied, nil)
		}, http.StatusForbidden},
		"keys unavailable": {func(context.Context, http.Header) (Caller, error) {
			return Caller{}, connect.NewError(connect.CodeUnavailable, nil)
		}, http.StatusServiceUnavailable},
		"a failure nobody classified": {func(context.Context, http.Header) (Caller, error) {
			return Caller{}, errors.New("boom")
		}, http.StatusServiceUnavailable},
		"a token with no episode": {func(context.Context, http.Header) (Caller, error) {
			c := workerCaller()
			c.Episode = nil
			return c, nil
		}, http.StatusForbidden},
		"a token with no principal": {func(context.Context, http.Header) (Caller, error) {
			c := workerCaller()
			c.PrincipalID = ""
			return c, nil
		}, http.StatusForbidden},
	} {
		t.Run(name, func(t *testing.T) {
			b := newFake()
			h := &Handler{Backend: b, Authenticate: test.auth}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, legacy(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, "2025-11-25"))
			if w.Code != test.status || b.lists != 0 {
				t.Fatalf("code=%d lists=%d", w.Code, b.lists)
			}
			if test.status == http.StatusUnauthorized && w.Header().Get("WWW-Authenticate") != "Bearer" {
				t.Fatal("invalid credentials did not produce a bearer challenge")
			}
		})
	}
	// Both ends missing is unavailable, not a panic.
	w := httptest.NewRecorder()
	(&Handler{}).ServeHTTP(w, legacy(`{"jsonrpc":"2.0","id":1,"method":"ping"}`, ""))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("an unconfigured handler answered %d", w.Code)
	}
}

func TestBackendFailuresBecomeTheRightAnswer(t *testing.T) {
	for name, test := range map[string]struct {
		err    error
		status int
		code   int
	}{
		"a forbidden principal": {ErrForbidden, http.StatusForbidden, 0},
		"an unknown tool":       {ErrUnknownTool, http.StatusOK, codeInvalidParams},
		"a failed ledger":       {errors.New("pq: connection refused"), http.StatusOK, codeInternal},
	} {
		t.Run(name, func(t *testing.T) {
			b := newFake()
			b.err = test.err
			h := newHandler(b)
			for _, r := range []*http.Request{
				legacy(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, "2025-11-25"),
				legacy(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x"}}`, "2025-11-25"),
			} {
				got := serve(t, h, r)
				if got.Code != test.status {
					t.Fatalf("HTTP %d, want %d (%v)", got.Code, test.status, got.Body)
				}
				if test.code != 0 {
					// The answer says nothing about the ledger's own failure.
					if message := got.failure(t, test.status, test.code)["message"].(string); strings.Contains(message, "pq") || strings.Contains(message, "connection") {
						t.Fatalf("an internal failure leaked: %v", message)
					}
				}
			}
		})
	}
}

// The session the server minted reaches the backend with a legacy call, and
// nothing else does: a value that is not one of the server's shape, and any
// value in the stateless revision, which has no sessions, are "".
func TestLegacySessionsPartitionCallsAndNothingElse(t *testing.T) {
	session := newSessionID()
	for name, test := range map[string]struct {
		request func() *http.Request
		want    string
	}{
		"a legacy call with a minted session": {func() *http.Request {
			r := legacy(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"helm_work_report","arguments":{}}}`, "2025-11-25")
			r.Header.Set("Mcp-Session-Id", session)
			return r
		}, session},
		"a legacy call with no session": {func() *http.Request {
			return legacy(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"helm_work_report","arguments":{}}}`, "2025-11-25")
		}, ""},
		"a legacy call with a session of another shape": {func() *http.Request {
			r := legacy(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"helm_work_report","arguments":{}}}`, "2025-11-25")
			r.Header.Set("Mcp-Session-Id", "x y")
			return r
		}, ""},
		"a stateless call that sends one anyway": {func() *http.Request {
			r := modern(1, "tools/call", map[string]any{"name": "helm_work_report", "arguments": map[string]any{}})
			r.Header.Set("Mcp-Session-Id", session)
			return r
		}, ""},
	} {
		t.Run(name, func(t *testing.T) {
			b := newFake()
			serve(t, newHandler(b), test.request()).result(t)
			if b.call.Session != test.want {
				t.Fatalf("the backend got session %q, want %q", b.call.Session, test.want)
			}
		})
	}
	if a, b := newSessionID(), newSessionID(); a == b || len(a) != 22 {
		t.Fatalf("session ids %q and %q are not fresh 22-character ids", a, b)
	}
}
