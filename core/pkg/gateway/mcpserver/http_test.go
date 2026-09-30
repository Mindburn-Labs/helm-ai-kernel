package mcpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/admission"
)

type protocolBackend struct {
	calls  int
	caller Caller
}

func (b *protocolBackend) Tools(context.Context, Caller) ([]Tool, error) {
	return []Tool{{Name: "helm_work_report", InputSchema: json.RawMessage(`{"type":"object"}`)}}, nil
}

func (b *protocolBackend) Call(_ context.Context, caller Caller, _ Call) (Result, error) {
	b.calls++
	b.caller = caller
	return Result{StructuredContent: map[string]any{"status": "escalated", "attempt_id": "attempt-1"}}, nil
}

func protocolCaller() Caller {
	return Caller{Caller: admission.Caller{TenantID: "tenant", WorkspaceID: "workspace", PrincipalID: "agt:seat"}, EpisodeID: "episode", WorkItemID: "work", OrganizationVersionID: "version"}
}

func protocolRequest(body string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "https://gateway.test/mcp", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	return r
}

func TestStreamableHTTPInitializationDiscoveryAndEscalation(t *testing.T) {
	backend := &protocolBackend{}
	h := &Handler{Backend: backend, Authenticate: func(context.Context, http.Header) (Caller, error) { return protocolCaller(), nil }}
	for _, body := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"native-client","version":"1"}}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"helm_work_report","arguments":{}}}`,
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, protocolRequest(body))
		if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "application/json" {
			t.Fatalf("response %d: %s", w.Code, w.Body.String())
		}
		var response struct {
			Result struct {
				ProtocolVersion string `json:"protocolVersion"`
				Tools           []Tool `json:"tools"`
				IsError         bool   `json:"isError"`
				Structured      struct {
					Status    string `json:"status"`
					AttemptID string `json:"attempt_id"`
				} `json:"structuredContent"`
				Content []struct{ Type, Text string } `json:"content"`
			} `json:"result"`
			Error json.RawMessage `json:"error"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || len(response.Error) > 0 {
			t.Fatalf("response invalid: %s (%v)", w.Body.String(), err)
		}
		if strings.Contains(body, "initialize") && response.Result.ProtocolVersion != "2025-11-25" {
			t.Fatal("protocol negotiation changed the supported requested version")
		}
		if strings.Contains(body, "tools/list") && (len(response.Result.Tools) != 1 || response.Result.Tools[0].Name != "helm_work_report") {
			t.Fatal("the permitted work tool is missing")
		}
		if strings.Contains(body, "tools/call") {
			if response.Result.IsError || response.Result.Structured.Status != "escalated" || response.Result.Structured.AttemptID != "attempt-1" {
				t.Fatalf("escalation became a tool error: %s", w.Body.String())
			}
			if len(response.Result.Content) != 1 || !json.Valid([]byte(response.Result.Content[0].Text)) {
				t.Fatal("structured result lacks the text fallback required by older clients")
			}
		}
	}
	if backend.calls != 1 || backend.caller.WorkItemID != "work" {
		t.Fatalf("backend calls=%d, identity=%+v", backend.calls, backend.caller)
	}
}

func TestTransportRefusesSmuggledIdentityAndAmbiguousJSON(t *testing.T) {
	backend := &protocolBackend{}
	h := &Handler{Backend: backend, Authenticate: func(context.Context, http.Header) (Caller, error) { return protocolCaller(), nil }}
	for name, body := range map[string]string{
		"body work binding": `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"helm_work_report","arguments":{},"work_ref":{"case_id":"foreign"}}}`,
		"duplicate method":  `{"jsonrpc":"2.0","id":1,"method":"ping","method":"tools/call","params":{"name":"helm_work_report","arguments":{}}}`,
		"escaped duplicate": `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"helm_work_report","arguments":{"x":1,"\u0078":2}}}`,
		"null id":           `{"jsonrpc":"2.0","id":null,"method":"tools/call","params":{"name":"helm_work_report","arguments":{}}}`,
		"second envelope":   `{"jsonrpc":"2.0","id":1,"method":"ping"} {"jsonrpc":"2.0","id":2,"method":"ping"}`,
	} {
		t.Run(name, func(t *testing.T) {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, protocolRequest(body))
			if !strings.Contains(w.Body.String(), `"error"`) {
				t.Fatalf("request accepted: %s", w.Body.String())
			}
		})
	}
	if backend.calls != 0 {
		t.Fatalf("refused requests reached the backend %d times", backend.calls)
	}
}

func TestTransportChecksOriginVersionAuthenticationAndBounds(t *testing.T) {
	for name, test := range map[string]struct {
		edit func(*http.Request)
		code int
	}{
		"foreign origin":      {func(r *http.Request) { r.Header.Set("Origin", "https://evil.test") }, http.StatusForbidden},
		"null origin":         {func(r *http.Request) { r.Header.Set("Origin", "null") }, http.StatusForbidden},
		"unsupported version": {func(r *http.Request) { r.Header.Set("MCP-Protocol-Version", "next") }, http.StatusBadRequest},
		"missing accept":      {func(r *http.Request) { r.Header.Del("Accept") }, http.StatusNotAcceptable},
	} {
		t.Run(name, func(t *testing.T) {
			authenticated := false
			h := &Handler{Backend: &protocolBackend{}, Authenticate: func(context.Context, http.Header) (Caller, error) { authenticated = true; return protocolCaller(), nil }}
			r := protocolRequest(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
			test.edit(r)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != test.code || authenticated {
				t.Fatalf("code=%d authenticated=%v", w.Code, authenticated)
			}
		})
	}
	count := 0
	h := &Handler{Backend: &protocolBackend{}, Authenticate: func(context.Context, http.Header) (Caller, error) { count++; return protocolCaller(), nil }}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, protocolRequest(strings.Repeat("x", MaxRequestBytes+1)))
	if w.Code != http.StatusRequestEntityTooLarge || count != 0 {
		t.Fatal("oversized input reached authentication")
	}
	h.Authenticate = func(context.Context, http.Header) (Caller, error) {
		return Caller{}, connect.NewError(connect.CodeUnauthenticated, nil)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, protocolRequest(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	if w.Code != http.StatusUnauthorized || w.Header().Get("WWW-Authenticate") != "Bearer" {
		t.Fatal("invalid credentials did not produce a bearer challenge")
	}
}

func TestNotificationsHaveNoResponseAndGETHasNoSSEStream(t *testing.T) {
	h := &Handler{Backend: &protocolBackend{}, Authenticate: func(context.Context, http.Header) (Caller, error) { return protocolCaller(), nil }}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, protocolRequest(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))
	if w.Code != http.StatusAccepted || w.Body.Len() != 0 {
		t.Fatal("notification emitted a JSON-RPC response")
	}
	r := httptest.NewRequest(http.MethodGet, "https://gateway.test/mcp", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatal("stateless transport unexpectedly advertised a server SSE stream")
	}
}
