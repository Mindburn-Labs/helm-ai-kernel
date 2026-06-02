package lark

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/channels"
)

func TestNewKindAndNormalizeInbound(t *testing.T) {
	a := New("token")
	if a.Kind() != channels.ChannelLark {
		t.Fatalf("Kind() = %q", a.Kind())
	}

	env, err := a.NormalizeInbound(context.Background(), []byte(`{
		"schema":"2.0",
		"event":{
			"sender":{
				"sender_id":{"open_id":"ou_1","union_id":"on_1","user_id":"user_1"},
				"sender_type":"user",
				"tenant_key":"tenant_key"
			},
			"message":{
				"message_id":"om_1",
				"create_time":"1617235200000",
				"chat_id":"oc_1",
				"chat_type":"p2p",
				"message_type":"text",
				"content":"{\"text\":\"hello\"}",
				"parent_id":"parent_1"
			}
		}
	}`))
	if err != nil {
		t.Fatalf("NormalizeInbound() error = %v", err)
	}
	if env.EnvelopeID == "" || env.Channel != channels.ChannelLark || env.MessageID != "om_1" {
		t.Fatalf("envelope identity fields = %#v", env)
	}
	if env.ThreadID != "parent_1" || env.SenderID != "ou_1" || env.SenderHandle != "user_1" || env.Text != "hello" {
		t.Fatalf("envelope message fields = %#v", env)
	}
	if env.ReceivedAtUnixMs != 1617235200000 {
		t.Fatalf("ReceivedAtUnixMs = %d", env.ReceivedAtUnixMs)
	}
	if env.Metadata["lark_chat_id"] != "oc_1" || env.Metadata["lark_tenant_key"] != "tenant_key" {
		t.Fatalf("metadata = %#v", env.Metadata)
	}
}

func TestNormalizeInboundFallbacksAndErrors(t *testing.T) {
	a := New("token")

	env, err := a.NormalizeInbound(context.Background(), []byte(`{
		"event":{
			"sender":{"sender_id":{"union_id":"on_fallback","user_id":"user_fallback"}},
			"message":{
				"message_id":"om_body",
				"create_time":"bad",
				"chat_id":"oc_body",
				"chat_type":"group",
				"message_type":"text",
				"body":{"content":"{\"text\":\"from body\"}"}
			}
		}
	}`))
	if err != nil {
		t.Fatalf("NormalizeInbound() fallback error = %v", err)
	}
	if env.SenderID != "on_fallback" || env.Text != "from body" || env.ReceivedAtUnixMs <= 0 {
		t.Fatalf("fallback envelope = %#v", env)
	}

	tests := []struct {
		name string
		raw  string
		want string
	}{
		{"bad json", `{`, "unmarshal callback"},
		{"missing message id", `{"event":{"sender":{"sender_id":{"open_id":"ou"}},"message":{}}}`, "message.message_id"},
		{"missing sender ids", `{"event":{"sender":{"sender_id":{}},"message":{"message_id":"om"}}}`, "both empty"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := a.NormalizeInbound(context.Background(), []byte(tt.raw))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("NormalizeInbound() error = %v, want %q", err, tt.want)
			}
		})
	}

	if parseCreateTimeMs("") != 0 || parseCreateTimeMs("bad") != 0 || parseCreateTimeMs("123") != 123 {
		t.Fatal("parseCreateTimeMs() did not handle empty, invalid, and valid inputs")
	}
	if extractLarkText("") != "" || extractLarkText("plain") != "plain" || extractLarkText(`{"text":"json"}`) != "json" {
		t.Fatal("extractLarkText() did not handle empty, raw, and JSON inputs")
	}
}

func TestSendValidationHealthAndSuccess(t *testing.T) {
	if err := New("").Health(context.Background()); err == nil || !strings.Contains(err.Error(), "access token") {
		t.Fatalf("Health() with empty token error = %v", err)
	}
	if err := New("token").Health(context.Background()); err != nil {
		t.Fatalf("Health() error = %v", err)
	}

	tests := []struct {
		name      string
		tenantID  string
		sessionID string
		body      channels.OutboundMessage
		token     string
		want      string
	}{
		{"empty tenant", "", "oc_1", channels.OutboundMessage{Text: "hello"}, "token", "tenantID"},
		{"empty session", "tenant", "", channels.OutboundMessage{Text: "hello"}, "token", "sessionID"},
		{"empty content", "tenant", "oc_1", channels.OutboundMessage{}, "token", "no content"},
		{"empty token", "tenant", "oc_1", channels.OutboundMessage{Text: "hello"}, "", "access token"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := New(tt.token).Send(context.Background(), tt.tenantID, tt.sessionID, tt.body)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Send() error = %v, want %q", err, tt.want)
			}
		})
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/im/v1/messages" || r.URL.Query().Get("receive_id_type") != "chat_id" {
			t.Fatalf("request URL = %s", r.URL.String())
		}
		if r.Header.Get("Authorization") != "Bearer token" {
			t.Fatalf("Authorization = %q", r.Header.Get("Authorization"))
		}
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		if payload["receive_id"] != "oc_1" || payload["msg_type"] != "text" || !strings.Contains(payload["content"].(string), "1 attachment(s)") {
			t.Fatalf("payload = %#v", payload)
		}
		_, _ = fmt.Fprint(w, `{"code":0}`)
	}))
	defer server.Close()

	a := New("token")
	a.apiBase = server.URL + "/"
	a.httpClient = nil
	err := a.Send(context.Background(), "tenant", "oc_1", channels.OutboundMessage{Attachments: []string{"artifact-1"}})
	if err != nil {
		t.Fatalf("Send() success error = %v", err)
	}

	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"code":999,"msg":"rate limited"}`)
	}))
	defer server.Close()

	a = New("token")
	a.apiBase = server.URL
	a.httpClient = server.Client()
	err = a.Send(context.Background(), "tenant", "oc_1", channels.OutboundMessage{Text: "hello"})
	if err == nil || !strings.Contains(err.Error(), "send message") {
		t.Fatalf("Send() postJSON wrapper error = %v", err)
	}
}

func TestPostJSONErrors(t *testing.T) {
	ctx := context.Background()
	a := New("token")

	if err := a.postJSON(ctx, "im/v1/messages", map[string]any{"bad": math.Inf(1)}); err == nil {
		t.Fatal("postJSON() marshal error = nil")
	}

	a = New("token")
	a.apiBase = "://bad-url"
	if err := a.postJSON(ctx, "im/v1/messages", map[string]any{"text": "hello"}); err == nil {
		t.Fatal("postJSON() request build error = nil")
	}

	a = New("token")
	a.httpClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("transport failed")
	})}
	if err := a.postJSON(ctx, "im/v1/messages", map[string]any{"text": "hello"}); err == nil || !strings.Contains(err.Error(), "transport failed") {
		t.Fatalf("postJSON() transport error = %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{`)
	}))
	a = New("token")
	a.apiBase = server.URL
	a.httpClient = server.Client()
	if err := a.postJSON(ctx, "im/v1/messages", map[string]any{"text": "hello"}); err == nil {
		t.Fatal("postJSON() decode error = nil")
	}
	server.Close()

	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = fmt.Fprint(w, `{"code":12}`)
	}))
	a = New("token")
	a.apiBase = server.URL
	a.httpClient = server.Client()
	if err := a.postJSON(ctx, "im/v1/messages", map[string]any{"text": "hello"}); err == nil || !strings.Contains(err.Error(), "status 502 code 12") {
		t.Fatalf("postJSON() status error = %v", err)
	}
	server.Close()
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
