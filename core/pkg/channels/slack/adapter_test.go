package slack

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
	if a.Kind() != channels.ChannelSlack {
		t.Fatalf("Kind() = %q", a.Kind())
	}

	env, err := a.NormalizeInbound(context.Background(), []byte(`{
		"type":"message",
		"user":"U123",
		"text":"hello",
		"channel":"C123",
		"ts":"1617235200.000001",
		"thread_ts":"1617235100.000001"
	}`))
	if err != nil {
		t.Fatalf("NormalizeInbound() error = %v", err)
	}
	if env.EnvelopeID == "" || env.Channel != channels.ChannelSlack || env.MessageID != "1617235200.000001" {
		t.Fatalf("envelope identity fields = %#v", env)
	}
	if env.ThreadID != "1617235100.000001" || env.SenderID != "U123" || env.Text != "hello" {
		t.Fatalf("envelope message fields = %#v", env)
	}
	if env.ReceivedAtUnixMs != 1617235200000 {
		t.Fatalf("ReceivedAtUnixMs = %d", env.ReceivedAtUnixMs)
	}
	if env.Metadata["slack_channel"] != "C123" || env.Metadata["slack_type"] != "message" {
		t.Fatalf("metadata = %#v", env.Metadata)
	}
}

func TestNormalizeInboundErrorsAndTimestampFallback(t *testing.T) {
	a := New("token")

	tests := []struct {
		name string
		raw  string
		want string
	}{
		{"bad json", `{`, "unmarshal event"},
		{"missing type", `{"user":"U","channel":"C","ts":"1"}`, "event type is empty"},
		{"missing user", `{"type":"message","channel":"C","ts":"1"}`, "event user is empty"},
		{"missing channel", `{"type":"message","user":"U","ts":"1"}`, "event channel is empty"},
		{"missing ts", `{"type":"message","user":"U","channel":"C"}`, "event ts is empty"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := a.NormalizeInbound(context.Background(), []byte(tt.raw))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("NormalizeInbound() error = %v, want %q", err, tt.want)
			}
		})
	}

	env, err := a.NormalizeInbound(context.Background(), []byte(`{"type":"message","user":"U","channel":"C","ts":"not-a-ts"}`))
	if err != nil {
		t.Fatalf("NormalizeInbound() fallback timestamp error = %v", err)
	}
	if env.ReceivedAtUnixMs <= 0 {
		t.Fatalf("ReceivedAtUnixMs = %d, want fallback timestamp", env.ReceivedAtUnixMs)
	}
	if tsToUnixMs("bad") != 0 {
		t.Fatal("tsToUnixMs() returned non-zero for invalid timestamp")
	}
}

func TestSendValidationHealthAndSuccess(t *testing.T) {
	if err := New("").Health(context.Background()); err == nil || !strings.Contains(err.Error(), "bot token") {
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
		{"empty tenant", "", "C123", channels.OutboundMessage{Text: "hello"}, "token", "tenantID"},
		{"empty session", "tenant", "", channels.OutboundMessage{Text: "hello"}, "token", "sessionID"},
		{"empty content", "tenant", "C123", channels.OutboundMessage{}, "token", "no content"},
		{"empty token", "tenant", "C123", channels.OutboundMessage{Text: "hello"}, "", "bot token"},
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
		if r.URL.Path != "/chat.postMessage" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer token" {
			t.Fatalf("Authorization = %q", r.Header.Get("Authorization"))
		}
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		if payload["channel"] != "C123" || payload["text"] != "1 attachment(s)" || payload["thread_ts"] != "thread-1" {
			t.Fatalf("payload = %#v", payload)
		}
		_, _ = fmt.Fprint(w, `{"ok":true}`)
	}))
	defer server.Close()

	a := New("token")
	a.apiBase = server.URL + "/"
	a.httpClient = nil
	err := a.Send(context.Background(), "tenant", "C123", channels.OutboundMessage{
		ThreadID:    "thread-1",
		Attachments: []string{"artifact-1"},
	})
	if err != nil {
		t.Fatalf("Send() success error = %v", err)
	}

	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"ok":false,"error":"rate_limited"}`)
	}))
	defer server.Close()

	a = New("token")
	a.apiBase = server.URL
	a.httpClient = server.Client()
	err = a.Send(context.Background(), "tenant", "C123", channels.OutboundMessage{Text: "hello"})
	if err == nil || !strings.Contains(err.Error(), "send message") {
		t.Fatalf("Send() postJSON wrapper error = %v", err)
	}
}

func TestPostJSONErrors(t *testing.T) {
	ctx := context.Background()
	a := New("token")

	if err := a.postJSON(ctx, "chat.postMessage", map[string]any{"bad": math.Inf(1)}); err == nil {
		t.Fatal("postJSON() marshal error = nil")
	}

	a = New("token")
	a.apiBase = "://bad-url"
	if err := a.postJSON(ctx, "chat.postMessage", map[string]any{"text": "hello"}); err == nil {
		t.Fatal("postJSON() request build error = nil")
	}

	a = New("token")
	a.httpClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("transport failed")
	})}
	if err := a.postJSON(ctx, "chat.postMessage", map[string]any{"text": "hello"}); err == nil || !strings.Contains(err.Error(), "transport failed") {
		t.Fatalf("postJSON() transport error = %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{`)
	}))
	a = New("token")
	a.apiBase = server.URL
	a.httpClient = server.Client()
	if err := a.postJSON(ctx, "chat.postMessage", map[string]any{"text": "hello"}); err == nil {
		t.Fatal("postJSON() decode error = nil")
	}
	server.Close()

	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = fmt.Fprint(w, `{"ok":false,"error":"bad_gateway"}`)
	}))
	a = New("token")
	a.apiBase = server.URL
	a.httpClient = server.Client()
	if err := a.postJSON(ctx, "chat.postMessage", map[string]any{"text": "hello"}); err == nil || !strings.Contains(err.Error(), "http 502") {
		t.Fatalf("postJSON() status error = %v", err)
	}
	server.Close()

	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"ok":false}`)
	}))
	a = New("token")
	a.apiBase = server.URL
	a.httpClient = server.Client()
	if err := a.postJSON(ctx, "chat.postMessage", map[string]any{"text": "hello"}); err == nil || !strings.Contains(err.Error(), "ok=false") {
		t.Fatalf("postJSON() ok=false error = %v", err)
	}
	server.Close()
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
