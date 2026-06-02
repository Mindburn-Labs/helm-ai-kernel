package telegram

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
	if a.Kind() != channels.ChannelTelegram {
		t.Fatalf("Kind() = %q", a.Kind())
	}

	env, err := a.NormalizeInbound(context.Background(), []byte(`{
		"update_id":123,
		"message":{
			"message_id":42,
			"from":{"id":111,"is_bot":false,"first_name":"Alice","username":"alice"},
			"chat":{"id":-1001,"type":"supergroup"},
			"date":1617235200,
			"text":"hello",
			"reply_to_message_id":41
		}
	}`))
	if err != nil {
		t.Fatalf("NormalizeInbound() error = %v", err)
	}
	if env.EnvelopeID == "" || env.Channel != channels.ChannelTelegram || env.MessageID != "42" {
		t.Fatalf("envelope identity fields = %#v", env)
	}
	if env.ThreadID != "41" || env.SenderID != "111" || env.SenderHandle != "alice" || env.Text != "hello" {
		t.Fatalf("envelope message fields = %#v", env)
	}
	if env.ReceivedAtUnixMs != 1617235200000 {
		t.Fatalf("ReceivedAtUnixMs = %d", env.ReceivedAtUnixMs)
	}
	if env.Metadata["telegram_chat_id"] != "-1001" || env.Metadata["telegram_update_id"] != "123" {
		t.Fatalf("metadata = %#v", env.Metadata)
	}
}

func TestNormalizeInboundFallbacksAndErrors(t *testing.T) {
	a := New("token")

	env, err := a.NormalizeInbound(context.Background(), []byte(`{
		"update_id":124,
		"message":{
			"message_id":43,
			"from":{"id":112,"first_name":"Bob"},
			"chat":{"id":1002,"type":"private"},
			"date":0,
			"text":"hello"
		}
	}`))
	if err != nil {
		t.Fatalf("NormalizeInbound() fallback error = %v", err)
	}
	if env.SenderHandle != "Bob" || env.ReceivedAtUnixMs <= 0 {
		t.Fatalf("fallback envelope = %#v", env)
	}

	tests := []struct {
		name string
		raw  string
		want string
	}{
		{"bad json", `{`, "unmarshal update"},
		{"missing message id", `{"message":{"from":{"id":111}}}`, "message_id is zero"},
		{"missing from id", `{"message":{"message_id":1}}`, "from.id is zero"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := a.NormalizeInbound(context.Background(), []byte(tt.raw))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("NormalizeInbound() error = %v, want %q", err, tt.want)
			}
		})
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
		{"empty tenant", "", "123", channels.OutboundMessage{Text: "hello"}, "token", "tenantID"},
		{"empty session", "tenant", "", channels.OutboundMessage{Text: "hello"}, "token", "sessionID"},
		{"empty content", "tenant", "123", channels.OutboundMessage{}, "token", "no content"},
		{"empty token", "tenant", "123", channels.OutboundMessage{Text: "hello"}, "", "bot token"},
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
		if r.URL.Path != "/bottoken/sendMessage" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		if payload["chat_id"] != "123" || payload["text"] != "1 attachment(s)" || payload["reply_to_message_id"] != float64(41) {
			t.Fatalf("payload = %#v", payload)
		}
		_, _ = fmt.Fprint(w, `{"ok":true}`)
	}))
	defer server.Close()

	a := New("token")
	a.apiBase = server.URL + "/"
	a.httpClient = nil
	err := a.Send(context.Background(), "tenant", "123", channels.OutboundMessage{
		ThreadID:    "41",
		Attachments: []string{"artifact-1"},
	})
	if err != nil {
		t.Fatalf("Send() success error = %v", err)
	}

	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"ok":false,"description":"rate limited"}`)
	}))
	defer server.Close()

	a = New("token")
	a.apiBase = server.URL
	a.httpClient = server.Client()
	err = a.Send(context.Background(), "tenant", "123", channels.OutboundMessage{Text: "hello"})
	if err == nil || !strings.Contains(err.Error(), "send message") {
		t.Fatalf("Send() postJSON wrapper error = %v", err)
	}
}

func TestPostJSONErrors(t *testing.T) {
	ctx := context.Background()
	a := New("token")

	if err := a.postJSON(ctx, "sendMessage", map[string]any{"bad": math.Inf(1)}); err == nil {
		t.Fatal("postJSON() marshal error = nil")
	}

	a = New("token")
	a.apiBase = "://bad-url"
	if err := a.postJSON(ctx, "sendMessage", map[string]any{"text": "hello"}); err == nil {
		t.Fatal("postJSON() request build error = nil")
	}

	a = New("token")
	a.httpClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("transport failed")
	})}
	if err := a.postJSON(ctx, "sendMessage", map[string]any{"text": "hello"}); err == nil || !strings.Contains(err.Error(), "transport failed") {
		t.Fatalf("postJSON() transport error = %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{`)
	}))
	a = New("token")
	a.apiBase = server.URL
	a.httpClient = server.Client()
	if err := a.postJSON(ctx, "sendMessage", map[string]any{"text": "hello"}); err == nil {
		t.Fatal("postJSON() decode error = nil")
	}
	server.Close()

	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = fmt.Fprint(w, `{"ok":false}`)
	}))
	a = New("token")
	a.apiBase = server.URL
	a.httpClient = server.Client()
	if err := a.postJSON(ctx, "sendMessage", map[string]any{"text": "hello"}); err == nil || !strings.Contains(err.Error(), "status 502") {
		t.Fatalf("postJSON() status error = %v", err)
	}
	server.Close()
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
