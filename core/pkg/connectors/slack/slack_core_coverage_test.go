package slack

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/effects"
)

func TestClientLocalSlackAPISuccess(t *testing.T) {
	ctx := context.Background()
	historyLimit := ""
	listCursors := make([]string, 0, 2)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer xoxb-test" {
			t.Fatalf("authorization header = %q", got)
		}
		if got := r.Header.Get("User-Agent"); got != userAgent {
			t.Fatalf("user agent = %q", got)
		}

		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/chat.postMessage":
			if r.Method != http.MethodPost {
				t.Fatalf("postMessage method = %s", r.Method)
			}
			_, _ = w.Write([]byte(`{"ok":true,"channel":"C123","ts":"1234567890.000001"}`))
		case "/conversations.history":
			if r.Method != http.MethodGet {
				t.Fatalf("history method = %s", r.Method)
			}
			historyLimit = r.URL.Query().Get("limit")
			_, _ = w.Write([]byte(`{"ok":true,"messages":[{"ts":"1234567890.123456789","user":"U123","text":"hello"}]}`))
		case "/conversations.list":
			if r.Method != http.MethodGet {
				t.Fatalf("list method = %s", r.Method)
			}
			cursor := r.URL.Query().Get("cursor")
			listCursors = append(listCursors, cursor)
			if cursor == "" {
				_, _ = w.Write([]byte(`{"ok":true,"channels":[{"id":"C1","name":"general","topic":{"value":"team"},"num_members":7}],"response_metadata":{"next_cursor":"next-page"}}`))
				return
			}
			_, _ = w.Write([]byte(`{"ok":true,"channels":[{"id":"C2","name":"ops","topic":{"value":"deploys"},"num_members":3}],"response_metadata":{"next_cursor":""}}`))
		case "/chat.update":
			if r.Method != http.MethodPost {
				t.Fatalf("update method = %s", r.Method)
			}
			_, _ = w.Write([]byte(`{"ok":true,"channel":"C123","ts":"1234567890.000001","text":"updated"}`))
		default:
			http.Error(w, "unknown method", http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := NewClient("xoxb-test")
	client.baseURL = server.URL
	client.httpClient = server.Client()

	sent, err := client.SendMessage(ctx, &SendMessageRequest{
		ChannelID: "C123",
		Text:      "hello",
		ThreadTS:  "1234567890.000000",
	})
	if err != nil {
		t.Fatalf("SendMessage: %v", err)
	}
	if sent.ChannelID != "C123" || sent.MessageTS == "" {
		t.Fatalf("unexpected send response: %+v", sent)
	}

	history, err := client.ReadChannel(ctx, "C123", 5000)
	if err != nil {
		t.Fatalf("ReadChannel: %v", err)
	}
	if historyLimit != "1000" {
		t.Fatalf("history limit = %q, want Slack clamp to 1000", historyLimit)
	}
	if len(history.Messages) != 1 || history.Messages[0].Timestamp.Nanosecond() != 123456000 {
		t.Fatalf("unexpected history response: %+v", history)
	}

	channels, err := client.ListChannels(ctx)
	if err != nil {
		t.Fatalf("ListChannels: %v", err)
	}
	if len(channels.Channels) != 2 || channels.Channels[1].Name != "ops" {
		t.Fatalf("unexpected channels: %+v", channels)
	}
	if len(listCursors) != 2 || listCursors[0] != "" || listCursors[1] != "next-page" {
		t.Fatalf("unexpected pagination cursors: %+v", listCursors)
	}

	updated, err := client.UpdateMessage(ctx, &UpdateMessageRequest{
		ChannelID: "C123",
		MessageTS: sent.MessageTS,
		Text:      "updated",
	})
	if err != nil {
		t.Fatalf("UpdateMessage: %v", err)
	}
	if updated.Text != "updated" || updated.MessageTS != sent.MessageTS {
		t.Fatalf("unexpected update response: %+v", updated)
	}
}

func TestClientValidationAndHelpers(t *testing.T) {
	ctx := context.Background()
	tokenless := NewClient("")
	if _, err := tokenless.ReadChannel(ctx, "C123", 1); err == nil || !strings.Contains(err.Error(), "not connected") {
		t.Fatalf("expected tokenless read error, got %v", err)
	}
	if _, err := tokenless.ListChannels(ctx); err == nil || !strings.Contains(err.Error(), "not connected") {
		t.Fatalf("expected tokenless list error, got %v", err)
	}
	if _, err := tokenless.UpdateMessage(ctx, &UpdateMessageRequest{ChannelID: "C", MessageTS: "1", Text: "x"}); err == nil || !strings.Contains(err.Error(), "not connected") {
		t.Fatalf("expected tokenless update error, got %v", err)
	}

	client := NewClient("xoxb-test")
	for name, req := range map[string]*SendMessageRequest{
		"nil":             nil,
		"missing channel": {Text: "x"},
		"missing text":    {ChannelID: "C123"},
	} {
		if _, err := client.SendMessage(ctx, req); err == nil {
			t.Fatalf("SendMessage %s: expected validation error", name)
		}
	}
	if _, err := client.ReadChannel(ctx, "", 1); err == nil || !strings.Contains(err.Error(), "channel_id required") {
		t.Fatalf("expected read channel validation error, got %v", err)
	}
	for name, req := range map[string]*UpdateMessageRequest{
		"nil":             nil,
		"missing ids":     {Text: "x"},
		"missing message": {ChannelID: "C123", Text: "x"},
		"missing text":    {ChannelID: "C123", MessageTS: "1"},
	} {
		if _, err := client.UpdateMessage(ctx, req); err == nil {
			t.Fatalf("UpdateMessage %s: expected validation error", name)
		}
	}

	if ts := parseSlackTS("not-a-ts"); !ts.IsZero() {
		t.Fatalf("bad timestamp parsed as %s", ts)
	}
	if ts := parseSlackTS("1234567890"); ts.IsZero() || ts.Nanosecond() != 0 {
		t.Fatalf("seconds-only timestamp parsed unexpectedly: %s", ts)
	}
	if backoff(1) != time.Second {
		t.Fatalf("backoff(1) = %s", backoff(1))
	}
	if !shouldRetry(0) || shouldRetry(maxRetries-1) {
		t.Fatalf("unexpected shouldRetry results")
	}
	if readerOrNil(nil) != nil {
		t.Fatal("readerOrNil(nil) returned reader")
	}
	if readerOrNil([]byte("x")) == nil {
		t.Fatal("readerOrNil(non-empty) returned nil")
	}

	resp := &http.Response{Header: make(http.Header)}
	resp.Header.Set("Retry-After", "2")
	if retryAfter(resp) != 2*time.Second {
		t.Fatalf("retryAfter valid header = %s", retryAfter(resp))
	}
	resp.Header.Set("Retry-After", "bad")
	if retryAfter(resp) != 5*time.Second {
		t.Fatalf("retryAfter invalid header = %s", retryAfter(resp))
	}

	if (*APIError)(nil).Error() != "" {
		t.Fatal("nil APIError should render as empty string")
	}
	if got := (&APIError{StatusCode: 200, ErrorCode: "invalid_auth"}).Error(); got != "slack api: 200: invalid_auth" {
		t.Fatalf("APIError string = %q", got)
	}
	if got := (&APIError{StatusCode: 200, ErrorCode: "missing_scope", Needed: "channels:read", Provided: "chat:write"}).Error(); !strings.Contains(got, "needed=\"channels:read\"") {
		t.Fatalf("scope APIError string = %q", got)
	}
}

func TestClientDoJSONErrorBranches(t *testing.T) {
	ctx := context.Background()
	client := NewClient("xoxb-test")

	if err := client.doJSON(ctx, http.MethodPost, "chat.postMessage", map[string]any{"bad": func() {}}, nil, nil); err == nil || !strings.Contains(err.Error(), "marshal request body") {
		t.Fatalf("expected marshal error, got %v", err)
	}

	badURLClient := NewClient("xoxb-test")
	badURLClient.baseURL = "http://[::1"
	if err := badURLClient.doJSON(ctx, http.MethodGet, "conversations.list", nil, nil, nil); err == nil || !strings.Contains(err.Error(), "build request") {
		t.Fatalf("expected build request error, got %v", err)
	}

	invalidJSON := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("{"))
	}))
	defer invalidJSON.Close()
	client.baseURL = invalidJSON.URL
	client.httpClient = invalidJSON.Client()
	if err := client.doJSON(ctx, http.MethodGet, "conversations.list", nil, nil, nil); err == nil || !strings.Contains(err.Error(), "decode response") {
		t.Fatalf("expected decode error, got %v", err)
	}

	missingScope := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":false,"error":"missing_scope","needed":"channels:read","provided":"chat:write"}`))
	}))
	defer missingScope.Close()
	client.baseURL = missingScope.URL
	client.httpClient = missingScope.Client()
	err := client.doJSON(ctx, http.MethodGet, "conversations.list", nil, url.Values{"limit": []string{"1"}}, nil)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Needed != "channels:read" {
		t.Fatalf("expected missing scope APIError, got %v", err)
	}

	successNoOut := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer successNoOut.Close()
	client.baseURL = successNoOut.URL
	client.httpClient = successNoOut.Client()
	if err := client.doJSON(ctx, http.MethodGet, "auth.test", nil, nil, nil); err != nil {
		t.Fatalf("success with nil out: %v", err)
	}

	serverError := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "temporary", http.StatusBadGateway)
	}))
	defer serverError.Close()
	client.baseURL = serverError.URL
	client.httpClient = serverError.Client()
	err = client.doJSON(ctx, http.MethodGet, "conversations.list", nil, nil, nil)
	if !errors.As(err, &apiErr) || apiErr.ErrorCode != "server_error" {
		t.Fatalf("expected server_error APIError, got %v", err)
	}
}

func TestConnectorExecuteSuccessWithLocalClient(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/chat.postMessage":
			_, _ = w.Write([]byte(`{"ok":true,"channel":"C123","ts":"1234567890.000001"}`))
		case "/conversations.history":
			_, _ = w.Write([]byte(`{"ok":true,"messages":[{"ts":"1234567890.000001","user":"U1","text":"hello"}]}`))
		case "/conversations.list":
			_, _ = w.Write([]byte(`{"ok":true,"channels":[{"id":"C123","name":"general","topic":{"value":"team"},"num_members":4}],"response_metadata":{"next_cursor":""}}`))
		case "/chat.update":
			_, _ = w.Write([]byte(`{"ok":true,"channel":"C123","ts":"1234567890.000001","text":"updated"}`))
		default:
			http.Error(w, "unknown", http.StatusNotFound)
		}
	}))
	defer server.Close()

	conn := NewConnector(Config{BotToken: "xoxb-test"})
	conn.client.baseURL = server.URL
	conn.client.httpClient = server.Client()

	ctx := context.Background()
	permit := &effects.EffectPermit{}

	sent, err := conn.Execute(ctx, permit, "slack.send_message", map[string]any{
		"channel_id": "C123",
		"text":       "hello",
		"thread_ts":  "1234567890.000000",
	})
	if err != nil {
		t.Fatalf("send execute: %v", err)
	}
	if sent.(*SendMessageResponse).MessageTS == "" {
		t.Fatalf("unexpected send result: %+v", sent)
	}

	read, err := conn.Execute(ctx, permit, "slack.read_channel", map[string]any{
		"channel_id": "C123",
		"limit":      int64(2),
	})
	if err != nil {
		t.Fatalf("read execute: %v", err)
	}
	if len(read.(*ReadChannelResponse).Messages) != 1 {
		t.Fatalf("unexpected read result: %+v", read)
	}

	listed, err := conn.Execute(ctx, permit, "slack.list_channels", map[string]any{})
	if err != nil {
		t.Fatalf("list execute: %v", err)
	}
	if len(listed.(*ListChannelsResponse).Channels) != 1 {
		t.Fatalf("unexpected list result: %+v", listed)
	}

	updated, err := conn.Execute(ctx, permit, "slack.update_message", map[string]any{
		"channel_id": "C123",
		"message_ts": "1234567890.000001",
		"text":       "updated",
	})
	if err != nil {
		t.Fatalf("update execute: %v", err)
	}
	if updated.(*UpdateMessageResponse).Text != "updated" {
		t.Fatalf("unexpected update result: %+v", updated)
	}

	if conn.Graph().Len() != 8 {
		t.Fatalf("graph len = %d, want 8 intent/effect nodes", conn.Graph().Len())
	}
	if intParam(map[string]any{"n": 2}, "n", 9) != 2 {
		t.Fatal("intParam int branch failed")
	}
	if intParam(map[string]any{"n": float64(3)}, "n", 9) != 3 {
		t.Fatal("intParam float64 branch failed")
	}
	if intParam(map[string]any{"n": "bad"}, "n", 9) != 9 {
		t.Fatal("intParam default branch failed")
	}
}

func TestConnectorGateAndMarshalBranches(t *testing.T) {
	ctx := context.Background()
	permit := &effects.EffectPermit{}

	denied := NewConnector(Config{BotToken: "xoxb-test"})
	denied.connectorID = "missing-policy"
	for _, tc := range []struct {
		name   string
		tool   string
		params map[string]any
	}{
		{"send", "slack.send_message", map[string]any{"channel_id": "C", "text": "x"}},
		{"read", "slack.read_channel", map[string]any{"channel_id": "C"}},
		{"list", "slack.list_channels", map[string]any{}},
		{"update", "slack.update_message", map[string]any{"channel_id": "C", "message_ts": "1", "text": "x"}},
	} {
		if _, err := denied.Execute(ctx, permit, tc.tool, tc.params); err == nil || !strings.Contains(err.Error(), "gate denied") {
			t.Fatalf("%s: expected gate denial, got %v", tc.name, err)
		}
	}

	for _, tc := range []struct {
		name   string
		tool   string
		params map[string]any
	}{
		{"send", "slack.send_message", map[string]any{"bad": func() {}, "channel_id": "C", "text": "x"}},
		{"read", "slack.read_channel", map[string]any{"bad": func() {}, "channel_id": "C"}},
		{"list", "slack.list_channels", map[string]any{"bad": func() {}}},
		{"update", "slack.update_message", map[string]any{"bad": func() {}, "channel_id": "C", "message_ts": "1", "text": "x"}},
	} {
		conn := NewConnector(Config{BotToken: "xoxb-test"})
		if _, err := conn.Execute(ctx, permit, tc.tool, tc.params); err == nil || !strings.Contains(err.Error(), "marshal intent") {
			t.Fatalf("%s: expected marshal intent error, got %v", tc.name, err)
		}
	}
}

type errorBody struct{}

func (errorBody) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
func (errorBody) Close() error             { return nil }
