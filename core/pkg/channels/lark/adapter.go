// Package lark provides the inbound channel adapter for Lark (Feishu) messaging.
//
// This adapter normalises raw Lark Event Callback v2.0 payloads into
// channels.ChannelEnvelope values and sends outbound messages via Lark OpenAPI.
package lark

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/channels"
)

const larkAPIBase = "https://open.larksuite.com/open-apis"

// Compile-time interface compliance check.
var _ channels.Adapter = (*Adapter)(nil)

// larkSender holds sender information from a Lark message event.
type larkSender struct {
	SenderID   larkSenderID `json:"sender_id"`
	SenderType string       `json:"sender_type"`
	TenantKey  string       `json:"tenant_key"`
}

// larkSenderID holds the various ID representations for a Lark user.
type larkSenderID struct {
	OpenID  string `json:"open_id"`
	UnionID string `json:"union_id"`
	UserID  string `json:"user_id"`
}

// larkMessageBody holds the message content.
type larkMessageBody struct {
	Content string `json:"content"`
}

// larkMessage holds the message metadata.
type larkMessage struct {
	MessageID   string          `json:"message_id"`
	CreateTime  string          `json:"create_time"` // Unix ms as string
	ChatID      string          `json:"chat_id"`
	ChatType    string          `json:"chat_type"`
	MessageType string          `json:"message_type"`
	Content     string          `json:"content"`
	Body        larkMessageBody `json:"body,omitempty"`
	ParentID    string          `json:"parent_id,omitempty"`
}

// larkEventBody is the inner event payload for receive_message events.
type larkEventBody struct {
	Sender  larkSender  `json:"sender"`
	Message larkMessage `json:"message"`
}

// larkEventCallback is the top-level Lark Event Callback v2.0 structure.
type larkEventCallback struct {
	Schema string        `json:"schema"`
	Event  larkEventBody `json:"event"`
}

// Adapter is the inbound/outbound channel adapter for Lark.
type Adapter struct {
	token      string
	apiBase    string
	httpClient *http.Client
}

// New returns a new Lark Adapter configured with a tenant access token.
func New(token string) *Adapter {
	return &Adapter{
		token:      token,
		apiBase:    larkAPIBase,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// Kind returns channels.ChannelLark.
func (a *Adapter) Kind() channels.ChannelKind {
	return channels.ChannelLark
}

// NormalizeInbound parses a raw Lark Event Callback v2.0 payload into a ChannelEnvelope.
//
// Expected JSON structure (minimal receive_message event):
//
//	{
//	  "schema": "2.0",
//	  "event": {
//	    "sender": {
//	      "sender_id": { "open_id": "ou_xxx", "union_id": "on_xxx", "user_id": "xxx" },
//	      "sender_type": "user",
//	      "tenant_key": "xxx"
//	    },
//	    "message": {
//	      "message_id": "om_xxx",
//	      "create_time": "1617235200000",
//	      "chat_id": "oc_xxx",
//	      "chat_type": "p2p",
//	      "message_type": "text",
//	      "content": "{\"text\":\"Hello!\"}",
//	      "parent_id": ""
//	    }
//	  }
//	}
//
// The TenantID and SessionID fields of the returned envelope will be empty;
// callers must populate them before passing the envelope to the router.
func (a *Adapter) NormalizeInbound(_ context.Context, raw []byte) (channels.ChannelEnvelope, error) {
	var cb larkEventCallback
	if err := json.Unmarshal(raw, &cb); err != nil {
		return channels.ChannelEnvelope{}, fmt.Errorf("lark/adapter: unmarshal callback: %w", err)
	}

	msg := cb.Event.Message
	sender := cb.Event.Sender

	if msg.MessageID == "" {
		return channels.ChannelEnvelope{}, fmt.Errorf("lark/adapter: message.message_id is empty")
	}

	senderID := sender.SenderID.OpenID
	if senderID == "" {
		senderID = sender.SenderID.UnionID
	}
	if senderID == "" {
		return channels.ChannelEnvelope{}, fmt.Errorf("lark/adapter: sender open_id and union_id are both empty")
	}

	receivedAtMs := parseCreateTimeMs(msg.CreateTime)
	if receivedAtMs <= 0 {
		receivedAtMs = time.Now().UnixMilli()
	}

	text := extractLarkText(msg.Content)
	if text == "" {
		text = extractLarkText(msg.Body.Content)
	}

	env := channels.ChannelEnvelope{
		EnvelopeID:       uuid.NewString(),
		Channel:          channels.ChannelLark,
		MessageID:        msg.MessageID,
		ThreadID:         msg.ParentID,
		SenderID:         senderID,
		SenderHandle:     sender.SenderID.UserID,
		SenderTrust:      channels.SenderTrustUnknown,
		ReceivedAtUnixMs: receivedAtMs,
		Text:             text,
		Metadata: map[string]string{
			"lark_chat_id":      msg.ChatID,
			"lark_chat_type":    msg.ChatType,
			"lark_message_type": msg.MessageType,
			"lark_tenant_key":   sender.TenantKey,
		},
	}

	return env, nil
}

// Send delivers an outbound message to the given session via Lark.
// The sessionID is interpreted as the destination Lark chat ID.
func (a *Adapter) Send(ctx context.Context, tenantID string, sessionID string, body channels.OutboundMessage) error {
	if tenantID == "" {
		return fmt.Errorf("lark/adapter: tenantID must not be empty")
	}
	if sessionID == "" {
		return fmt.Errorf("lark/adapter: sessionID must not be empty")
	}
	if body.Text == "" && len(body.Attachments) == 0 {
		return fmt.Errorf("lark/adapter: outbound message has no content")
	}
	if a.token == "" {
		return fmt.Errorf("lark/adapter: tenant access token is not configured")
	}

	text := body.Text
	if text == "" {
		text = fmt.Sprintf("%d attachment(s)", len(body.Attachments))
	}
	content, err := json.Marshal(map[string]string{"text": text})
	if err != nil {
		return err
	}
	payload := map[string]any{
		"receive_id": sessionID,
		"msg_type":   "text",
		"content":    string(content),
	}
	if err := a.postJSON(ctx, "im/v1/messages?receive_id_type=chat_id", payload); err != nil {
		return fmt.Errorf("lark/adapter: send message: %w", err)
	}
	return nil
}

// Health returns nil when the adapter is operational.
func (a *Adapter) Health(_ context.Context) error {
	if a.token == "" {
		return fmt.Errorf("lark/adapter: tenant access token is not configured")
	}
	return nil
}

func (a *Adapter) postJSON(ctx context.Context, path string, payload map[string]any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(a.apiBase, "/")+"/"+path, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+a.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	client := a.httpClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	var raw struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || raw.Code != 0 {
		if raw.Msg == "" {
			raw.Msg = fmt.Sprintf("lark api returned status %d code %d", resp.StatusCode, raw.Code)
		}
		return fmt.Errorf("%s", raw.Msg)
	}
	return nil
}

// parseCreateTimeMs parses a Lark create_time string (Unix milliseconds) into int64.
// Returns 0 on any parse failure.
func parseCreateTimeMs(s string) int64 {
	if s == "" {
		return 0
	}
	var ms int64
	_, err := fmt.Sscanf(s, "%d", &ms)
	if err != nil {
		return 0
	}
	return ms
}

// extractLarkText extracts the plain text from a Lark content JSON string.
// Lark text messages encode content as: {"text":"message body"}.
func extractLarkText(content string) string {
	if content == "" {
		return ""
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(content), &m); err != nil {
		// If it is not valid JSON return the raw content string.
		return content
	}
	return m["text"]
}
