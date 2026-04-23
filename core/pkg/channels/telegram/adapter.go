// Package telegram provides the inbound channel adapter for Telegram messaging.
//
// This adapter normalises raw Telegram Bot API Update payloads into
// channels.ChannelEnvelope values and sends outbound messages via Bot API.
package telegram

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/channels"
)

const telegramAPIBase = "https://api.telegram.org"

// Compile-time interface compliance check.
var _ channels.Adapter = (*Adapter)(nil)

// telegramFrom is the sender information embedded in a Telegram message.
type telegramFrom struct {
	ID        int64  `json:"id"`
	IsBot     bool   `json:"is_bot"`
	FirstName string `json:"first_name"`
	Username  string `json:"username,omitempty"`
}

// telegramChat holds the chat metadata.
type telegramChat struct {
	ID   int64  `json:"id"`
	Type string `json:"type"`
}

// telegramMessage is the subset of the Telegram Message object needed for normalisation.
type telegramMessage struct {
	MessageID        int          `json:"message_id"`
	From             telegramFrom `json:"from"`
	Chat             telegramChat `json:"chat"`
	Date             int64        `json:"date"`
	Text             string       `json:"text,omitempty"`
	ReplyToMessageID *int         `json:"reply_to_message_id,omitempty"`
}

// telegramUpdate is the subset of the Telegram Update object needed for normalisation.
type telegramUpdate struct {
	UpdateID int             `json:"update_id"`
	Message  telegramMessage `json:"message"`
}

// Adapter is the inbound/outbound channel adapter for Telegram.
type Adapter struct {
	token      string
	apiBase    string
	httpClient *http.Client
}

// New returns a new Telegram Adapter configured with the given bot token.
func New(token string) *Adapter {
	return &Adapter{
		token:      token,
		apiBase:    telegramAPIBase,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// Kind returns channels.ChannelTelegram.
func (a *Adapter) Kind() channels.ChannelKind {
	return channels.ChannelTelegram
}

// NormalizeInbound parses a raw Telegram Bot API Update payload into a ChannelEnvelope.
//
// Expected JSON structure (minimal):
//
//	{
//	  "update_id": 123456789,
//	  "message": {
//	    "message_id": 42,
//	    "from": { "id": 111111, "is_bot": false, "first_name": "Alice", "username": "alice" },
//	    "chat": { "id": -1001234567890, "type": "supergroup" },
//	    "date": 1617235200,
//	    "text": "Hello!"
//	  }
//	}
//
// The TenantID and SessionID fields of the returned envelope will be empty;
// callers must populate them before passing the envelope to the router.
func (a *Adapter) NormalizeInbound(_ context.Context, raw []byte) (channels.ChannelEnvelope, error) {
	var update telegramUpdate
	if err := json.Unmarshal(raw, &update); err != nil {
		return channels.ChannelEnvelope{}, fmt.Errorf("telegram/adapter: unmarshal update: %w", err)
	}

	msg := update.Message
	if msg.MessageID == 0 {
		return channels.ChannelEnvelope{}, fmt.Errorf("telegram/adapter: message_id is zero")
	}
	if msg.From.ID == 0 {
		return channels.ChannelEnvelope{}, fmt.Errorf("telegram/adapter: from.id is zero")
	}

	receivedAtMs := msg.Date * 1000
	if receivedAtMs <= 0 {
		receivedAtMs = time.Now().UnixMilli()
	}

	senderHandle := msg.From.Username
	if senderHandle == "" {
		senderHandle = msg.From.FirstName
	}

	threadID := ""
	if msg.ReplyToMessageID != nil {
		threadID = fmt.Sprintf("%d", *msg.ReplyToMessageID)
	}

	env := channels.ChannelEnvelope{
		EnvelopeID:       uuid.NewString(),
		Channel:          channels.ChannelTelegram,
		MessageID:        fmt.Sprintf("%d", msg.MessageID),
		ThreadID:         threadID,
		SenderID:         fmt.Sprintf("%d", msg.From.ID),
		SenderHandle:     senderHandle,
		SenderTrust:      channels.SenderTrustUnknown,
		ReceivedAtUnixMs: receivedAtMs,
		Text:             msg.Text,
		Metadata: map[string]string{
			"telegram_chat_id":   fmt.Sprintf("%d", msg.Chat.ID),
			"telegram_chat_type": msg.Chat.Type,
			"telegram_update_id": fmt.Sprintf("%d", update.UpdateID),
		},
	}

	return env, nil
}

// Send delivers an outbound message to the given session via Telegram.
// The sessionID is interpreted as the destination Telegram chat ID.
func (a *Adapter) Send(ctx context.Context, tenantID string, sessionID string, body channels.OutboundMessage) error {
	if tenantID == "" {
		return fmt.Errorf("telegram/adapter: tenantID must not be empty")
	}
	if sessionID == "" {
		return fmt.Errorf("telegram/adapter: sessionID must not be empty")
	}
	if body.Text == "" && len(body.Attachments) == 0 {
		return fmt.Errorf("telegram/adapter: outbound message has no content")
	}
	if a.token == "" {
		return fmt.Errorf("telegram/adapter: bot token is not configured")
	}

	text := body.Text
	if text == "" {
		text = fmt.Sprintf("%d attachment(s)", len(body.Attachments))
	}
	payload := map[string]any{
		"chat_id": sessionID,
		"text":    text,
	}
	if body.ThreadID != "" {
		if replyID, err := strconv.Atoi(body.ThreadID); err == nil {
			payload["reply_to_message_id"] = replyID
		}
	}
	if err := a.postJSON(ctx, "sendMessage", payload); err != nil {
		return fmt.Errorf("telegram/adapter: send message: %w", err)
	}
	return nil
}

// Health returns nil when the adapter is operational.
func (a *Adapter) Health(_ context.Context) error {
	if a.token == "" {
		return fmt.Errorf("telegram/adapter: bot token is not configured")
	}
	return nil
}

func (a *Adapter) postJSON(ctx context.Context, method string, payload map[string]any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	endpoint := fmt.Sprintf("%s/bot%s/%s", strings.TrimRight(a.apiBase, "/"), a.token, method)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(data))
	if err != nil {
		return err
	}
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
		OK          bool   `json:"ok"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || !raw.OK {
		if raw.Description == "" {
			raw.Description = fmt.Sprintf("telegram api returned status %d", resp.StatusCode)
		}
		return fmt.Errorf("%s", raw.Description)
	}
	return nil
}
