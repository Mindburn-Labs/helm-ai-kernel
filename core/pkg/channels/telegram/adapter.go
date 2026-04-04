// Package telegram provides the inbound channel adapter for Telegram messaging.
//
// This adapter normalises raw Telegram Bot API Update payloads into
// channels.ChannelEnvelope values and stubs outbound message delivery.
package telegram

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/channels"
)

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
	token string
}

// New returns a new Telegram Adapter configured with the given bot token.
func New(token string) *Adapter {
	return &Adapter{token: token}
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
// This is a stub implementation.
func (a *Adapter) Send(_ context.Context, tenantID string, sessionID string, body channels.OutboundMessage) error {
	if tenantID == "" {
		return fmt.Errorf("telegram/adapter: tenantID must not be empty")
	}
	if sessionID == "" {
		return fmt.Errorf("telegram/adapter: sessionID must not be empty")
	}
	if body.Text == "" && len(body.Attachments) == 0 {
		return fmt.Errorf("telegram/adapter: outbound message has no content")
	}
	// Stub: in a full implementation this would call the Telegram sendMessage API.
	return nil
}

// Health returns nil when the adapter is operational.
// This is a stub; a real implementation would call the Telegram getMe endpoint.
func (a *Adapter) Health(_ context.Context) error {
	if a.token == "" {
		return fmt.Errorf("telegram/adapter: bot token is not configured")
	}
	return nil
}
