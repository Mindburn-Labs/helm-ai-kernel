package channels

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

const (
	directionInbound  = "inbound"
	directionOutbound = "outbound"
)

// ChannelReceipt is an immutable record of a processed channel message.
// Receipts are generated for both inbound and outbound messages, providing an
// audit trail that links channel activity back to HELM sessions and tenants.
type ChannelReceipt struct {
	// ReceiptID is a unique identifier for this receipt.
	ReceiptID string `json:"receipt_id"`
	// EnvelopeID links back to the ChannelEnvelope for inbound receipts.
	// For outbound receipts this field holds a generated reference.
	EnvelopeID string `json:"envelope_id"`
	// Channel identifies the platform this receipt relates to.
	Channel ChannelKind `json:"channel"`
	// Direction is "inbound" or "outbound".
	Direction string `json:"direction"`
	// TenantID scopes the receipt to a HELM tenant.
	TenantID string `json:"tenant_id"`
	// SessionID identifies the HELM session this message belongs to.
	SessionID string `json:"session_id"`
	// ProcessedAtMs is the UTC timestamp in milliseconds when the receipt was generated.
	ProcessedAtMs int64 `json:"processed_at_unix_ms"`
	// ContentHash is the SHA-256 hex digest of the message content.
	ContentHash string `json:"content_hash"`
}

// NewInboundReceipt builds a ChannelReceipt from a processed inbound ChannelEnvelope.
func NewInboundReceipt(env ChannelEnvelope) *ChannelReceipt {
	return &ChannelReceipt{
		ReceiptID:     uuid.NewString(),
		EnvelopeID:    env.EnvelopeID,
		Channel:       env.Channel,
		Direction:     directionInbound,
		TenantID:      env.TenantID,
		SessionID:     env.SessionID,
		ProcessedAtMs: time.Now().UnixMilli(),
		ContentHash:   hashEnvelope(env),
	}
}

// NewOutboundReceipt builds a ChannelReceipt for a message sent via a channel adapter.
func NewOutboundReceipt(tenantID, sessionID string, channel ChannelKind, msg OutboundMessage) *ChannelReceipt {
	envelopeID := uuid.NewString()
	return &ChannelReceipt{
		ReceiptID:     uuid.NewString(),
		EnvelopeID:    envelopeID,
		Channel:       channel,
		Direction:     directionOutbound,
		TenantID:      tenantID,
		SessionID:     sessionID,
		ProcessedAtMs: time.Now().UnixMilli(),
		ContentHash:   hashOutbound(msg),
	}
}

// hashEnvelope returns a SHA-256 hex digest of the envelope's text and attachments.
func hashEnvelope(env ChannelEnvelope) string {
	payload := struct {
		Text        string                 `json:"text"`
		Attachments []ChannelAttachmentRef `json:"attachments,omitempty"`
	}{
		Text:        env.Text,
		Attachments: env.Attachments,
	}
	return jsonHash(payload)
}

// hashOutbound returns a SHA-256 hex digest of the outbound message content.
func hashOutbound(msg OutboundMessage) string {
	return jsonHash(msg)
}

// jsonHash marshals v to JSON and returns the SHA-256 hex digest.
// On marshal error it falls back to hashing the empty string — this
// is intentionally lenient so receipt generation never panics.
func jsonHash(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		b = []byte{}
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
