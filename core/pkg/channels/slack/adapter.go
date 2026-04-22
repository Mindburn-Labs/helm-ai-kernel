// Package slack provides the inbound channel adapter for Slack messaging.
//
// This adapter is responsible for normalising raw Slack event payloads into
// channels.ChannelEnvelope values and for sending outbound messages back
// to Slack users. It is distinct from core/pkg/connectors/slack/ which
// provides the governed outbound effect connector.
package slack

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/channels"
)

// Compile-time interface compliance check.
var _ channels.Adapter = (*Adapter)(nil)

// slackEventPayload is the subset of the Slack Events API JSON structure that
// this adapter needs to normalise an inbound message.
type slackEventPayload struct {
	Type    string `json:"type"`
	User    string `json:"user"`
	Text    string `json:"text"`
	Channel string `json:"channel"`
	TS      string `json:"ts"`
	ThreadTS string `json:"thread_ts,omitempty"`
}

// Adapter is the inbound/outbound channel adapter for Slack.
// In its current form it is a foundational implementation: it parses the Slack
// Events API wire format but does not make real API calls for outbound messages.
type Adapter struct {
	token string
}

// New returns a new Slack Adapter configured with the given bot token.
func New(token string) *Adapter {
	return &Adapter{token: token}
}

// Kind returns channels.ChannelSlack.
func (a *Adapter) Kind() channels.ChannelKind {
	return channels.ChannelSlack
}

// NormalizeInbound parses a raw Slack Events API payload into a ChannelEnvelope.
//
// Expected JSON structure (minimal):
//
//	{
//	  "type":       "message",
//	  "user":       "U01ABCDEF",
//	  "text":       "Hello!",
//	  "channel":    "C01ABCDEF",
//	  "ts":         "1617235200.000001",
//	  "thread_ts":  "1617235100.000001"  // optional
//	}
//
// The TenantID and SessionID fields of the returned envelope will be empty;
// callers must populate them before passing the envelope to the router.
func (a *Adapter) NormalizeInbound(_ context.Context, raw []byte) (channels.ChannelEnvelope, error) {
	var evt slackEventPayload
	if err := json.Unmarshal(raw, &evt); err != nil {
		return channels.ChannelEnvelope{}, fmt.Errorf("slack/adapter: unmarshal event: %w", err)
	}

	if evt.Type == "" {
		return channels.ChannelEnvelope{}, fmt.Errorf("slack/adapter: event type is empty")
	}
	if evt.User == "" {
		return channels.ChannelEnvelope{}, fmt.Errorf("slack/adapter: event user is empty")
	}
	if evt.Channel == "" {
		return channels.ChannelEnvelope{}, fmt.Errorf("slack/adapter: event channel is empty")
	}
	if evt.TS == "" {
		return channels.ChannelEnvelope{}, fmt.Errorf("slack/adapter: event ts is empty")
	}

	receivedAtMs := tsToUnixMs(evt.TS)
	if receivedAtMs <= 0 {
		receivedAtMs = time.Now().UnixMilli()
	}

	env := channels.ChannelEnvelope{
		EnvelopeID:       uuid.NewString(),
		Channel:          channels.ChannelSlack,
		MessageID:        evt.TS,
		SenderID:         evt.User,
		SenderHandle:     evt.User,
		SenderTrust:      channels.SenderTrustUnknown,
		ReceivedAtUnixMs: receivedAtMs,
		Text:             evt.Text,
		Metadata: map[string]string{
			"slack_channel": evt.Channel,
			"slack_ts":      evt.TS,
			"slack_type":    evt.Type,
		},
	}

	if evt.ThreadTS != "" {
		env.ThreadID = evt.ThreadTS
	}

	return env, nil
}

// Send delivers an outbound message to the given tenant session via Slack.
// This is a stub implementation; production callers should replace it with a real
// Slack Web API client (e.g. via the governed connectors/slack connector).
func (a *Adapter) Send(_ context.Context, tenantID string, sessionID string, body channels.OutboundMessage) error {
	if tenantID == "" {
		return fmt.Errorf("slack/adapter: tenantID must not be empty")
	}
	if sessionID == "" {
		return fmt.Errorf("slack/adapter: sessionID must not be empty")
	}
	if body.Text == "" && len(body.Attachments) == 0 {
		return fmt.Errorf("slack/adapter: outbound message has no content")
	}
	// Stub: in a full implementation this would call the Slack chat.postMessage API.
	return nil
}

// Health returns nil when the adapter is operational.
// This is a stub; a real implementation would verify token validity via the Slack API.
func (a *Adapter) Health(_ context.Context) error {
	if a.token == "" {
		return fmt.Errorf("slack/adapter: bot token is not configured")
	}
	return nil
}

// tsToUnixMs converts a Slack timestamp string ("1617235200.000001") to a Unix millisecond value.
// It returns 0 on any parse failure.
func tsToUnixMs(ts string) int64 {
	parts := strings.SplitN(ts, ".", 2)
	if len(parts) == 0 {
		return 0
	}
	secs, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return 0
	}
	return secs * 1000
}
