// Package slack provides the inbound channel adapter for Slack messaging.
//
// This adapter is responsible for normalising raw Slack event payloads into
// channels.ChannelEnvelope values and for sending outbound messages back
// to Slack users. It is distinct from core/pkg/connectors/slack/ which
// provides the governed outbound effect connector.
package slack

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

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/channels"
)

// Compile-time interface compliance check.
var _ channels.Adapter = (*Adapter)(nil)

// slackEventPayload is the subset of the Slack Events API JSON structure that
// this adapter needs to normalise an inbound message.
type slackEventPayload struct {
	Type     string `json:"type"`
	User     string `json:"user"`
	Text     string `json:"text"`
	Channel  string `json:"channel"`
	TS       string `json:"ts"`
	ThreadTS string `json:"thread_ts,omitempty"`
}

const slackAPIBase = "https://slack.com/api"

// Adapter is the inbound/outbound channel adapter for Slack.
type Adapter struct {
	token      string
	apiBase    string
	httpClient *http.Client
}

// New returns a new Slack Adapter configured with the given bot token.
func New(token string) *Adapter {
	return &Adapter{
		token:      token,
		apiBase:    slackAPIBase,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
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
// The sessionID is interpreted as the destination Slack channel ID.
func (a *Adapter) Send(ctx context.Context, tenantID string, sessionID string, body channels.OutboundMessage) error {
	if tenantID == "" {
		return fmt.Errorf("slack/adapter: tenantID must not be empty")
	}
	if sessionID == "" {
		return fmt.Errorf("slack/adapter: sessionID must not be empty")
	}
	if body.Text == "" && len(body.Attachments) == 0 {
		return fmt.Errorf("slack/adapter: outbound message has no content")
	}
	if a.token == "" {
		return fmt.Errorf("slack/adapter: bot token is not configured")
	}

	text := body.Text
	if text == "" {
		text = fmt.Sprintf("%d attachment(s)", len(body.Attachments))
	}
	payload := map[string]any{
		"channel": sessionID,
		"text":    text,
	}
	if body.ThreadID != "" {
		payload["thread_ts"] = body.ThreadID
	}
	if err := a.postJSON(ctx, "chat.postMessage", payload); err != nil {
		return fmt.Errorf("slack/adapter: send message: %w", err)
	}
	return nil
}

// Health returns nil when the adapter is operational.
func (a *Adapter) Health(_ context.Context) error {
	if a.token == "" {
		return fmt.Errorf("slack/adapter: bot token is not configured")
	}
	return nil
}

func (a *Adapter) postJSON(ctx context.Context, method string, payload map[string]any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(a.apiBase, "/")+"/"+method, bytes.NewReader(data))
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
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("http %d: %s", resp.StatusCode, raw.Error)
	}
	if !raw.OK {
		if raw.Error == "" {
			raw.Error = "slack api returned ok=false"
		}
		return fmt.Errorf("%s", raw.Error)
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
