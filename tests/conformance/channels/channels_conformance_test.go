package channels_conformance

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/channels"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/channels/lark"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/channels/slack"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/channels/telegram"
)

// nowMs returns the current time as Unix milliseconds.
func nowMs() int64 { return time.Now().UnixMilli() }

// validEnvelope builds a ChannelEnvelope that passes ValidateEnvelope.
func validEnvelope(channel channels.ChannelKind) channels.ChannelEnvelope {
	return channels.ChannelEnvelope{
		EnvelopeID:       "env-conformance-001",
		Channel:          channel,
		TenantID:         "tenant-conformance",
		SessionID:        "session-conformance",
		MessageID:        "msg-conformance-001",
		SenderID:         "sender-conformance-001",
		SenderTrust:      channels.SenderTrustUnknown,
		ReceivedAtUnixMs: nowMs(),
		Text:             "Hello from conformance test",
	}
}

// TestChannelConformance_SlackAdapterNormalizesInbound verifies Slack normalisation.
func TestChannelConformance_SlackAdapterNormalizesInbound(t *testing.T) {
	adapter := slack.New("xoxb-conformance-token")

	payload := map[string]interface{}{
		"type":    "message",
		"user":    "U01CONFORMANCE",
		"text":    "Hello from Slack",
		"channel": "C01CONFORMANCE",
		"ts":      "1617235200.000001",
	}
	raw, err := json.Marshal(payload)
	require.NoError(t, err)

	t.Run("normalise_returns_slack_envelope", func(t *testing.T) {
		env, err := adapter.NormalizeInbound(context.Background(), raw)
		require.NoError(t, err)
		assert.Equal(t, channels.ChannelSlack, env.Channel)
		assert.Equal(t, "U01CONFORMANCE", env.SenderID)
		assert.Equal(t, "Hello from Slack", env.Text)
	})
}

// TestChannelConformance_EnvelopeRequiredFields verifies that all required fields are populated.
func TestChannelConformance_EnvelopeRequiredFields(t *testing.T) {
	adapter := slack.New("xoxb-conformance-token")

	payload := map[string]interface{}{
		"type":    "message",
		"user":    "U01REQFIELDS",
		"text":    "Required fields test",
		"channel": "C01REQFIELDS",
		"ts":      "1617235200.000001",
	}
	raw, err := json.Marshal(payload)
	require.NoError(t, err)

	env, err := adapter.NormalizeInbound(context.Background(), raw)
	require.NoError(t, err)

	t.Run("envelope_id_is_set", func(t *testing.T) {
		assert.NotEmpty(t, env.EnvelopeID)
	})
	t.Run("channel_is_set", func(t *testing.T) {
		assert.Equal(t, channels.ChannelSlack, env.Channel)
	})
	t.Run("sender_id_is_set", func(t *testing.T) {
		assert.NotEmpty(t, env.SenderID)
	})
	t.Run("message_id_is_set", func(t *testing.T) {
		assert.NotEmpty(t, env.MessageID)
	})
	t.Run("received_at_unix_ms_is_positive", func(t *testing.T) {
		assert.Greater(t, env.ReceivedAtUnixMs, int64(0))
	})
}

// TestChannelConformance_AntiSpoofCatchesMissingSender verifies that missing sender_id fails.
func TestChannelConformance_AntiSpoofCatchesMissingSender(t *testing.T) {
	validator := channels.NewAntiSpoofValidator()
	env := validEnvelope(channels.ChannelSlack)
	env.SenderID = "" // deliberately blank

	t.Run("missing_sender_id_fails_anti_spoof", func(t *testing.T) {
		result, err := validator.Validate(context.Background(), env)
		require.NoError(t, err) // Validate itself must not error
		assert.False(t, result.Passed)
		assert.Equal(t, channels.SenderTrustSuspicious, result.SenderTrust)
		assert.NotEmpty(t, result.Reason)
	})
}

// TestChannelConformance_AntiSpoofCatchesFutureTimestamp verifies that future timestamps fail.
func TestChannelConformance_AntiSpoofCatchesFutureTimestamp(t *testing.T) {
	validator := channels.NewAntiSpoofValidator()
	env := validEnvelope(channels.ChannelSlack)
	// Set timestamp far in the future (10 minutes ahead) — well beyond the 1 s tolerance.
	env.ReceivedAtUnixMs = time.Now().Add(10 * time.Minute).UnixMilli()

	t.Run("future_timestamp_fails_anti_spoof", func(t *testing.T) {
		result, err := validator.Validate(context.Background(), env)
		require.NoError(t, err)
		assert.False(t, result.Passed)
		assert.Equal(t, channels.SenderTrustSuspicious, result.SenderTrust)
	})
}

// TestChannelConformance_RouterCreatesSessionOnFirstContact verifies session creation.
func TestChannelConformance_RouterCreatesSessionOnFirstContact(t *testing.T) {
	router := channels.NewRouter()
	env := validEnvelope(channels.ChannelSlack)

	t.Run("first_contact_creates_session", func(t *testing.T) {
		route, err := router.Route(context.Background(), env)
		require.NoError(t, err)
		require.NotNil(t, route)
		assert.NotEmpty(t, route.SessionID)
		assert.Equal(t, env.TenantID, route.TenantID)
		assert.Equal(t, channels.ChannelSlack, route.Channel)
	})
}

// TestChannelConformance_RouterRoutesRepeatContactToSameSession verifies session persistence.
func TestChannelConformance_RouterRoutesRepeatContactToSameSession(t *testing.T) {
	router := channels.NewRouter()
	env := validEnvelope(channels.ChannelSlack)

	firstRoute, err := router.Route(context.Background(), env)
	require.NoError(t, err)

	t.Run("second_contact_routes_to_same_session", func(t *testing.T) {
		secondRoute, err := router.Route(context.Background(), env)
		require.NoError(t, err)
		assert.Equal(t, firstRoute.SessionID, secondRoute.SessionID)
	})
}

// TestChannelConformance_InboundReceiptGeneration verifies receipt fields for inbound messages.
func TestChannelConformance_InboundReceiptGeneration(t *testing.T) {
	env := validEnvelope(channels.ChannelSlack)

	t.Run("inbound_receipt_has_required_fields", func(t *testing.T) {
		receipt := channels.NewInboundReceipt(env)
		require.NotNil(t, receipt)
		assert.NotEmpty(t, receipt.ReceiptID)
		assert.Equal(t, env.EnvelopeID, receipt.EnvelopeID)
		assert.Equal(t, channels.ChannelSlack, receipt.Channel)
		assert.Equal(t, "inbound", receipt.Direction)
		assert.Equal(t, env.TenantID, receipt.TenantID)
		assert.Equal(t, env.SessionID, receipt.SessionID)
		assert.NotEmpty(t, receipt.ContentHash)
		assert.Greater(t, receipt.ProcessedAtMs, int64(0))
	})
}

// TestChannelConformance_OutboundReceiptGeneration verifies receipt fields for outbound messages.
func TestChannelConformance_OutboundReceiptGeneration(t *testing.T) {
	msg := channels.OutboundMessage{Text: "Hello outbound", RequireAck: true}

	t.Run("outbound_receipt_has_required_fields", func(t *testing.T) {
		receipt := channels.NewOutboundReceipt("tenant-out", "session-out", channels.ChannelSlack, msg)
		require.NotNil(t, receipt)
		assert.NotEmpty(t, receipt.ReceiptID)
		assert.NotEmpty(t, receipt.EnvelopeID)
		assert.Equal(t, channels.ChannelSlack, receipt.Channel)
		assert.Equal(t, "outbound", receipt.Direction)
		assert.Equal(t, "tenant-out", receipt.TenantID)
		assert.Equal(t, "session-out", receipt.SessionID)
		assert.NotEmpty(t, receipt.ContentHash)
	})
}

// TestChannelConformance_TelegramAdapterNormalizesCorrectly verifies Telegram normalisation.
func TestChannelConformance_TelegramAdapterNormalizesCorrectly(t *testing.T) {
	adapter := telegram.New("bot-token-conformance")

	update := map[string]interface{}{
		"update_id": 100000001,
		"message": map[string]interface{}{
			"message_id": 42,
			"from": map[string]interface{}{
				"id":         111111,
				"is_bot":     false,
				"first_name": "Alice",
				"username":   "alice_conformance",
			},
			"chat": map[string]interface{}{
				"id":   -1001234567890,
				"type": "supergroup",
			},
			"date": time.Now().Unix(),
			"text": "Hello from Telegram",
		},
	}
	raw, err := json.Marshal(update)
	require.NoError(t, err)

	t.Run("telegram_envelope_has_correct_channel_and_sender", func(t *testing.T) {
		env, err := adapter.NormalizeInbound(context.Background(), raw)
		require.NoError(t, err)
		assert.Equal(t, channels.ChannelTelegram, env.Channel)
		assert.Equal(t, "111111", env.SenderID)
		assert.Equal(t, "alice_conformance", env.SenderHandle)
		assert.Equal(t, "Hello from Telegram", env.Text)
		assert.NotEmpty(t, env.EnvelopeID)
	})
}

// TestChannelConformance_LarkAdapterNormalizesCorrectly verifies Lark normalisation.
func TestChannelConformance_LarkAdapterNormalizesCorrectly(t *testing.T) {
	adapter := lark.New("lark-verify-token-conformance")

	// Lark create_time is a Unix-millisecond timestamp encoded as a JSON string.
	createTimeStr := time.Now().UTC().Format("1617235200000") // fixture; use fmt below
	_ = createTimeStr
	createTimeMs := time.Now().UnixMilli()
	createTimeValue := fmt.Sprintf("%d", createTimeMs)

	type larkPayload struct {
		Schema string `json:"schema"`
		Event  struct {
			Sender struct {
				SenderID struct {
					OpenID  string `json:"open_id"`
					UnionID string `json:"union_id"`
					UserID  string `json:"user_id"`
				} `json:"sender_id"`
				SenderType string `json:"sender_type"`
				TenantKey  string `json:"tenant_key"`
			} `json:"sender"`
			Message struct {
				MessageID   string `json:"message_id"`
				CreateTime  string `json:"create_time"`
				ChatID      string `json:"chat_id"`
				ChatType    string `json:"chat_type"`
				MessageType string `json:"message_type"`
				Content     string `json:"content"`
			} `json:"message"`
		} `json:"event"`
	}

	var cb larkPayload
	cb.Schema = "2.0"
	cb.Event.Sender.SenderID.OpenID = "ou_conformance_open"
	cb.Event.Sender.SenderID.UnionID = "on_conformance_union"
	cb.Event.Sender.SenderID.UserID = "usr_conformance"
	cb.Event.Sender.SenderType = "user"
	cb.Event.Sender.TenantKey = "tenant_lark_conformance"
	cb.Event.Message.MessageID = "om_conformance_001"
	cb.Event.Message.CreateTime = createTimeValue
	cb.Event.Message.ChatID = "oc_conformance_chat"
	cb.Event.Message.ChatType = "p2p"
	cb.Event.Message.MessageType = "text"
	cb.Event.Message.Content = `{"text":"Hello from Lark"}`

	raw, err := json.Marshal(cb)
	require.NoError(t, err)

	t.Run("lark_envelope_has_correct_channel_and_sender", func(t *testing.T) {
		env, err := adapter.NormalizeInbound(context.Background(), raw)
		require.NoError(t, err)
		assert.Equal(t, channels.ChannelLark, env.Channel)
		assert.Equal(t, "ou_conformance_open", env.SenderID)
		assert.NotEmpty(t, env.EnvelopeID)
	})

	t.Run("lark_envelope_extracts_text_content", func(t *testing.T) {
		env, err := adapter.NormalizeInbound(context.Background(), raw)
		require.NoError(t, err)
		assert.Equal(t, "Hello from Lark", env.Text)
	})
}

// TestChannelConformance_AdapterRegistryRejectsDuplicateRegistrations verifies dedup enforcement.
func TestChannelConformance_AdapterRegistryRejectsDuplicateRegistrations(t *testing.T) {
	registry := channels.NewAdapterRegistry()

	adapterA := slack.New("token-a")
	adapterB := slack.New("token-b") // same kind, different token

	t.Run("first_registration_succeeds", func(t *testing.T) {
		err := registry.Register(adapterA)
		require.NoError(t, err)
	})

	t.Run("duplicate_registration_is_rejected", func(t *testing.T) {
		err := registry.Register(adapterB)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "already registered")
	})
}

// TestChannelConformance_AdapterRegistryMultipleKinds verifies that different kinds coexist.
func TestChannelConformance_AdapterRegistryMultipleKinds(t *testing.T) {
	registry := channels.NewAdapterRegistry()

	slackAdapter := slack.New("slack-token")
	tgAdapter := telegram.New("tg-token")
	larkAdapter := lark.New("lark-token")

	require.NoError(t, registry.Register(slackAdapter))
	require.NoError(t, registry.Register(tgAdapter))
	require.NoError(t, registry.Register(larkAdapter))

	t.Run("all_three_adapters_are_retrievable", func(t *testing.T) {
		a, err := registry.Get(channels.ChannelSlack)
		require.NoError(t, err)
		assert.Equal(t, channels.ChannelSlack, a.Kind())

		b, err := registry.Get(channels.ChannelTelegram)
		require.NoError(t, err)
		assert.Equal(t, channels.ChannelTelegram, b.Kind())

		c, err := registry.Get(channels.ChannelLark)
		require.NoError(t, err)
		assert.Equal(t, channels.ChannelLark, c.Kind())
	})

	t.Run("list_returns_all_registered_kinds", func(t *testing.T) {
		kinds := registry.List()
		assert.Len(t, kinds, 3)
	})
}
