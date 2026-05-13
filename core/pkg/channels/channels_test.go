package channels_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/channels"
	slackadapter "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/channels/slack"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// nowMs returns the current UTC time as a Unix millisecond timestamp.
func nowMs() int64 { return time.Now().UnixMilli() }

// validEnvelope builds a minimal valid ChannelEnvelope.
func validEnvelope() channels.ChannelEnvelope {
	return channels.ChannelEnvelope{
		EnvelopeID:       "env-001",
		Channel:          channels.ChannelSlack,
		TenantID:         "tenant-abc",
		SessionID:        "session-xyz",
		MessageID:        "msg-001",
		SenderID:         "U01ABC",
		SenderTrust:      channels.SenderTrustUnknown,
		ReceivedAtUnixMs: nowMs(),
		Text:             "hello",
	}
}

// ---------------------------------------------------------------------------
// Envelope validation
// ---------------------------------------------------------------------------

func TestValidateEnvelope_HappyPath(t *testing.T) {
	env := validEnvelope()
	if err := channels.ValidateEnvelope(env); err != nil {
		t.Fatalf("expected no error for valid envelope, got: %v", err)
	}
}

func TestValidateEnvelope_MissingEnvelopeID(t *testing.T) {
	env := validEnvelope()
	env.EnvelopeID = ""
	if err := channels.ValidateEnvelope(env); err == nil {
		t.Fatal("expected error for missing envelope_id")
	}
}

func TestValidateEnvelope_MissingTenantID(t *testing.T) {
	env := validEnvelope()
	env.TenantID = ""
	if err := channels.ValidateEnvelope(env); err == nil {
		t.Fatal("expected error for missing tenant_id")
	}
}

func TestValidateEnvelope_MissingSessionID(t *testing.T) {
	env := validEnvelope()
	env.SessionID = ""
	if err := channels.ValidateEnvelope(env); err == nil {
		t.Fatal("expected error for missing session_id")
	}
}

func TestValidateEnvelope_MissingMessageID(t *testing.T) {
	env := validEnvelope()
	env.MessageID = ""
	if err := channels.ValidateEnvelope(env); err == nil {
		t.Fatal("expected error for missing message_id")
	}
}

func TestValidateEnvelope_MissingSenderID(t *testing.T) {
	env := validEnvelope()
	env.SenderID = ""
	if err := channels.ValidateEnvelope(env); err == nil {
		t.Fatal("expected error for missing sender_id")
	}
}

func TestValidateEnvelope_InvalidChannel(t *testing.T) {
	env := validEnvelope()
	env.Channel = "matrix"
	if err := channels.ValidateEnvelope(env); err == nil {
		t.Fatal("expected error for invalid channel")
	}
}

func TestValidateEnvelope_FutureTimestamp(t *testing.T) {
	env := validEnvelope()
	env.ReceivedAtUnixMs = nowMs() + 10*60*1000 // 10 minutes in the future
	if err := channels.ValidateEnvelope(env); err == nil {
		t.Fatal("expected error for future timestamp")
	}
}

func TestValidateEnvelope_TooOldTimestamp(t *testing.T) {
	env := validEnvelope()
	env.ReceivedAtUnixMs = nowMs() - 10*60*1000 // 10 minutes in the past
	if err := channels.ValidateEnvelope(env); err == nil {
		t.Fatal("expected error for timestamp too far in the past")
	}
}

// ---------------------------------------------------------------------------
// ValidChannelKind
// ---------------------------------------------------------------------------

func TestValidChannelKind(t *testing.T) {
	valid := []channels.ChannelKind{
		channels.ChannelSlack,
		channels.ChannelTelegram,
		channels.ChannelLark,
		channels.ChannelWhatsApp,
		channels.ChannelSignal,
	}
	for _, k := range valid {
		if !channels.ValidChannelKind(k) {
			t.Errorf("expected %q to be valid", k)
		}
	}
	invalid := []channels.ChannelKind{"irc", "matrix", "", "SLACK"}
	for _, k := range invalid {
		if channels.ValidChannelKind(k) {
			t.Errorf("expected %q to be invalid", k)
		}
	}
}

// ---------------------------------------------------------------------------
// AdapterRegistry
// ---------------------------------------------------------------------------

// fakeAdapter satisfies the channels.Adapter interface for testing.
type fakeAdapter struct {
	kind channels.ChannelKind
}

func (s *fakeAdapter) Kind() channels.ChannelKind { return s.kind }
func (s *fakeAdapter) NormalizeInbound(_ context.Context, _ []byte) (channels.ChannelEnvelope, error) {
	return channels.ChannelEnvelope{}, nil
}
func (s *fakeAdapter) Send(_ context.Context, _, _ string, _ channels.OutboundMessage) error {
	return nil
}
func (s *fakeAdapter) Health(_ context.Context) error { return nil }

func TestAdapterRegistry_RegisterAndGet(t *testing.T) {
	reg := channels.NewAdapterRegistry()
	adapter := &fakeAdapter{kind: channels.ChannelSlack}

	if err := reg.Register(adapter); err != nil {
		t.Fatalf("Register: unexpected error: %v", err)
	}

	got, err := reg.Get(channels.ChannelSlack)
	if err != nil {
		t.Fatalf("Get: unexpected error: %v", err)
	}
	if got.Kind() != channels.ChannelSlack {
		t.Errorf("expected kind %q, got %q", channels.ChannelSlack, got.Kind())
	}
}

func TestAdapterRegistry_DuplicateRegister(t *testing.T) {
	reg := channels.NewAdapterRegistry()
	adapter := &fakeAdapter{kind: channels.ChannelSlack}

	if err := reg.Register(adapter); err != nil {
		t.Fatalf("first Register: unexpected error: %v", err)
	}
	if err := reg.Register(adapter); err == nil {
		t.Fatal("expected error on duplicate registration")
	}
}

func TestAdapterRegistry_GetUnregistered(t *testing.T) {
	reg := channels.NewAdapterRegistry()
	if _, err := reg.Get(channels.ChannelTelegram); err == nil {
		t.Fatal("expected error when getting unregistered adapter")
	}
}

func TestAdapterRegistry_List(t *testing.T) {
	reg := channels.NewAdapterRegistry()
	_ = reg.Register(&fakeAdapter{kind: channels.ChannelSlack})
	_ = reg.Register(&fakeAdapter{kind: channels.ChannelTelegram})

	kinds := reg.List()
	if len(kinds) != 2 {
		t.Fatalf("expected 2 adapters, got %d", len(kinds))
	}
}

func TestAdapterRegistry_NilAdapter(t *testing.T) {
	reg := channels.NewAdapterRegistry()
	if err := reg.Register(nil); err == nil {
		t.Fatal("expected error when registering nil adapter")
	}
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

func TestRouter_CreateSession(t *testing.T) {
	ctx := context.Background()
	router := channels.NewRouter()

	sessionID, err := router.CreateSession(ctx, "tenant-1", channels.ChannelSlack)
	if err != nil {
		t.Fatalf("CreateSession: unexpected error: %v", err)
	}
	if sessionID == "" {
		t.Fatal("CreateSession: returned empty session ID")
	}
}

func TestRouter_CreateSession_EmptyTenant(t *testing.T) {
	ctx := context.Background()
	router := channels.NewRouter()
	if _, err := router.CreateSession(ctx, "", channels.ChannelSlack); err == nil {
		t.Fatal("expected error for empty tenantID")
	}
}

func TestRouter_CreateSession_InvalidChannel(t *testing.T) {
	ctx := context.Background()
	router := channels.NewRouter()
	if _, err := router.CreateSession(ctx, "tenant-1", "irc"); err == nil {
		t.Fatal("expected error for invalid channel")
	}
}

func TestRouter_Route_NewSession(t *testing.T) {
	ctx := context.Background()
	router := channels.NewRouter()
	env := validEnvelope()

	route, err := router.Route(ctx, env)
	if err != nil {
		t.Fatalf("Route: unexpected error: %v", err)
	}
	if route.SessionID == "" {
		t.Fatal("Route: empty session ID")
	}
	if route.TenantID != env.TenantID {
		t.Errorf("expected TenantID %q, got %q", env.TenantID, route.TenantID)
	}
	if route.Channel != env.Channel {
		t.Errorf("expected Channel %q, got %q", env.Channel, route.Channel)
	}
}

func TestRouter_Route_SameSessionForSameSender(t *testing.T) {
	ctx := context.Background()
	router := channels.NewRouter()
	env := validEnvelope()

	route1, _ := router.Route(ctx, env)
	route2, _ := router.Route(ctx, env)

	if route1.SessionID != route2.SessionID {
		t.Errorf("expected same session for same sender, got %q vs %q",
			route1.SessionID, route2.SessionID)
	}
}

func TestRouter_Route_DifferentSessionForDifferentSender(t *testing.T) {
	ctx := context.Background()
	router := channels.NewRouter()

	env1 := validEnvelope()
	env1.SenderID = "sender-A"

	env2 := validEnvelope()
	env2.SenderID = "sender-B"

	route1, _ := router.Route(ctx, env1)
	route2, _ := router.Route(ctx, env2)

	if route1.SessionID == route2.SessionID {
		t.Error("expected different sessions for different senders")
	}
}

func TestRouter_Route_EmptyTenantID(t *testing.T) {
	ctx := context.Background()
	router := channels.NewRouter()
	env := validEnvelope()
	env.TenantID = ""
	if _, err := router.Route(ctx, env); err == nil {
		t.Fatal("expected error for empty tenant_id")
	}
}

// ---------------------------------------------------------------------------
// Anti-spoof validator
// ---------------------------------------------------------------------------

func TestAntiSpoofValidator_HappyPath(t *testing.T) {
	ctx := context.Background()
	v := channels.NewAntiSpoofValidator()
	env := validEnvelope()

	result, err := v.Validate(ctx, env)
	if err != nil {
		t.Fatalf("Validate: unexpected error: %v", err)
	}
	if !result.Passed {
		t.Errorf("expected Passed=true, got reason: %s", result.Reason)
	}
}

func TestAntiSpoofValidator_EmptyEnvelopeID(t *testing.T) {
	ctx := context.Background()
	v := channels.NewAntiSpoofValidator()
	env := validEnvelope()
	env.EnvelopeID = ""

	result, err := v.Validate(ctx, env)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected Passed=false for empty envelope_id")
	}
	if result.SenderTrust != channels.SenderTrustSuspicious {
		t.Errorf("expected SenderTrustSuspicious, got %q", result.SenderTrust)
	}
}

func TestAntiSpoofValidator_EmptySenderID(t *testing.T) {
	ctx := context.Background()
	v := channels.NewAntiSpoofValidator()
	env := validEnvelope()
	env.SenderID = ""

	result, err := v.Validate(ctx, env)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected Passed=false for empty sender_id")
	}
}

func TestAntiSpoofValidator_FutureTimestamp(t *testing.T) {
	ctx := context.Background()
	v := channels.NewAntiSpoofValidator()
	env := validEnvelope()
	env.ReceivedAtUnixMs = nowMs() + 60*1000*10 // 10 minutes in the future

	result, _ := v.Validate(ctx, env)
	if result.Passed {
		t.Fatal("expected Passed=false for future timestamp")
	}
}

func TestAntiSpoofValidator_TooOldTimestamp(t *testing.T) {
	ctx := context.Background()
	v := channels.NewAntiSpoofValidator()
	env := validEnvelope()
	env.ReceivedAtUnixMs = nowMs() - 10*60*1000 // 10 minutes old

	result, _ := v.Validate(ctx, env)
	if result.Passed {
		t.Fatal("expected Passed=false for too-old timestamp")
	}
}

// ---------------------------------------------------------------------------
// Receipt generation
// ---------------------------------------------------------------------------

func TestNewInboundReceipt(t *testing.T) {
	env := validEnvelope()
	receipt := channels.NewInboundReceipt(env)

	if receipt == nil {
		t.Fatal("NewInboundReceipt returned nil")
	}
	if receipt.ReceiptID == "" {
		t.Error("ReceiptID is empty")
	}
	if receipt.EnvelopeID != env.EnvelopeID {
		t.Errorf("expected EnvelopeID %q, got %q", env.EnvelopeID, receipt.EnvelopeID)
	}
	if receipt.Direction != "inbound" {
		t.Errorf("expected direction 'inbound', got %q", receipt.Direction)
	}
	if receipt.Channel != env.Channel {
		t.Errorf("expected channel %q, got %q", env.Channel, receipt.Channel)
	}
	if receipt.TenantID != env.TenantID {
		t.Errorf("expected tenantID %q, got %q", env.TenantID, receipt.TenantID)
	}
	if receipt.ContentHash == "" {
		t.Error("ContentHash is empty")
	}
}

func TestNewOutboundReceipt(t *testing.T) {
	msg := channels.OutboundMessage{Text: "hello", RequireAck: true}
	receipt := channels.NewOutboundReceipt("tenant-1", "session-1", channels.ChannelSlack, msg)

	if receipt == nil {
		t.Fatal("NewOutboundReceipt returned nil")
	}
	if receipt.Direction != "outbound" {
		t.Errorf("expected direction 'outbound', got %q", receipt.Direction)
	}
	if receipt.ContentHash == "" {
		t.Error("ContentHash is empty")
	}
}

// ---------------------------------------------------------------------------
// Slack adapter — NormalizeInbound
// ---------------------------------------------------------------------------

func TestSlackAdapter_NormalizeInbound_HappyPath(t *testing.T) {
	adapter := slackadapter.New("xoxb-test-token")

	payload := map[string]any{
		"type":      "message",
		"user":      "U01ABCDEF",
		"text":      "Hello from Slack!",
		"channel":   "C01ABCDEF",
		"ts":        "1617235200.000001",
		"thread_ts": "1617235100.000001",
	}
	raw, _ := json.Marshal(payload)

	env, err := adapter.NormalizeInbound(context.Background(), raw)
	if err != nil {
		t.Fatalf("NormalizeInbound: unexpected error: %v", err)
	}

	if env.Channel != channels.ChannelSlack {
		t.Errorf("expected channel slack, got %q", env.Channel)
	}
	if env.SenderID != "U01ABCDEF" {
		t.Errorf("expected SenderID 'U01ABCDEF', got %q", env.SenderID)
	}
	if env.Text != "Hello from Slack!" {
		t.Errorf("expected text 'Hello from Slack!', got %q", env.Text)
	}
	if env.MessageID != "1617235200.000001" {
		t.Errorf("expected MessageID '1617235200.000001', got %q", env.MessageID)
	}
	if env.ThreadID != "1617235100.000001" {
		t.Errorf("expected ThreadID '1617235100.000001', got %q", env.ThreadID)
	}
	if env.EnvelopeID == "" {
		t.Error("EnvelopeID is empty")
	}
	if env.Metadata["slack_channel"] != "C01ABCDEF" {
		t.Errorf("expected slack_channel metadata 'C01ABCDEF', got %q", env.Metadata["slack_channel"])
	}
}

func TestSlackAdapter_NormalizeInbound_MissingUser(t *testing.T) {
	adapter := slackadapter.New("xoxb-test-token")

	payload := map[string]any{
		"type":    "message",
		"text":    "No user!",
		"channel": "C01ABCDEF",
		"ts":      "1617235200.000001",
	}
	raw, _ := json.Marshal(payload)

	if _, err := adapter.NormalizeInbound(context.Background(), raw); err == nil {
		t.Fatal("expected error for missing user")
	}
}

func TestSlackAdapter_NormalizeInbound_MissingTS(t *testing.T) {
	adapter := slackadapter.New("xoxb-test-token")

	payload := map[string]any{
		"type":    "message",
		"user":    "U01ABCDEF",
		"text":    "No ts!",
		"channel": "C01ABCDEF",
	}
	raw, _ := json.Marshal(payload)

	if _, err := adapter.NormalizeInbound(context.Background(), raw); err == nil {
		t.Fatal("expected error for missing ts")
	}
}

func TestSlackAdapter_NormalizeInbound_InvalidJSON(t *testing.T) {
	adapter := slackadapter.New("xoxb-test-token")
	if _, err := adapter.NormalizeInbound(context.Background(), []byte("not json")); err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestSlackAdapter_Kind(t *testing.T) {
	adapter := slackadapter.New("xoxb-test-token")
	if adapter.Kind() != channels.ChannelSlack {
		t.Errorf("expected ChannelSlack, got %q", adapter.Kind())
	}
}

func TestSlackAdapter_Health_EmptyToken(t *testing.T) {
	adapter := slackadapter.New("")
	if err := adapter.Health(context.Background()); err == nil {
		t.Fatal("expected error for empty token")
	}
}

func TestSlackAdapter_Health_ValidToken(t *testing.T) {
	adapter := slackadapter.New("xoxb-test-token")
	if err := adapter.Health(context.Background()); err != nil {
		t.Fatalf("unexpected health error: %v", err)
	}
}
