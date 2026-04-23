package channels

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// ChannelSignatureVerifier verifies the cryptographic signature of an inbound
// channel envelope. Each channel platform has a different signature scheme;
// implementations of this interface encapsulate the platform-specific logic.
type ChannelSignatureVerifier interface {
	// Verify checks the signature on the given envelope.
	// It returns nil if the signature is valid, or an error describing the failure.
	Verify(env ChannelEnvelope) error
}

// SignatureSecrets holds the per-channel secrets needed for signature verification.
// Only the channels that are configured need non-empty values.
type SignatureSecrets struct {
	// SlackSigningSecret is the Slack app signing secret (used for X-Slack-Signature HMAC).
	SlackSigningSecret string
	// TelegramBotToken is the Telegram bot token (used for webhook verification).
	TelegramBotToken string
	// LarkVerificationToken is the Lark app verification token.
	LarkVerificationToken string
	// WhatsAppAppSecret is the WhatsApp Business API app secret.
	WhatsAppAppSecret string
	// SignalServerCert is the Signal webhook certificate fingerprint (SHA-256 hex).
	SignalServerCert string
}

// NewSignatureVerifier returns a ChannelSignatureVerifier for the given channel kind
// using the provided secrets. If the secret for the given channel is empty, a
// verifier that requires the signature metadata key to be absent is returned
// (i.e. it accepts envelopes that have no signature claim but rejects envelopes
// that claim a signature when no secret is available to verify it).
func NewSignatureVerifier(kind ChannelKind, secrets SignatureSecrets) ChannelSignatureVerifier {
	switch kind {
	case ChannelSlack:
		return &slackSignatureVerifier{signingSecret: secrets.SlackSigningSecret}
	case ChannelTelegram:
		return &telegramSignatureVerifier{botToken: secrets.TelegramBotToken}
	case ChannelLark:
		return &larkSignatureVerifier{verificationToken: secrets.LarkVerificationToken}
	case ChannelWhatsApp:
		return &whatsappSignatureVerifier{appSecret: secrets.WhatsAppAppSecret}
	case ChannelSignal:
		return &signalSignatureVerifier{serverCert: secrets.SignalServerCert}
	default:
		return &rejectUnknownVerifier{channel: string(kind)}
	}
}

// ── Slack ──────────────────────────────────────────────────────────────────

// slackSignatureVerifier verifies the X-Slack-Signature HMAC-SHA256 header.
//
// Slack signs webhook payloads with: v0=HMAC-SHA256(signing_secret, "v0:<timestamp>:<body>").
// Adapters must populate:
//   - Metadata["slack_signature"]  → the v0=... header value
//   - Metadata["slack_timestamp"]  → the X-Slack-Request-Timestamp header
//   - SignatureRef                 → the raw request body (or its SHA-256 hash)
type slackSignatureVerifier struct {
	signingSecret string
}

func (v *slackSignatureVerifier) Verify(env ChannelEnvelope) error {
	sig := metaVal(env, "slack_signature")
	ts := metaVal(env, "slack_timestamp")

	// If no signature metadata is present, skip verification (adapter didn't capture it).
	if sig == "" && ts == "" {
		return nil
	}

	if v.signingSecret == "" {
		return fmt.Errorf("slack signature present but no signing secret configured")
	}

	if sig == "" {
		return fmt.Errorf("slack_timestamp present but slack_signature missing")
	}
	if ts == "" {
		return fmt.Errorf("slack_signature present but slack_timestamp missing")
	}

	// Validate timestamp is numeric (prevents injection in the HMAC base string).
	if _, err := strconv.ParseInt(ts, 10, 64); err != nil {
		return fmt.Errorf("slack_timestamp is not a valid integer: %w", err)
	}

	// Reconstruct the signing base string.
	body := env.SignatureRef
	if body == "" {
		// Fall back to text if no raw body ref is stored.
		body = env.Text
	}
	baseString := fmt.Sprintf("v0:%s:%s", ts, body)

	mac := hmac.New(sha256.New, []byte(v.signingSecret))
	mac.Write([]byte(baseString))
	expected := "v0=" + hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(expected), []byte(sig)) {
		return fmt.Errorf("slack HMAC signature mismatch")
	}

	return nil
}

// ── Telegram ───────────────────────────────────────────────────────────────

// telegramSignatureVerifier verifies the Telegram webhook secret_token header.
//
// When a secret_token is configured on the webhook, Telegram sends it in the
// X-Telegram-Bot-Api-Secret-Token header. Adapters must populate:
//   - Metadata["telegram_secret_token"] → the header value
type telegramSignatureVerifier struct {
	botToken string
}

func (v *telegramSignatureVerifier) Verify(env ChannelEnvelope) error {
	secretToken := metaVal(env, "telegram_secret_token")

	// If no token metadata present, skip (adapter didn't capture it).
	if secretToken == "" {
		return nil
	}

	if v.botToken == "" {
		return fmt.Errorf("telegram secret token present but no bot token configured")
	}

	// The secret_token is set when configuring the webhook and should match
	// the SHA-256 of the bot token (our convention) or the raw token itself.
	expectedHash := sha256Hex(v.botToken)
	if secretToken != v.botToken && secretToken != expectedHash {
		return fmt.Errorf("telegram secret token mismatch")
	}

	return nil
}

// ── Lark ───────────────────────────────────────────────────────────────────

// larkSignatureVerifier verifies the Lark Event Callback v2.0 verification token.
//
// Lark sends a verification_token in the event payload header. Adapters must populate:
//   - Metadata["lark_verification_token"] → the token from the callback payload
type larkSignatureVerifier struct {
	verificationToken string
}

func (v *larkSignatureVerifier) Verify(env ChannelEnvelope) error {
	token := metaVal(env, "lark_verification_token")

	if token == "" {
		return nil
	}

	if v.verificationToken == "" {
		return fmt.Errorf("lark verification token present but no secret configured")
	}

	if token != v.verificationToken {
		return fmt.Errorf("lark verification token mismatch")
	}

	return nil
}

// ── WhatsApp ───────────────────────────────────────────────────────────────

// whatsappSignatureVerifier verifies the WhatsApp webhook X-Hub-Signature-256 header.
//
// WhatsApp (Meta) signs webhook payloads with HMAC-SHA256 using the app secret.
// Adapters must populate:
//   - Metadata["whatsapp_signature"] → the sha256=<hex> header value
//   - SignatureRef                   → the raw request body (or its hash)
type whatsappSignatureVerifier struct {
	appSecret string
}

func (v *whatsappSignatureVerifier) Verify(env ChannelEnvelope) error {
	sig := metaVal(env, "whatsapp_signature")

	if sig == "" {
		return nil
	}

	if v.appSecret == "" {
		return fmt.Errorf("whatsapp signature present but no app secret configured")
	}

	// WhatsApp sends "sha256=<hex>".
	hexSig := strings.TrimPrefix(sig, "sha256=")
	if hexSig == sig {
		return fmt.Errorf("whatsapp signature missing sha256= prefix")
	}

	body := env.SignatureRef
	if body == "" {
		body = env.Text
	}

	mac := hmac.New(sha256.New, []byte(v.appSecret))
	mac.Write([]byte(body))
	expected := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(expected), []byte(hexSig)) {
		return fmt.Errorf("whatsapp HMAC signature mismatch")
	}

	return nil
}

// ── Signal ─────────────────────────────────────────────────────────────────

// signalSignatureVerifier verifies Signal message authentication.
//
// Signal webhook integrations use a certificate fingerprint for mutual TLS.
// Adapters must populate:
//   - Metadata["signal_cert_fingerprint"] → the SHA-256 fingerprint of the client cert
type signalSignatureVerifier struct {
	serverCert string
}

func (v *signalSignatureVerifier) Verify(env ChannelEnvelope) error {
	fp := metaVal(env, "signal_cert_fingerprint")

	if fp == "" {
		return nil
	}

	if v.serverCert == "" {
		return fmt.Errorf("signal cert fingerprint present but no server cert configured")
	}

	// Normalize: strip colons and lowercase for comparison.
	normalizedFP := strings.ToLower(strings.ReplaceAll(fp, ":", ""))
	normalizedExpected := strings.ToLower(strings.ReplaceAll(v.serverCert, ":", ""))

	if normalizedFP != normalizedExpected {
		return fmt.Errorf("signal certificate fingerprint mismatch")
	}

	return nil
}

// ── Reject Unknown ─────────────────────────────────────────────────────────

type rejectUnknownVerifier struct {
	channel string
}

func (v *rejectUnknownVerifier) Verify(_ ChannelEnvelope) error {
	return fmt.Errorf("no signature verifier for channel %q", v.channel)
}

// ── Helpers ────────────────────────────────────────────────────────────────

func metaVal(env ChannelEnvelope, key string) string {
	if env.Metadata == nil {
		return ""
	}
	return env.Metadata[key]
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
