package channels

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"
)

// ── Slack Signature Tests ──────────────────────────────────────────────────

func TestSlackSignatureVerify_ValidHMAC(t *testing.T) {
	secret := "8f742231b10e8888abcd99yez67a156e"
	ts := "1531420618"
	body := `{"token":"xyzz0WbapA4vBCDEFasx0q6G","team_id":"T1DC2JH3J"}`

	baseString := "v0:" + ts + ":" + body
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(baseString))
	sig := "v0=" + hex.EncodeToString(mac.Sum(nil))

	env := ChannelEnvelope{
		Channel:      ChannelSlack,
		SignatureRef: body,
		Metadata: map[string]string{
			"slack_signature": sig,
			"slack_timestamp": ts,
		},
	}

	v := &slackSignatureVerifier{signingSecret: secret}
	if err := v.Verify(env); err != nil {
		t.Fatalf("valid HMAC should pass: %v", err)
	}
}

func TestSlackSignatureVerify_InvalidHMAC(t *testing.T) {
	env := ChannelEnvelope{
		Channel:      ChannelSlack,
		SignatureRef: `{"some":"body"}`,
		Metadata: map[string]string{
			"slack_signature": "v0=deadbeef",
			"slack_timestamp": "1531420618",
		},
	}

	v := &slackSignatureVerifier{signingSecret: "real-secret"}
	if err := v.Verify(env); err == nil {
		t.Fatal("invalid HMAC should fail")
	}
}

func TestSlackSignatureVerify_NoMetadata(t *testing.T) {
	env := ChannelEnvelope{Channel: ChannelSlack}
	v := &slackSignatureVerifier{signingSecret: "secret"}
	if err := v.Verify(env); err != nil {
		t.Fatalf("no metadata should pass (skip verification): %v", err)
	}
}

func TestSlackSignatureVerify_SignaturePresentNoSecret(t *testing.T) {
	env := ChannelEnvelope{
		Channel: ChannelSlack,
		Metadata: map[string]string{
			"slack_signature": "v0=abc",
			"slack_timestamp": "123",
		},
	}
	v := &slackSignatureVerifier{signingSecret: ""}
	if err := v.Verify(env); err == nil {
		t.Fatal("signature present without secret should fail")
	}
}

func TestSlackSignatureVerify_TimestampWithoutSignature(t *testing.T) {
	env := ChannelEnvelope{
		Channel: ChannelSlack,
		Metadata: map[string]string{
			"slack_timestamp": "123",
		},
	}
	v := &slackSignatureVerifier{signingSecret: "secret"}
	if err := v.Verify(env); err == nil {
		t.Fatal("timestamp without signature should fail")
	}
}

func TestSlackSignatureVerify_NonNumericTimestamp(t *testing.T) {
	env := ChannelEnvelope{
		Channel: ChannelSlack,
		Metadata: map[string]string{
			"slack_signature": "v0=abc",
			"slack_timestamp": "not-a-number",
		},
	}
	v := &slackSignatureVerifier{signingSecret: "secret"}
	if err := v.Verify(env); err == nil {
		t.Fatal("non-numeric timestamp should fail")
	}
}

// ── Telegram Signature Tests ───────────────────────────────────────────────

func TestTelegramSignatureVerify_ValidToken(t *testing.T) {
	token := "123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11"
	env := ChannelEnvelope{
		Channel: ChannelTelegram,
		Metadata: map[string]string{
			"telegram_secret_token": token,
		},
	}
	v := &telegramSignatureVerifier{botToken: token}
	if err := v.Verify(env); err != nil {
		t.Fatalf("valid token should pass: %v", err)
	}
}

func TestTelegramSignatureVerify_ValidHashedToken(t *testing.T) {
	token := "123456:ABC-DEF"
	hash := sha256Hex(token)
	env := ChannelEnvelope{
		Channel: ChannelTelegram,
		Metadata: map[string]string{
			"telegram_secret_token": hash,
		},
	}
	v := &telegramSignatureVerifier{botToken: token}
	if err := v.Verify(env); err != nil {
		t.Fatalf("hashed token should pass: %v", err)
	}
}

func TestTelegramSignatureVerify_InvalidToken(t *testing.T) {
	env := ChannelEnvelope{
		Channel: ChannelTelegram,
		Metadata: map[string]string{
			"telegram_secret_token": "wrong-token",
		},
	}
	v := &telegramSignatureVerifier{botToken: "real-token"}
	if err := v.Verify(env); err == nil {
		t.Fatal("invalid token should fail")
	}
}

func TestTelegramSignatureVerify_NoMetadata(t *testing.T) {
	env := ChannelEnvelope{Channel: ChannelTelegram}
	v := &telegramSignatureVerifier{botToken: "token"}
	if err := v.Verify(env); err != nil {
		t.Fatalf("no metadata should pass: %v", err)
	}
}

// ── Lark Signature Tests ──────────────────────────────────────────────────

func TestLarkSignatureVerify_ValidToken(t *testing.T) {
	token := "lark-verification-token-123"
	env := ChannelEnvelope{
		Channel: ChannelLark,
		Metadata: map[string]string{
			"lark_verification_token": token,
		},
	}
	v := &larkSignatureVerifier{verificationToken: token}
	if err := v.Verify(env); err != nil {
		t.Fatalf("valid token should pass: %v", err)
	}
}

func TestLarkSignatureVerify_InvalidToken(t *testing.T) {
	env := ChannelEnvelope{
		Channel: ChannelLark,
		Metadata: map[string]string{
			"lark_verification_token": "wrong",
		},
	}
	v := &larkSignatureVerifier{verificationToken: "correct"}
	if err := v.Verify(env); err == nil {
		t.Fatal("invalid token should fail")
	}
}

func TestLarkSignatureVerify_NoMetadata(t *testing.T) {
	env := ChannelEnvelope{Channel: ChannelLark}
	v := &larkSignatureVerifier{verificationToken: "token"}
	if err := v.Verify(env); err != nil {
		t.Fatalf("no metadata should pass: %v", err)
	}
}

// ── WhatsApp Signature Tests ──────────────────────────────────────────────

func TestWhatsAppSignatureVerify_ValidHMAC(t *testing.T) {
	secret := "whatsapp-app-secret"
	body := `{"entry":[{"changes":[]}]}`

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(body))
	sig := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	env := ChannelEnvelope{
		Channel:      ChannelWhatsApp,
		SignatureRef: body,
		Metadata: map[string]string{
			"whatsapp_signature": sig,
		},
	}

	v := &whatsappSignatureVerifier{appSecret: secret}
	if err := v.Verify(env); err != nil {
		t.Fatalf("valid HMAC should pass: %v", err)
	}
}

func TestWhatsAppSignatureVerify_InvalidHMAC(t *testing.T) {
	env := ChannelEnvelope{
		Channel:      ChannelWhatsApp,
		SignatureRef: `{"body":"data"}`,
		Metadata: map[string]string{
			"whatsapp_signature": "sha256=deadbeef",
		},
	}
	v := &whatsappSignatureVerifier{appSecret: "secret"}
	if err := v.Verify(env); err == nil {
		t.Fatal("invalid HMAC should fail")
	}
}

func TestWhatsAppSignatureVerify_MissingPrefix(t *testing.T) {
	env := ChannelEnvelope{
		Channel: ChannelWhatsApp,
		Metadata: map[string]string{
			"whatsapp_signature": "deadbeef",
		},
	}
	v := &whatsappSignatureVerifier{appSecret: "secret"}
	if err := v.Verify(env); err == nil {
		t.Fatal("missing sha256= prefix should fail")
	}
}

func TestWhatsAppSignatureVerify_NoMetadata(t *testing.T) {
	env := ChannelEnvelope{Channel: ChannelWhatsApp}
	v := &whatsappSignatureVerifier{appSecret: "secret"}
	if err := v.Verify(env); err != nil {
		t.Fatalf("no metadata should pass: %v", err)
	}
}

// ── Signal Signature Tests ────────────────────────────────────────────────

func TestSignalSignatureVerify_ValidFingerprint(t *testing.T) {
	fp := "AB:CD:EF:01:23:45:67:89"
	env := ChannelEnvelope{
		Channel: ChannelSignal,
		Metadata: map[string]string{
			"signal_cert_fingerprint": fp,
		},
	}
	v := &signalSignatureVerifier{serverCert: fp}
	if err := v.Verify(env); err != nil {
		t.Fatalf("valid fingerprint should pass: %v", err)
	}
}

func TestSignalSignatureVerify_NormalizedComparison(t *testing.T) {
	env := ChannelEnvelope{
		Channel: ChannelSignal,
		Metadata: map[string]string{
			"signal_cert_fingerprint": "AB:CD:EF:01",
		},
	}
	// Same bytes, different format (no colons, lowercase).
	v := &signalSignatureVerifier{serverCert: "abcdef01"}
	if err := v.Verify(env); err != nil {
		t.Fatalf("normalized fingerprints should match: %v", err)
	}
}

func TestSignalSignatureVerify_InvalidFingerprint(t *testing.T) {
	env := ChannelEnvelope{
		Channel: ChannelSignal,
		Metadata: map[string]string{
			"signal_cert_fingerprint": "wrong",
		},
	}
	v := &signalSignatureVerifier{serverCert: "correct"}
	if err := v.Verify(env); err == nil {
		t.Fatal("mismatched fingerprint should fail")
	}
}

func TestSignalSignatureVerify_NoMetadata(t *testing.T) {
	env := ChannelEnvelope{Channel: ChannelSignal}
	v := &signalSignatureVerifier{serverCert: "cert"}
	if err := v.Verify(env); err != nil {
		t.Fatalf("no metadata should pass: %v", err)
	}
}

// ── Unknown Channel ───────────────────────────────────────────────────────

func TestRejectUnknownChannel(t *testing.T) {
	v := &rejectUnknownVerifier{channel: "foobar"}
	if err := v.Verify(ChannelEnvelope{}); err == nil {
		t.Fatal("unknown channel should be rejected")
	}
}

// ── Integration: Anti-Spoof with Secrets ──────────────────────────────────

func TestAntiSpoofWithSecrets_SlackVerification(t *testing.T) {
	secret := "test-slack-secret"
	ts := "1617235200"
	body := `{"text":"hello"}`

	baseString := "v0:" + ts + ":" + body
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(baseString))
	sig := "v0=" + hex.EncodeToString(mac.Sum(nil))

	validator := NewAntiSpoofValidatorWithSecrets(SignatureSecrets{
		SlackSigningSecret: secret,
	})

	env := ChannelEnvelope{
		EnvelopeID:       "env-1",
		Channel:          ChannelSlack,
		SenderID:         "U123",
		ReceivedAtUnixMs: time.Now().UnixMilli(),
		SignatureRef:     body,
		Metadata: map[string]string{
			"slack_signature": sig,
			"slack_timestamp": ts,
		},
	}

	result, err := validator.Validate(nil, env)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("valid slack signature should pass, reason: %s", result.Reason)
	}
}

func TestAntiSpoofWithSecrets_SlackBadSignature(t *testing.T) {
	validator := NewAntiSpoofValidatorWithSecrets(SignatureSecrets{
		SlackSigningSecret: "real-secret",
	})

	env := ChannelEnvelope{
		EnvelopeID:       "env-2",
		Channel:          ChannelSlack,
		SenderID:         "U123",
		ReceivedAtUnixMs: time.Now().UnixMilli(),
		Metadata: map[string]string{
			"slack_signature": "v0=forged",
			"slack_timestamp": "1617235200",
		},
	}

	result, err := validator.Validate(nil, env)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("forged signature should NOT pass")
	}
	if result.SenderTrust != SenderTrustSuspicious {
		t.Fatalf("expected suspicious trust, got %q", result.SenderTrust)
	}
}

func TestAntiSpoofNoSecrets_SkipsVerification(t *testing.T) {
	validator := NewAntiSpoofValidator()

	env := ChannelEnvelope{
		EnvelopeID:       "env-3",
		Channel:          ChannelSlack,
		SenderID:         "U456",
		ReceivedAtUnixMs: time.Now().UnixMilli(),
	}

	result, err := validator.Validate(nil, env)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("no signature metadata should pass: %s", result.Reason)
	}
}

// ── NewSignatureVerifier factory ──────────────────────────────────────────

func TestNewSignatureVerifier_AllChannels(t *testing.T) {
	secrets := SignatureSecrets{
		SlackSigningSecret:    "s",
		TelegramBotToken:      "t",
		LarkVerificationToken: "l",
		WhatsAppAppSecret:     "w",
		SignalServerCert:      "c",
	}

	channels := []ChannelKind{ChannelSlack, ChannelTelegram, ChannelLark, ChannelWhatsApp, ChannelSignal}
	for _, ch := range channels {
		v := NewSignatureVerifier(ch, secrets)
		if v == nil {
			t.Fatalf("nil verifier for channel %q", ch)
		}
		// With no signature metadata, all should pass.
		if err := v.Verify(ChannelEnvelope{Channel: ch}); err != nil {
			t.Fatalf("channel %q with no metadata should pass: %v", ch, err)
		}
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────

func TestSha256Hex(t *testing.T) {
	result := sha256Hex("test")
	if len(result) != 64 {
		t.Fatalf("expected 64 hex chars, got %d", len(result))
	}
}

func TestMetaVal_NilMetadata(t *testing.T) {
	env := ChannelEnvelope{}
	if metaVal(env, "any") != "" {
		t.Fatal("nil metadata should return empty string")
	}
}
