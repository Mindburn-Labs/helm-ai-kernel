package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/channels"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/channels/slack"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/channels/telegram"
)

func TestSignatureSecretsForEnabledChannelsRequiresConfiguredSecrets(t *testing.T) {
	t.Setenv("SLACK_SIGNING_SECRET", "")
	t.Setenv("TELEGRAM_WEBHOOK_SECRET_TOKEN", "")
	t.Setenv("TELEGRAM_BOT_TOKEN", "")

	if _, err := signatureSecretsForEnabledChannels([]string{"slack"}); err == nil {
		t.Fatal("slack gateway should require SLACK_SIGNING_SECRET")
	}
	if _, err := signatureSecretsForEnabledChannels([]string{"telegram"}); err == nil {
		t.Fatal("telegram gateway should require a webhook secret")
	}

	t.Setenv("SLACK_SIGNING_SECRET", "slack-secret")
	t.Setenv("TELEGRAM_WEBHOOK_SECRET_TOKEN", "telegram-secret")
	secrets, err := signatureSecretsForEnabledChannels([]string{"slack", "telegram"})
	if err != nil {
		t.Fatalf("configured secrets rejected: %v", err)
	}
	if secrets.SlackSigningSecret != "slack-secret" || secrets.TelegramBotToken != "telegram-secret" {
		t.Fatalf("unexpected secrets: %+v", secrets)
	}
}

func TestWebhookHandlerRejectsForgedSlackWebhook(t *testing.T) {
	secret := "slack-signing-secret"
	handler := slackWebhookTestHandler(t, secret)
	body, ts := slackWebhookBody()

	missing := httptest.NewRequest(http.MethodPost, "/webhook/slack", strings.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, missing)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing signature status = %d body=%s", rec.Code, rec.Body.String())
	}

	bad := httptest.NewRequest(http.MethodPost, "/webhook/slack", strings.NewReader(body))
	bad.Header.Set("X-Slack-Request-Timestamp", ts)
	bad.Header.Set("X-Slack-Signature", "v0=deadbeef")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, bad)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad signature status = %d body=%s", rec.Code, rec.Body.String())
	}

	valid := httptest.NewRequest(http.MethodPost, "/webhook/slack", strings.NewReader(body))
	valid.Header.Set("X-Slack-Request-Timestamp", ts)
	valid.Header.Set("X-Slack-Signature", slackSignature(secret, ts, body))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, valid)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("valid signature status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestWebhookHandlerRejectsForgedTelegramWebhook(t *testing.T) {
	secret := "telegram-webhook-secret"
	handler := telegramWebhookTestHandler(t, secret)
	body := fmt.Sprintf(`{"update_id":123,"message":{"message_id":42,"from":{"id":111,"is_bot":false,"first_name":"Alice"},"chat":{"id":222,"type":"private"},"date":%d,"text":"hello"}}`, time.Now().Unix())

	missing := httptest.NewRequest(http.MethodPost, "/webhook/telegram", strings.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, missing)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing token status = %d body=%s", rec.Code, rec.Body.String())
	}

	bad := httptest.NewRequest(http.MethodPost, "/webhook/telegram", strings.NewReader(body))
	bad.Header.Set("X-Telegram-Bot-Api-Secret-Token", "wrong")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, bad)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad token status = %d body=%s", rec.Code, rec.Body.String())
	}

	valid := httptest.NewRequest(http.MethodPost, "/webhook/telegram", strings.NewReader(body))
	valid.Header.Set("X-Telegram-Bot-Api-Secret-Token", secret)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, valid)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("valid token status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func slackWebhookTestHandler(t *testing.T, secret string) http.Handler {
	t.Helper()
	registry := channels.NewAdapterRegistry()
	if err := registry.Register(slack.New("")); err != nil {
		t.Fatalf("register slack: %v", err)
	}
	validator := channels.NewAntiSpoofValidatorWithSecrets(channels.SignatureSecrets{SlackSigningSecret: secret})
	return webhookHandler(registry, validator, testLogger())
}

func telegramWebhookTestHandler(t *testing.T, secret string) http.Handler {
	t.Helper()
	registry := channels.NewAdapterRegistry()
	if err := registry.Register(telegram.New("")); err != nil {
		t.Fatalf("register telegram: %v", err)
	}
	validator := channels.NewAntiSpoofValidatorWithSecrets(channels.SignatureSecrets{TelegramBotToken: secret})
	return webhookHandler(registry, validator, testLogger())
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func slackWebhookBody() (string, string) {
	ts := fmt.Sprintf("%d.000000", time.Now().Unix())
	body := fmt.Sprintf(`{"type":"message","user":"U01","text":"hello","channel":"C01","ts":%q}`, ts)
	return body, strings.Split(ts, ".")[0]
}

func slackSignature(secret, ts, body string) string {
	baseString := "v0:" + ts + ":" + body
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(baseString))
	return "v0=" + hex.EncodeToString(mac.Sum(nil))
}
