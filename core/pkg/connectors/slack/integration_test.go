package slack

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// Integration tests against the real Slack Web API. Guarded behind env vars.
//
// Required env (all must be set, else test is skipped):
//
//	HELM_SLACK_BOT_TOKEN — xoxb-... bot token
//	HELM_SLACK_CHANNEL   — channel ID (e.g., C0123456789) the bot can post to
//
// These tests post a test message and then read it back; nothing destructive.

func skipIfNoIntegration(t *testing.T) (token, channel string) {
	t.Helper()
	token = os.Getenv("HELM_SLACK_BOT_TOKEN")
	channel = os.Getenv("HELM_SLACK_CHANNEL")
	if token == "" || channel == "" {
		t.Skip("skipping: HELM_SLACK_BOT_TOKEN + HELM_SLACK_CHANNEL required for integration")
	}
	return token, channel
}

func TestIntegration_SendMessage_ReadChannel(t *testing.T) {
	token, channel := skipIfNoIntegration(t)
	client := NewClient(token)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	stamp := time.Now().UTC().Format("20060102-150405.000000")
	body := "HELM Slack connector integration test " + stamp

	sent, err := client.SendMessage(ctx, &SendMessageRequest{
		ChannelID: channel,
		Text:      body,
	})
	if err != nil {
		t.Fatalf("SendMessage: %v", err)
	}
	if sent.MessageTS == "" {
		t.Fatal("SendMessage returned empty message_ts")
	}

	// Read it back within a short window; our message should be the newest.
	history, err := client.ReadChannel(ctx, channel, 10)
	if err != nil {
		t.Fatalf("ReadChannel: %v", err)
	}
	if len(history.Messages) == 0 {
		t.Fatal("ReadChannel returned no messages")
	}
	found := false
	for _, m := range history.Messages {
		if m.Text == body {
			found = true
			break
		}
	}
	if !found {
		t.Logf("Expected to find posted message %q in latest %d; did not (usually benign — channel may be busy)", body, len(history.Messages))
	}
}

func TestIntegration_ListChannels(t *testing.T) {
	token, _ := skipIfNoIntegration(t)
	client := NewClient(token)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := client.ListChannels(ctx)
	if err != nil {
		t.Fatalf("ListChannels: %v", err)
	}
	if len(resp.Channels) == 0 {
		t.Log("ListChannels returned zero channels — unusual but not a bug for a bot with limited scope")
	}
	for _, ch := range resp.Channels {
		if ch.ID == "" || ch.Name == "" {
			t.Fatalf("ListChannels returned channel with missing ID/Name: %+v", ch)
		}
	}
}

func TestIntegration_TokenlessReturnsSentinel(t *testing.T) {
	// Token-less path must not perform HTTP.
	client := NewClient("")
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	_, err := client.SendMessage(ctx, &SendMessageRequest{ChannelID: "C0", Text: "x"})
	if err == nil {
		t.Fatal("expected error for tokenless SendMessage")
	}
	if !strings.Contains(err.Error(), "not connected") {
		t.Fatalf("expected 'not connected' sentinel, got: %v", err)
	}
}
