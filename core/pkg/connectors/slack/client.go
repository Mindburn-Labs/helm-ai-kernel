// Package slack is a STUB connector. All public methods return "not connected"
// errors until a real Slack API client ships (bot token auth, signed-request
// verification, event handling). Tracked as roadmap item P2-02 (real connector
// set: GitHub + Slack + Linear). DO NOT depend on this package for production
// workloads.
package slack

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// Client is the HTTP client for the Slack API. STUB — see package doc.
type Client struct {
	botToken   string
	httpClient *http.Client
}

// NewClient creates a new Slack API client.
func NewClient(botToken string) *Client {
	return &Client{
		botToken: botToken,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// SendMessage sends a message to a Slack channel.
func (c *Client) SendMessage(_ context.Context, _ *SendMessageRequest) (*SendMessageResponse, error) {
	return nil, fmt.Errorf("slack: client not connected (stub: configure bot token and Slack API endpoint)")
}

// ReadChannel reads recent messages from a Slack channel.
func (c *Client) ReadChannel(_ context.Context, _ string, _ int) (*ReadChannelResponse, error) {
	return nil, fmt.Errorf("slack: client not connected (stub: configure bot token and Slack API endpoint)")
}

// ListChannels lists available Slack channels.
func (c *Client) ListChannels(_ context.Context) (*ListChannelsResponse, error) {
	return nil, fmt.Errorf("slack: client not connected (stub: configure bot token and Slack API endpoint)")
}

// UpdateMessage updates an existing Slack message.
func (c *Client) UpdateMessage(_ context.Context, _ *UpdateMessageRequest) (*UpdateMessageResponse, error) {
	return nil, fmt.Errorf("slack: client not connected (stub: configure bot token and Slack API endpoint)")
}
