package slack

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// Client is the HTTP client for the Slack API.
// In production, this would use a real bot token and Slack API endpoints.
// The current implementation is a stub that returns structured errors.
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
