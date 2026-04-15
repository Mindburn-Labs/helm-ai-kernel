// Package gmail is a STUB connector. All public methods return "not connected"
// errors until a real Gmail API client ships. Tracked as roadmap item P2-04
// (marked-experimental connector set: Gmail + GCalendar + Polymarket + TimesFM).
// DO NOT depend on this package for production workloads.
package gmail

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// Client is the HTTP client for the Gmail API. STUB — see package doc.
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// NewClient creates a new Gmail API client.
func NewClient(baseURL string) *Client {
	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Send sends an email via the Gmail API.
func (c *Client) Send(_ context.Context, _ *SendRequest) (*SendResponse, error) {
	return nil, fmt.Errorf("gmail: client not connected (stub: configure OAuth2 credentials and Gmail API endpoint at %s)", c.baseURL)
}

// ReadThread reads a thread by ID from the Gmail API.
func (c *Client) ReadThread(_ context.Context, _ string) (*ThreadResponse, error) {
	return nil, fmt.Errorf("gmail: client not connected (stub: configure OAuth2 credentials and Gmail API endpoint at %s)", c.baseURL)
}

// ListThreads lists threads matching a query from the Gmail API.
func (c *Client) ListThreads(_ context.Context, _ string, _ int) (*ThreadListResponse, error) {
	return nil, fmt.Errorf("gmail: client not connected (stub: configure OAuth2 credentials and Gmail API endpoint at %s)", c.baseURL)
}

// CreateDraft creates a draft email via the Gmail API.
func (c *Client) CreateDraft(_ context.Context, _ *DraftRequest) (*DraftResponse, error) {
	return nil, fmt.Errorf("gmail: client not connected (stub: configure OAuth2 credentials and Gmail API endpoint at %s)", c.baseURL)
}
