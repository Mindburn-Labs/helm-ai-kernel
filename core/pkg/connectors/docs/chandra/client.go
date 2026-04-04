package chandra

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// Client is the HTTP client for the Chandra document intelligence API.
// In production this would authenticate against the real Chandra endpoint.
// The current implementation is a stub that returns structured errors.
type Client struct {
	apiKey     string
	baseURL    string
	httpClient *http.Client
}

// NewClient creates a new Chandra API client.
func NewClient(apiKey string) *Client {
	return &Client{
		apiKey:  apiKey,
		baseURL: "https://api.chandra.ai/v1",
		httpClient: &http.Client{
			Timeout: 120 * time.Second,
		},
	}
}

// NewClientWithBaseURL creates a new Chandra API client with a custom base URL.
// Intended for testing.
func NewClientWithBaseURL(apiKey, baseURL string) *Client {
	c := NewClient(apiKey)
	c.baseURL = baseURL
	return c
}

// ParseDocument submits a document URL for parsing and returns the result.
func (c *Client) ParseDocument(_ context.Context, _ *ParseRequest) (*ParseResult, error) {
	return nil, fmt.Errorf("chandra: client not connected (stub: configure API key and Chandra endpoint)")
}
