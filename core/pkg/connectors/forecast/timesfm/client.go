// Package timesfm is a STUB connector. All public methods return "not connected"
// errors until a real TimesFM probabilistic forecasting API client ships. Tracked
// as roadmap item P2-04 (marked-experimental connector set). DO NOT depend on
// this package for production workloads.
package timesfm

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// Client is the HTTP client for the TimesFM probabilistic forecasting API.
// STUB — see package doc.
type Client struct {
	apiKey     string
	baseURL    string
	httpClient *http.Client
}

// NewClient creates a new TimesFM API client.
func NewClient(apiKey string) *Client {
	return &Client{
		apiKey:  apiKey,
		baseURL: "https://api.timesfm.ai/v1",
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// NewClientWithBaseURL creates a new TimesFM API client with a custom base URL.
// Intended for testing.
func NewClientWithBaseURL(apiKey, baseURL string) *Client {
	c := NewClient(apiKey)
	c.baseURL = baseURL
	return c
}

// Forecast requests a probabilistic forecast and returns the result.
func (c *Client) Forecast(_ context.Context, _ *ForecastRequest) (*ForecastResult, error) {
	return nil, fmt.Errorf("timesfm: client not connected (stub: configure API key and TimesFM endpoint)")
}
