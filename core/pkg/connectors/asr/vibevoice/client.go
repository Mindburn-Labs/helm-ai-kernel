// Package vibevoice is a STUB connector. All public methods return "not connected"
// errors until a real VibeVoice ASR API client ships. Tracked as roadmap item
// P2-04 (marked-experimental connector set). DO NOT depend on this package for
// production workloads.
package vibevoice

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// Client is the HTTP client for the VibeVoice ASR API. STUB — see package doc.
type Client struct {
	apiKey     string
	baseURL    string
	httpClient *http.Client
}

// NewClient creates a new VibeVoice API client.
func NewClient(apiKey string) *Client {
	return &Client{
		apiKey:  apiKey,
		baseURL: "https://api.vibevoice.ai/v1",
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
}

// NewClientWithBaseURL creates a new VibeVoice API client with a custom base URL.
// Intended for testing.
func NewClientWithBaseURL(apiKey, baseURL string) *Client {
	c := NewClient(apiKey)
	c.baseURL = baseURL
	return c
}

// Transcribe submits an audio URL for transcription and returns the result.
func (c *Client) Transcribe(_ context.Context, _ *TranscriptionRequest) (*TranscriptionResult, error) {
	return nil, fmt.Errorf("vibevoice: client not connected (stub: configure API key and VibeVoice endpoint)")
}
