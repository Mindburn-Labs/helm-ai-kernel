package gcalendar

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// Client is the HTTP client for the Google Calendar API.
// In production, this would use real OAuth2 credentials and Calendar API endpoints.
// The current implementation is a stub that returns structured errors.
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// NewClient creates a new Google Calendar API client.
func NewClient(baseURL string) *Client {
	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// CreateEvent creates a new calendar event.
func (c *Client) CreateEvent(_ context.Context, _ *CreateEventRequest) (*CreateEventResponse, error) {
	return nil, fmt.Errorf("gcalendar: client not connected (stub: configure OAuth2 credentials and Calendar API endpoint at %s)", c.baseURL)
}

// ReadAvailability reads free/busy availability for a time range.
func (c *Client) ReadAvailability(_ context.Context, _ time.Time, _ time.Time) ([]AvailabilitySlot, error) {
	return nil, fmt.Errorf("gcalendar: client not connected (stub: configure OAuth2 credentials and Calendar API endpoint at %s)", c.baseURL)
}

// UpdateEvent updates an existing calendar event.
func (c *Client) UpdateEvent(_ context.Context, _ *UpdateEventRequest) (*UpdateEventResponse, error) {
	return nil, fmt.Errorf("gcalendar: client not connected (stub: configure OAuth2 credentials and Calendar API endpoint at %s)", c.baseURL)
}

// ListEvents lists calendar events within a time range.
func (c *Client) ListEvents(_ context.Context, _ time.Time, _ time.Time, _ int) (*ListEventsResponse, error) {
	return nil, fmt.Errorf("gcalendar: client not connected (stub: configure OAuth2 credentials and Calendar API endpoint at %s)", c.baseURL)
}
