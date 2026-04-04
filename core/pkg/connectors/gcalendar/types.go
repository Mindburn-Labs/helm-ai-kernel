// Package gcalendar provides the HELM connector for Google Calendar API interactions.
//
// Architecture:
//   - types.go:     Request/response types for Google Calendar operations
//   - client.go:    HTTP client for Google Calendar API (stub implementation)
//   - connector.go: High-level connector composing client + ZeroTrust + ProofGraph
//
// Per HELM Standard v1.2: every Google Calendar action becomes an
// INTENT -> EFFECT chain in the ProofGraph DAG.
package gcalendar

import "time"

// CreateEventRequest is the request to create a calendar event.
type CreateEventRequest struct {
	Title          string    `json:"title"`
	Description    string    `json:"description,omitempty"`
	StartTime      time.Time `json:"start_time"`
	EndTime        time.Time `json:"end_time"`
	AttendeeEmails []string  `json:"attendee_emails,omitempty"`
	Location       string    `json:"location,omitempty"`
}

// CreateEventResponse is the response after creating a calendar event.
type CreateEventResponse struct {
	EventID  string `json:"event_id"`
	HtmlLink string `json:"html_link"`
}

// AvailabilitySlot represents a time slot with free/busy status.
type AvailabilitySlot struct {
	Start  time.Time `json:"start"`
	End    time.Time `json:"end"`
	Status string    `json:"status"` // "free" or "busy"
}

// CalendarEvent represents a calendar event.
type CalendarEvent struct {
	EventID     string    `json:"event_id"`
	Title       string    `json:"title"`
	Description string    `json:"description,omitempty"`
	Start       time.Time `json:"start"`
	End         time.Time `json:"end"`
	Attendees   []string  `json:"attendees,omitempty"`
}

// ListEventsResponse is the response when listing calendar events.
type ListEventsResponse struct {
	Events []CalendarEvent `json:"events"`
}

// UpdateEventRequest is the request to update a calendar event.
type UpdateEventRequest struct {
	EventID        string    `json:"event_id"`
	Title          string    `json:"title,omitempty"`
	Description    string    `json:"description,omitempty"`
	StartTime      time.Time `json:"start_time,omitempty"`
	EndTime        time.Time `json:"end_time,omitempty"`
	AttendeeEmails []string  `json:"attendee_emails,omitempty"`
	Location       string    `json:"location,omitempty"`
}

// UpdateEventResponse is the response after updating a calendar event.
type UpdateEventResponse struct {
	EventID  string `json:"event_id"`
	HtmlLink string `json:"html_link"`
}

// intentPayload is the ProofGraph INTENT node payload for a Calendar action.
type intentPayload struct {
	Type     string         `json:"type"`
	ToolName string         `json:"tool_name"`
	Params   map[string]any `json:"params,omitempty"`
}

// effectPayload is the ProofGraph EFFECT node payload after a Calendar action.
type effectPayload struct {
	Type           string `json:"type"`
	ToolName       string `json:"tool_name"`
	ContentHash    string `json:"content_hash"`
	ProvenanceHash string `json:"provenance_hash,omitempty"`
}
