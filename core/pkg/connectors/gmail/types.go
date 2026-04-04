// Package gmail provides the HELM connector for Gmail API interactions.
//
// Architecture:
//   - types.go:     Request/response types for Gmail operations
//   - client.go:    HTTP client for Gmail API (stub implementation)
//   - connector.go: High-level connector composing client + ZeroTrust + ProofGraph
//
// Per HELM Standard v1.2: every Gmail action becomes an
// INTENT -> EFFECT chain in the ProofGraph DAG.
package gmail

import "time"

// SendRequest is the request to send an email.
type SendRequest struct {
	To          []string     `json:"to"`
	Cc          []string     `json:"cc,omitempty"`
	Bcc         []string     `json:"bcc,omitempty"`
	Subject     string       `json:"subject"`
	Body        string       `json:"body"`
	ThreadID    string       `json:"thread_id,omitempty"`
	Attachments []Attachment `json:"attachments,omitempty"`
}

// SendResponse is the response after sending an email.
type SendResponse struct {
	MessageID string    `json:"message_id"`
	ThreadID  string    `json:"thread_id"`
	SentAt    time.Time `json:"sent_at"`
}

// ThreadResponse is the response when reading a thread.
type ThreadResponse struct {
	ThreadID string    `json:"thread_id"`
	Messages []Message `json:"messages"`
}

// Message represents a single email message.
type Message struct {
	MessageID string    `json:"message_id"`
	From      string    `json:"from"`
	Subject   string    `json:"subject"`
	Body      string    `json:"body"`
	Date      time.Time `json:"date"`
}

// ThreadListResponse is the response when listing threads.
type ThreadListResponse struct {
	Threads       []ThreadSummary `json:"threads"`
	NextPageToken string          `json:"next_page_token,omitempty"`
}

// ThreadSummary is a summary of a thread for listing purposes.
type ThreadSummary struct {
	ThreadID     string `json:"thread_id"`
	Subject      string `json:"subject"`
	Snippet      string `json:"snippet"`
	MessageCount int    `json:"message_count"`
}

// DraftRequest is the request to create a draft email.
type DraftRequest struct {
	To      []string `json:"to"`
	Subject string   `json:"subject"`
	Body    string   `json:"body"`
}

// DraftResponse is the response after creating a draft.
type DraftResponse struct {
	DraftID   string    `json:"draft_id"`
	CreatedAt time.Time `json:"created_at"`
}

// Attachment represents an email attachment.
type Attachment struct {
	Filename  string `json:"filename"`
	MimeType  string `json:"mime_type"`
	SizeBytes int64  `json:"size_bytes"`
}

// intentPayload is the ProofGraph INTENT node payload for a Gmail action.
type intentPayload struct {
	Type     string         `json:"type"`
	ToolName string         `json:"tool_name"`
	Params   map[string]any `json:"params,omitempty"`
}

// effectPayload is the ProofGraph EFFECT node payload after a Gmail action.
type effectPayload struct {
	Type           string `json:"type"`
	ToolName       string `json:"tool_name"`
	ContentHash    string `json:"content_hash"`
	ProvenanceHash string `json:"provenance_hash,omitempty"`
}
