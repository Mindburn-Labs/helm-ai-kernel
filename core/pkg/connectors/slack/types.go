// Package slack provides the HELM connector for Slack API interactions.
//
// Architecture:
//   - types.go:     Request/response types for Slack operations
//   - client.go:    HTTP client for Slack API (stub implementation)
//   - connector.go: High-level connector composing client + ZeroTrust + ProofGraph
//
// Per HELM Standard v1.2: every Slack action becomes an
// INTENT -> EFFECT chain in the ProofGraph DAG.
package slack

import "time"

// SendMessageRequest is the request to send a message to a Slack channel.
type SendMessageRequest struct {
	ChannelID string `json:"channel_id"`
	Text      string `json:"text"`
	ThreadTS  string `json:"thread_ts,omitempty"`
}

// SendMessageResponse is the response after sending a message.
type SendMessageResponse struct {
	MessageTS string `json:"message_ts"`
	ChannelID string `json:"channel_id"`
}

// ChannelMessage represents a single message in a Slack channel.
type ChannelMessage struct {
	MessageTS string    `json:"message_ts"`
	User      string    `json:"user"`
	Text      string    `json:"text"`
	Timestamp time.Time `json:"timestamp"`
}

// ReadChannelResponse is the response when reading channel messages.
type ReadChannelResponse struct {
	Messages []ChannelMessage `json:"messages"`
}

// Channel represents a Slack channel.
type Channel struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Topic       string `json:"topic"`
	MemberCount int    `json:"member_count"`
}

// ListChannelsResponse is the response when listing channels.
type ListChannelsResponse struct {
	Channels []Channel `json:"channels"`
}

// UpdateMessageRequest is the request to update a message.
type UpdateMessageRequest struct {
	ChannelID string `json:"channel_id"`
	MessageTS string `json:"message_ts"`
	Text      string `json:"text"`
}

// UpdateMessageResponse is the response after updating a message.
type UpdateMessageResponse struct {
	ChannelID string `json:"channel_id"`
	MessageTS string `json:"message_ts"`
	Text      string `json:"text"`
}

// intentPayload is the ProofGraph INTENT node payload for a Slack action.
type intentPayload struct {
	Type     string         `json:"type"`
	ToolName string         `json:"tool_name"`
	Params   map[string]any `json:"params,omitempty"`
}

// effectPayload is the ProofGraph EFFECT node payload after a Slack action.
type effectPayload struct {
	Type           string `json:"type"`
	ToolName       string `json:"tool_name"`
	ContentHash    string `json:"content_hash"`
	ProvenanceHash string `json:"provenance_hash,omitempty"`
}
