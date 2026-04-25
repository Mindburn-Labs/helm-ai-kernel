// Package slack provides a HELM connector for the Slack Web API.
//
// This file implements a real Slack Web API client (slack.com/api/*).
//
// Two construction modes:
//   - NewClient(botToken)         — if botToken == "", all calls return
//     "not connected" sentinels (backward-compat for unit tests).
//   - NewClient(realBotToken)     — authenticated Bearer-token calls with
//     rate-limit handling, retry on 429/5xx, and Slack's ok=false error shape.
//
// Supported endpoints (HELM tool → API method):
//   - slack.send_message  → chat.postMessage
//   - slack.read_channel  → conversations.history
//   - slack.list_channels → conversations.list
//   - slack.update_message→ chat.update
package slack

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// slackAPIBase is the root of the Slack Web API.
const slackAPIBase = "https://slack.com/api"

// userAgent identifies HELM on requests to slack.com.
const userAgent = "helm-oss/0.4.0 (+https://github.com/Mindburn-Labs/helm-oss)"

// maxRetries bounds transient-failure retries for 5xx / 429.
const maxRetries = 3

// Client is an HTTP client for the Slack Web API.
// When constructed with an empty botToken via NewClient, all methods return
// a sentinel "not connected" error (preserving token-less unit tests).
type Client struct {
	botToken   string
	baseURL    string
	httpClient *http.Client
	userAgent  string
}

// NewClient creates a new Slack Web API client.
// If botToken is empty, all methods return "not connected" errors — safe for
// unit tests. For real API access, pass a bot or user token (xoxb-/xoxp-).
func NewClient(botToken string) *Client {
	return &Client{
		botToken: botToken,
		baseURL:  slackAPIBase,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		userAgent: userAgent,
	}
}

// SendMessage sends a message to a Slack channel.
func (c *Client) SendMessage(ctx context.Context, req *SendMessageRequest) (*SendMessageResponse, error) {
	if c.botToken == "" {
		return nil, fmt.Errorf("slack: client not connected (configure bot token and Slack API endpoint)")
	}
	if req == nil {
		return nil, errors.New("slack: SendMessage: nil request")
	}
	if req.ChannelID == "" {
		return nil, errors.New("slack: SendMessage: channel_id required")
	}
	if req.Text == "" {
		return nil, errors.New("slack: SendMessage: text required")
	}

	payload := map[string]any{
		"channel": req.ChannelID,
		"text":    req.Text,
	}
	if req.ThreadTS != "" {
		payload["thread_ts"] = req.ThreadTS
	}

	var raw struct {
		Channel string `json:"channel"`
		TS      string `json:"ts"`
	}
	if err := c.doJSON(ctx, http.MethodPost, "chat.postMessage", payload, nil, &raw); err != nil {
		return nil, err
	}
	return &SendMessageResponse{MessageTS: raw.TS, ChannelID: raw.Channel}, nil
}

// ReadChannel reads recent messages from a Slack channel.
// `limit` caps the number of messages returned (Slack caps at 1000).
func (c *Client) ReadChannel(ctx context.Context, channelID string, limit int) (*ReadChannelResponse, error) {
	if c.botToken == "" {
		return nil, fmt.Errorf("slack: client not connected (configure bot token and Slack API endpoint)")
	}
	if channelID == "" {
		return nil, errors.New("slack: ReadChannel: channel_id required")
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}

	q := url.Values{}
	q.Set("channel", channelID)
	q.Set("limit", strconv.Itoa(limit))

	var raw struct {
		Messages []struct {
			TS   string `json:"ts"`
			User string `json:"user"`
			Text string `json:"text"`
		} `json:"messages"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "conversations.history", nil, q, &raw); err != nil {
		return nil, err
	}

	out := &ReadChannelResponse{Messages: make([]ChannelMessage, 0, len(raw.Messages))}
	for _, m := range raw.Messages {
		ts := parseSlackTS(m.TS)
		out.Messages = append(out.Messages, ChannelMessage{
			MessageTS: m.TS,
			User:      m.User,
			Text:      m.Text,
			Timestamp: ts,
		})
	}
	return out, nil
}

// ListChannels lists available Slack channels visible to the bot.
func (c *Client) ListChannels(ctx context.Context) (*ListChannelsResponse, error) {
	if c.botToken == "" {
		return nil, fmt.Errorf("slack: client not connected (configure bot token and Slack API endpoint)")
	}

	// Slack's conversations.list is paginated via cursor. We collect up to 4
	// pages (~4000 channels) to keep memory bounded.
	const maxPages = 4
	out := &ListChannelsResponse{Channels: make([]Channel, 0, 32)}
	cursor := ""
	for page := 0; page < maxPages; page++ {
		q := url.Values{}
		q.Set("types", "public_channel,private_channel")
		q.Set("limit", "1000")
		if cursor != "" {
			q.Set("cursor", cursor)
		}

		var raw struct {
			Channels []struct {
				ID    string `json:"id"`
				Name  string `json:"name"`
				Topic struct {
					Value string `json:"value"`
				} `json:"topic"`
				NumMembers int `json:"num_members"`
			} `json:"channels"`
			ResponseMetadata struct {
				NextCursor string `json:"next_cursor"`
			} `json:"response_metadata"`
		}
		if err := c.doJSON(ctx, http.MethodGet, "conversations.list", nil, q, &raw); err != nil {
			return nil, err
		}
		for _, ch := range raw.Channels {
			out.Channels = append(out.Channels, Channel{
				ID:          ch.ID,
				Name:        ch.Name,
				Topic:       ch.Topic.Value,
				MemberCount: ch.NumMembers,
			})
		}
		cursor = raw.ResponseMetadata.NextCursor
		if cursor == "" {
			break
		}
	}
	return out, nil
}

// UpdateMessage updates an existing Slack message.
func (c *Client) UpdateMessage(ctx context.Context, req *UpdateMessageRequest) (*UpdateMessageResponse, error) {
	if c.botToken == "" {
		return nil, fmt.Errorf("slack: client not connected (configure bot token and Slack API endpoint)")
	}
	if req == nil {
		return nil, errors.New("slack: UpdateMessage: nil request")
	}
	if req.ChannelID == "" || req.MessageTS == "" {
		return nil, errors.New("slack: UpdateMessage: channel_id and message_ts required")
	}
	if req.Text == "" {
		return nil, errors.New("slack: UpdateMessage: text required")
	}

	payload := map[string]any{
		"channel": req.ChannelID,
		"ts":      req.MessageTS,
		"text":    req.Text,
	}

	var raw struct {
		Channel string `json:"channel"`
		TS      string `json:"ts"`
		Text    string `json:"text"`
	}
	if err := c.doJSON(ctx, http.MethodPost, "chat.update", payload, nil, &raw); err != nil {
		return nil, err
	}
	return &UpdateMessageResponse{
		ChannelID: raw.Channel,
		MessageTS: raw.TS,
		Text:      raw.Text,
	}, nil
}

// APIError is a structured error from the Slack API.
// Slack's HTTP layer returns 200 almost always; errors surface in the JSON
// body as `"ok": false, "error": "<code>"`. APIError wraps both.
type APIError struct {
	StatusCode int
	ErrorCode  string // Slack's error code ("channel_not_found", "invalid_auth", etc.)
	Warning    string // Slack warning on successful responses (e.g. deprecated args)
	Needed     string // scopes Slack says the token needs but lacks
	Provided   string // scopes the token actually has
	RetryAfter time.Duration
	RawBody    string
}

func (e *APIError) Error() string {
	if e == nil {
		return ""
	}
	if e.Needed != "" || e.Provided != "" {
		return fmt.Sprintf("slack api: %d: %s (missing_scope; needed=%q provided=%q)",
			e.StatusCode, e.ErrorCode, e.Needed, e.Provided)
	}
	return fmt.Sprintf("slack api: %d: %s", e.StatusCode, e.ErrorCode)
}

// doJSON performs an authenticated request against the Slack Web API.
//   - method: "GET" or "POST"
//   - apiMethod: the Slack method name, e.g. "chat.postMessage".
//   - body: JSON body for POST (nil for GET).
//   - query: URL query values for GET (nil for POST).
//   - out: pointer to struct for JSON decoding (nil if caller doesn't need body).
//
// Slack's API always returns 200 on the HTTP layer for authenticated calls;
// errors are in the JSON body as `"ok": false, "error": "<code>"`. This
// function surfaces those as *APIError.
func (c *Client) doJSON(ctx context.Context, method, apiMethod string, body any, query url.Values, out any) error {
	endpoint := c.baseURL + "/" + apiMethod
	if method == http.MethodGet && len(query) > 0 {
		endpoint += "?" + query.Encode()
	}

	var bodyBytes []byte
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal request body: %w", err)
		}
		bodyBytes = b
	}

	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, method, endpoint, readerOrNil(bodyBytes))
		if err != nil {
			return fmt.Errorf("build request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+c.botToken)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", c.userAgent)
		if bodyBytes != nil {
			req.Header.Set("Content-Type", "application/json; charset=utf-8")
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("transport error: %w", err)
			if !shouldRetry(attempt) {
				return lastErr
			}
			time.Sleep(backoff(attempt))
			continue
		}
		respBody, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			lastErr = fmt.Errorf("read response body: %w", readErr)
			if !shouldRetry(attempt) {
				return lastErr
			}
			time.Sleep(backoff(attempt))
			continue
		}

		// 429 (rate limit) — Slack sets Retry-After in seconds.
		if resp.StatusCode == http.StatusTooManyRequests {
			wait := retryAfter(resp)
			lastErr = &APIError{
				StatusCode: resp.StatusCode,
				ErrorCode:  "rate_limited",
				RetryAfter: wait,
				RawBody:    string(respBody),
			}
			if !shouldRetry(attempt) {
				return lastErr
			}
			if wait > 60*time.Second {
				wait = 60 * time.Second
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(wait):
			}
			continue
		}

		// 5xx — server error; retry with backoff.
		if resp.StatusCode >= 500 && resp.StatusCode <= 599 {
			lastErr = &APIError{
				StatusCode: resp.StatusCode,
				ErrorCode:  "server_error",
				RawBody:    string(respBody),
			}
			if !shouldRetry(attempt) {
				return lastErr
			}
			time.Sleep(backoff(attempt))
			continue
		}

		// 2xx — check Slack's `"ok"` field.
		var envelope struct {
			OK       bool   `json:"ok"`
			Error    string `json:"error,omitempty"`
			Warning  string `json:"warning,omitempty"`
			Needed   string `json:"needed,omitempty"`
			Provided string `json:"provided,omitempty"`
		}
		if err := json.Unmarshal(respBody, &envelope); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
		if !envelope.OK {
			// Slack sometimes signals retryable errors via "error":"ratelimited"
			// outside of a 429 status. Surface as retryable if so.
			if envelope.Error == "ratelimited" && shouldRetry(attempt) {
				time.Sleep(5 * time.Second)
				continue
			}
			return &APIError{
				StatusCode: resp.StatusCode,
				ErrorCode:  envelope.Error,
				Warning:    envelope.Warning,
				Needed:     envelope.Needed,
				Provided:   envelope.Provided,
				RawBody:    string(respBody),
			}
		}

		// Decode into caller's out if requested.
		if out != nil && len(respBody) > 0 {
			if err := json.Unmarshal(respBody, out); err != nil {
				return fmt.Errorf("decode response: %w", err)
			}
		}
		return nil
	}

	if lastErr == nil {
		lastErr = errors.New("slack: retries exhausted without a definitive result")
	}
	return lastErr
}

// parseSlackTS turns a Slack timestamp ("1234567890.123456") into time.Time.
// Returns zero time on parse failure.
func parseSlackTS(ts string) time.Time {
	// Slack timestamps are "<seconds>.<microseconds_with_fraction>".
	parts := strings.SplitN(ts, ".", 2)
	secs, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return time.Time{}
	}
	var nsec int64
	if len(parts) == 2 {
		// Micro + extra suffix that Slack appends for uniqueness; take first 6.
		us := parts[1]
		if len(us) > 6 {
			us = us[:6]
		}
		if n, err := strconv.ParseInt(us, 10, 64); err == nil {
			nsec = n * 1000 // micros → nanos
		}
	}
	return time.Unix(secs, nsec).UTC()
}

// retryAfter returns the delay for a 429 response.
func retryAfter(resp *http.Response) time.Duration {
	if s := resp.Header.Get("Retry-After"); s != "" {
		if secs, err := strconv.Atoi(s); err == nil && secs > 0 {
			return time.Duration(secs) * time.Second
		}
	}
	return 5 * time.Second
}

// backoff returns exponential backoff for the given attempt index.
func backoff(attempt int) time.Duration {
	return 500 * time.Millisecond << attempt
}

func shouldRetry(attempt int) bool { return attempt < maxRetries-1 }

func readerOrNil(b []byte) io.Reader {
	if len(b) == 0 {
		return nil
	}
	return bytes.NewReader(b)
}
