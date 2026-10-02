package siwc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"slices"
	"strings"
	"time"
)

const maxResponseRequestBytes = 2 << 20

// Response retains only a completed provider response. Body includes the full
// output items needed in the next request's input; it is untrusted model data,
// not a HELM accepted result, authority record or provider invoice.
type Response struct {
	ID             string          `json:"id"`
	Model          string          `json:"model"`
	RequestedModel string          `json:"requested_model"`
	RequestID      string          `json:"request_id,omitempty"`
	Body           json.RawMessage `json:"response"`
}

// Responses performs one fixed-endpoint, account-specific request. Its gateway
// caller must resolve the current owner-bound CP Connection and perform ordinary
// HELM admission first. No organization grant, reservation or retry is created
// here. Failure always returns a zero Response, including after partial output.
func (s *Store) Responses(ctx context.Context, c *Client, ref Reference, body json.RawMessage) (Response, error) {
	if s == nil || c == nil || c.http == nil {
		return Response{}, ErrUnavailable
	}
	body = slices.Clone(body)
	model, err := validateResponseRequest(body)
	if err != nil {
		return Response{}, err
	}
	models, err := s.Models(ctx, c, ref)
	if err != nil {
		return Response{}, err
	}
	if !slices.ContainsFunc(models, func(m Model) bool { return m.Slug == model }) {
		return Response{}, ErrPermission
	}
	token, err := s.AccessToken(ctx, c, ref)
	if err != nil {
		return Response{}, err
	}
	if err = s.responseAccountCurrent(ctx, c, ref); err != nil {
		return Response{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.responsesURL, bytes.NewReader(body))
	if err != nil {
		return Response{}, ErrResponseRequest
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")
	client := *c.http
	client.Timeout = 2 * time.Minute
	response, err := client.Do(req)
	if err != nil {
		failure := responseFailure("response_transport_failed", "", 0, "")
		failure.cause = ErrResponseInterrupted
		if ctx.Err() != nil {
			failure.cause = ctx.Err()
		}
		return Response{}, failure
	}
	defer func() { _ = response.Body.Close() }()
	requestID := response.Header.Get("X-Request-Id")
	if !responseIdentifier(requestID, true) {
		requestID = ""
	}
	if response.StatusCode != http.StatusOK {
		return Response{}, responseHTTPFailure(response, requestID)
	}
	// The live SIWC route can omit Content-Type. Its body must still be a
	// bounded, valid SSE stream with a complete terminal response. A declared
	// incompatible media type is rejected; HTTP 200 itself proves nothing.
	if contentType := response.Header.Get("Content-Type"); contentType != "" {
		mediaType, _, parseErr := mime.ParseMediaType(contentType)
		if parseErr != nil || mediaType != "text/event-stream" {
			failure := responseFailure("response_media_type_invalid", "", response.StatusCode, requestID)
			failure.cause = ErrResponseProtocol
			return Response{}, failure
		}
	}
	out, err := readResponseStream(ctx, response.Body, response.StatusCode, requestID)
	if err != nil {
		return Response{}, err
	}
	if err := s.responseAccountCurrent(ctx, c, ref); err != nil {
		code := "response_account_check_failed"
		if errors.Is(err, ErrChanged) {
			code = "response_account_changed"
		} else if ctx.Err() != nil {
			code = "response_interrupted"
		}
		failure := responseFailure(code, "", response.StatusCode, requestID)
		failure.cause = err
		return Response{}, failure
	}
	out.RequestedModel, out.RequestID = model, requestID
	return out, nil
}

func (s *Store) responseAccountCurrent(ctx context.Context, c *Client, ref Reference) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	unlock, err := s.lock(ctx, ref.ID)
	if err != nil {
		return err
	}
	defer unlock()
	current, err := s.load(ref.ID)
	if err != nil {
		return err
	}
	if current.Reference() != ref || current.Issuer != c.issuer || !current.SignedIn || !current.PlanUse {
		return ErrChanged
	}
	return ctx.Err()
}

func validateResponseRequest(body []byte) (string, error) {
	if len(body) == 0 || len(body) > maxResponseRequestBytes {
		return "", ErrResponseRequest
	}
	fields, err := responseObject(body)
	if err != nil {
		return "", ErrResponseRequest
	}
	var model string
	var store, stream *bool
	var input []json.RawMessage
	if json.Unmarshal(fields["model"], &model) != nil || !catalogText(model, 255) || strings.ContainsAny(model, " \t\r\n") ||
		json.Unmarshal(fields["store"], &store) != nil || store == nil || *store ||
		json.Unmarshal(fields["stream"], &stream) != nil || stream == nil || !*stream ||
		json.Unmarshal(fields["input"], &input) != nil || len(input) == 0 {
		return "", ErrResponseRequest
	}
	for _, name := range []string{"background", "conversation", "max_output_tokens", "max_tool_calls", "metadata", "moderation", "multi_agent", "prompt", "prompt_cache_retention", "safety_identifier", "temperature", "top_logprobs", "top_p", "truncation", "user", "previous_response_id"} {
		if _, exists := fields[name]; exists {
			return "", ErrResponseRequest
		}
	}
	for _, item := range input {
		fields, err := responseObject(item)
		if err != nil {
			return "", ErrResponseRequest
		}
		var role string
		_ = json.Unmarshal(fields["role"], &role)
		if role == "system" {
			return "", ErrResponseRequest
		}
	}
	return model, nil
}

// Reject duplicate envelope fields instead of interpreting the same bytes in
// two ways. Nested tool/content data remains provider-validated, untrusted data.
func responseObject(body []byte) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, ErrResponseProtocol
	}
	fields := make(map[string]json.RawMessage)
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, ErrResponseProtocol
		}
		name, ok := token.(string)
		if !ok {
			return nil, ErrResponseProtocol
		}
		if _, duplicate := fields[name]; duplicate {
			return nil, ErrResponseProtocol
		}
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return nil, ErrResponseProtocol
		}
		fields[name] = value
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') || decoder.Decode(new(any)) != io.EOF {
		return nil, ErrResponseProtocol
	}
	return fields, nil
}
