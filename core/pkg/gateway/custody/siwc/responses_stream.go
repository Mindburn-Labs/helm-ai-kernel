package siwc

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

const (
	maxResponseStreamBytes = 8 << 20
	maxResponseEventBytes  = 2 << 20
	maxResponseEvents      = 16384
)

func responseHTTPFailure(response *http.Response, requestID string) error {
	raw, err := io.ReadAll(io.LimitReader(response.Body, (128<<10)+1))
	if err != nil || len(raw) > 128<<10 {
		return responseFailure("provider_failure", "", response.StatusCode, requestID)
	}
	fields, err := responseObject(raw)
	if err != nil {
		return responseFailure("provider_failure", "", response.StatusCode, requestID)
	}
	code, param := responseErrorFields(fields["error"])
	return responseFailure(code, param, response.StatusCode, requestID)
}

func responseErrorFields(raw json.RawMessage) (string, string) {
	fields, err := responseObject(raw)
	if err != nil {
		return "provider_failure", ""
	}
	var code, param string
	_ = json.Unmarshal(fields["code"], &code)
	_ = json.Unmarshal(fields["param"], &param)
	return code, param
}

func readResponseStream(ctx context.Context, body io.Reader, status int, requestID string) (Response, error) {
	limited := &io.LimitedReader{R: body, N: maxResponseStreamBytes + 1}
	scanner := bufio.NewScanner(limited)
	scanner.Buffer(make([]byte, 4096), maxResponseEventBytes)
	var event, responseID string
	var completed Response
	var data []string
	dataBytes, events := 0, 0
	fail := func(code string, cause error) (Response, error) {
		failure := responseFailure(code, "", status, requestID)
		failure.cause = cause
		return Response{}, failure
	}
	consume := func() (Response, bool, error) {
		if len(data) == 0 {
			event = ""
			return Response{}, false, nil
		}
		events++
		raw := strings.Join(data, "\n")
		data, dataBytes = nil, 0
		fields, err := responseObject([]byte(raw))
		if err != nil || events > maxResponseEvents {
			return Response{}, false, ErrResponseProtocol
		}
		var kind string
		if json.Unmarshal(fields["type"], &kind) != nil || !responseIdentifier(kind, true) || event != "" && event != kind {
			return Response{}, false, ErrResponseProtocol
		}
		event = ""
		// A completed event is staged until bounded EOF. A later failure keeps
		// its typed recovery; any other event contradicts the terminal result.
		if completed.ID != "" && kind != "error" && kind != "response.failed" && kind != "response.incomplete" {
			return Response{}, false, ErrResponseProtocol
		}
		switch kind {
		case "error":
			code, param := responseErrorFields(json.RawMessage(raw))
			return Response{}, false, responseFailure(code, param, status, requestID)
		case "response.failed":
			response, err := responseObject(fields["response"])
			if err != nil {
				return Response{}, false, ErrResponseProtocol
			}
			code, param := responseErrorFields(response["error"])
			return Response{}, false, responseFailure(code, param, status, requestID)
		case "response.incomplete":
			return Response{}, false, ErrResponseIncomplete
		case "response.created", "response.in_progress", "response.completed":
			response, err := responseObject(fields["response"])
			if err != nil {
				return Response{}, false, ErrResponseProtocol
			}
			var id, model, state string
			_ = json.Unmarshal(response["id"], &id)
			_ = json.Unmarshal(response["model"], &model)
			_ = json.Unmarshal(response["status"], &state)
			if !strings.HasPrefix(id, "resp_") || !responseIdentifier(id, false) || responseID != "" && responseID != id {
				return Response{}, false, ErrResponseProtocol
			}
			responseID = id
			if kind != "response.completed" {
				return Response{}, false, nil
			}
			var output []json.RawMessage
			if state != "completed" || !catalogText(model, 255) || strings.ContainsAny(model, " \t\r\n") ||
				json.Unmarshal(response["output"], &output) != nil || output == nil ||
				response["error"] != nil && strings.TrimSpace(string(response["error"])) != "null" ||
				response["incomplete_details"] != nil && strings.TrimSpace(string(response["incomplete_details"])) != "null" {
				return Response{}, false, ErrResponseProtocol
			}
			return Response{ID: id, Model: model, Body: fields["response"]}, true, nil
		}
		return Response{}, false, nil
	}
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return fail("response_interrupted", err)
		}
		if limited.N <= 0 {
			return fail("response_stream_too_large", ErrResponseProtocol)
		}
		line := scanner.Text()
		if line == "" {
			out, done, err := consume()
			if err != nil {
				if _, ok := err.(*ResponseFailure); ok {
					return Response{}, err
				}
				return fail("response_terminal_invalid", err)
			}
			if done {
				completed = out
			}
			continue
		}
		field, value, _ := strings.Cut(line, ":")
		value = strings.TrimPrefix(value, " ")
		switch field {
		case "event":
			if event != "" || !responseIdentifier(value, true) {
				return fail("response_event_invalid", ErrResponseProtocol)
			}
			event = value
		case "data":
			dataBytes += len(value) + 1
			if dataBytes > maxResponseEventBytes {
				return fail("response_event_too_large", ErrResponseProtocol)
			}
			data = append(data, value)
		}
	}
	if ctx.Err() != nil {
		return fail("response_interrupted", ctx.Err())
	}
	if scanner.Err() != nil {
		if errors.Is(scanner.Err(), bufio.ErrTooLong) {
			return fail("response_event_too_large", ErrResponseProtocol)
		}
		return fail("response_interrupted", ErrResponseInterrupted)
	}
	if limited.N <= 0 {
		return fail("response_stream_too_large", ErrResponseProtocol)
	}
	// A terminal event requires its SSE blank-line delimiter. EOF inside an
	// event, an interrupted suffix or a stream containing only deltas never
	// publishes a staged response. The HTTP client/context also bounds EOF wait.
	if len(data) == 0 && event == "" && completed.ID != "" {
		return completed, nil
	}
	return fail("response_missing_completion", ErrResponseIncomplete)
}
