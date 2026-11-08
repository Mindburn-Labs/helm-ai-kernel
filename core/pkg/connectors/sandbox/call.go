package sandbox

// quantum_posture: this file moves bytes over the provider's TLS; it neither
// signs nor negotiates a key exchange, and no post-quantum claim is made.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// DefaultLimit bounds a provider answer (09-04).
const DefaultLimit int64 = 4 << 20

// Call is one provider request.
type Call struct {
	// Client is the HTTP client. DoJSON never follows a redirect, so a
	// credential is never replayed to another host.
	Client   *http.Client
	Provider string
	Method   string
	URL      string
	// Auth puts the credential on the request. It is the only place a key is
	// read; the key is not logged or put in an error.
	Auth func(*http.Request)
	// Body is JSON-encoded when not nil.
	Body any
	// RawBody, when not nil, is sent as application/octet-stream instead of
	// Body.
	RawBody []byte
	// Out receives a 2xx answer when not nil. A nil Out accepts any 2xx body.
	Out any
	// RawOut, when not nil, receives the 2xx answer bytes unparsed (still
	// bounded by Limit); Out is then ignored.
	RawOut *[]byte
	// Limit bounds the answer; zero means DefaultLimit.
	Limit int64
}

// DoJSON performs the call and classifies its failure.
func DoJSON(ctx context.Context, c Call) error {
	limit := c.Limit
	if limit <= 0 {
		limit = DefaultLimit
	}
	var body io.Reader
	contentType := "application/json"
	if c.RawBody != nil {
		body = bytes.NewReader(c.RawBody)
		contentType = "application/octet-stream"
	} else if c.Body != nil {
		raw, err := json.Marshal(c.Body)
		if err != nil {
			return &CallError{Provider: c.Provider, Detail: fmt.Sprintf("encoding the request: %v", err), Refused: true}
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, c.Method, c.URL, body)
	if err != nil {
		return &CallError{Provider: c.Provider, Detail: fmt.Sprintf("building the request: %v", err), Refused: true}
	}
	if c.Auth != nil {
		c.Auth(req)
	}
	if body != nil {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("Accept", "application/json")
	client := http.DefaultClient
	if c.Client != nil {
		client = c.Client
	}
	noRedirect := *client
	noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := noRedirect.Do(req)
	if err != nil {
		// The error text names the URL and the transport failure, never a header.
		return &CallError{Provider: c.Provider, Detail: fmt.Sprintf("%s %s: %v", c.Method, req.URL.Path, scrub(err))}
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.ContentLength > limit {
		return &CallError{Provider: c.Provider, Status: resp.StatusCode, TooLarge: true,
			Detail: fmt.Sprintf("%s %s: the answer exceeds %d bytes", c.Method, req.URL.Path, limit)}
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return &CallError{Provider: c.Provider, Status: resp.StatusCode, Drift: true,
			Detail: fmt.Sprintf("%s %s: reading the answer: %v", c.Method, req.URL.Path, scrub(err))}
	}
	if int64(len(raw)) > limit {
		return &CallError{Provider: c.Provider, Status: resp.StatusCode, TooLarge: true,
			Detail: fmt.Sprintf("%s %s: the answer exceeds %d bytes", c.Method, req.URL.Path, limit)}
	}
	switch status := resp.StatusCode; {
	case status >= 200 && status < 300:
		if c.RawOut != nil {
			*c.RawOut = raw
			return nil
		}
		if c.Out == nil {
			return nil
		}
		if err := json.Unmarshal(raw, c.Out); err != nil {
			return &CallError{Provider: c.Provider, Status: status, Drift: true,
				Detail: fmt.Sprintf("%s %s: the answer is not the expected JSON", c.Method, req.URL.Path)}
		}
		return nil
	case status >= 400 && status < 500:
		return &CallError{Provider: c.Provider, Status: status, Refused: true,
			Detail: fmt.Sprintf("%s %s: status %d", c.Method, req.URL.Path, status)}
	default:
		return &CallError{Provider: c.Provider, Status: status,
			Detail: fmt.Sprintf("%s %s: status %d", c.Method, req.URL.Path, status)}
	}
}

// scrub drops the URL a net/http error repeats, which can carry a query.
func scrub(err error) error {
	var ue interface{ Unwrap() error }
	if errors.As(err, &ue) && ue.Unwrap() != nil {
		return ue.Unwrap()
	}
	return err
}
