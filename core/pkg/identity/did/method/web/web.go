// Package web implements the did:web DID method driver.
//
// did:web maps a DID to an HTTPS-resolvable URL containing the DID
// Document. The DID `did:web:example.com:agents:alice` becomes the URL
// `https://example.com/agents/alice/did.json`. The bare-host form
// `did:web:example.com` resolves to `https://example.com/.well-known/did.json`.
//
// Reference: https://w3c-ccg.github.io/did-method-web/

package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/identity/did"
)

// HTTPClient is the minimum HTTP surface this driver needs. The standard
// http.Client already satisfies it; tests inject a stub.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// Driver implements did.Method for the did:web method.
type Driver struct {
	client  HTTPClient
	timeout time.Duration
	scheme  string // overridable for testing (default "https")
}

// Option configures a did:web Driver.
type Option func(*Driver)

// WithHTTPClient injects an HTTPClient (e.g. for testing).
func WithHTTPClient(c HTTPClient) Option { return func(d *Driver) { d.client = c } }

// WithTimeout overrides the default 5-second request timeout.
func WithTimeout(t time.Duration) Option { return func(d *Driver) { d.timeout = t } }

// WithScheme overrides the URL scheme. Production callers should leave
// this at "https"; tests use "http" against an httptest.Server.
func WithScheme(s string) Option { return func(d *Driver) { d.scheme = s } }

// New returns a configured did:web driver. The default timeout is 5s and
// the default HTTP client is `http.DefaultClient`.
func New(opts ...Option) *Driver {
	d := &Driver{
		client:  http.DefaultClient,
		timeout: 5 * time.Second,
		scheme:  "https",
	}
	for _, opt := range opts {
		opt(d)
	}
	return d
}

// Name returns the method-specific name.
func (Driver) Name() string { return "web" }

// Resolve performs the network fetch and JSON-decodes the document.
func (d *Driver) Resolve(ctx context.Context, didURI string) (*did.ResolvedDocument, error) {
	u, err := didToURL(didURI, d.scheme)
	if err != nil {
		return nil, err
	}

	reqCtx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("did:web: building request: %w", err)
	}
	req.Header.Set("Accept", "application/did+json, application/json")

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("did:web: fetching %s: %w", u, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("did:web: %s returned status %d", u, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MiB ceiling
	if err != nil {
		return nil, fmt.Errorf("did:web: reading body: %w", err)
	}

	var doc did.ResolvedDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("did:web: decoding document: %w", err)
	}

	if doc.ID == "" {
		return nil, errors.New("did:web: document missing id")
	}
	if doc.ID != didURI {
		return nil, fmt.Errorf("did:web: document id %q != requested %q", doc.ID, didURI)
	}
	return &doc, nil
}

// didToURL maps a did:web DID to the HTTPS URL of its document.
//
// Per the spec, colon-separated path segments map to '/' in the URL, and
// the bare-host form maps to the .well-known location.
func didToURL(didURI, scheme string) (string, error) {
	method, identifier, err := did.ParseDID(didURI)
	if err != nil {
		return "", err
	}
	if method != "web" {
		return "", fmt.Errorf("did:web: wrong method %q", method)
	}

	parts := strings.Split(identifier, ":")
	host, err := url.PathUnescape(parts[0])
	if err != nil || host == "" {
		return "", fmt.Errorf("did:web: invalid host segment %q", parts[0])
	}

	var path string
	if len(parts) == 1 {
		path = "/.well-known/did.json"
	} else {
		segments := make([]string, len(parts)-1)
		for i, seg := range parts[1:] {
			s, err := url.PathUnescape(seg)
			if err != nil || s == "" {
				return "", fmt.Errorf("did:web: invalid path segment %q", seg)
			}
			segments[i] = url.PathEscape(s)
		}
		path = "/" + strings.Join(segments, "/") + "/did.json"
	}

	return scheme + "://" + host + path, nil
}
