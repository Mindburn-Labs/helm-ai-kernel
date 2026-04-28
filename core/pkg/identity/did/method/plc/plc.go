// Package plc implements the did:plc DID method driver.
//
// did:plc DIDs are issued by a Public Ledger of Credentials directory
// service (default https://plc.directory). Resolution is an HTTP GET
// against the directory: GET <directory>/<did> returns the DID Document
// in JSON form.
//
// Reference: https://github.com/did-method-plc/did-method-plc

package plc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/identity/did"
)

// DefaultDirectoryURL is the production PLC directory.
const DefaultDirectoryURL = "https://plc.directory"

// HTTPClient is the minimum HTTP surface this driver needs.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// Driver implements did.Method for the did:plc method.
type Driver struct {
	directoryURL string
	client       HTTPClient
	timeout      time.Duration
}

// Option configures a did:plc Driver.
type Option func(*Driver)

// WithDirectoryURL overrides the default plc.directory URL.
func WithDirectoryURL(u string) Option {
	return func(d *Driver) { d.directoryURL = strings.TrimRight(u, "/") }
}

// WithHTTPClient injects an HTTPClient (e.g. for testing).
func WithHTTPClient(c HTTPClient) Option { return func(d *Driver) { d.client = c } }

// WithTimeout overrides the default 5-second request timeout.
func WithTimeout(t time.Duration) Option { return func(d *Driver) { d.timeout = t } }

// New returns a configured did:plc driver.
func New(opts ...Option) *Driver {
	d := &Driver{
		directoryURL: DefaultDirectoryURL,
		client:       http.DefaultClient,
		timeout:      5 * time.Second,
	}
	for _, opt := range opts {
		opt(d)
	}
	return d
}

// Name returns the method-specific name.
func (Driver) Name() string { return "plc" }

// Resolve fetches the DID Document from the configured PLC directory.
func (d *Driver) Resolve(ctx context.Context, didURI string) (*did.ResolvedDocument, error) {
	method, _, err := did.ParseDID(didURI)
	if err != nil {
		return nil, err
	}
	if method != "plc" {
		return nil, fmt.Errorf("did:plc: wrong method %q", method)
	}

	reqCtx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()

	url := d.directoryURL + "/" + didURI
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("did:plc: building request: %w", err)
	}
	req.Header.Set("Accept", "application/did+json, application/json")

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("did:plc: fetching %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("did:plc: %s returned status %d", url, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("did:plc: reading body: %w", err)
	}

	var doc did.ResolvedDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("did:plc: decoding document: %w", err)
	}

	if doc.ID == "" {
		return nil, errors.New("did:plc: document missing id")
	}
	if doc.ID != didURI {
		return nil, fmt.Errorf("did:plc: document id %q != requested %q", doc.ID, didURI)
	}
	return &doc, nil
}
