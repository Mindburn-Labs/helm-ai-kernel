package github

import (
	"net/http"
	"time"
)

// Options only the qualification suite uses; helm-gateway builds the adapter
// with its defaults (WithBaseURL aside), so these are not shipped.

// WithHTTPClient replaces the HTTP client. The adapter still refuses to
// follow redirects: a moved repository is a different target.
func WithHTTPClient(c *http.Client) Option { return func(a *Adapter) { a.httpClient = c } }

// WithMaxResponseBytes sets one limit for every answer, comparisons included.
func WithMaxResponseBytes(n int64) Option {
	return func(a *Adapter) { a.maxResponseBytes, a.maxCompareBytes = n, n }
}

// WithClock sets the clock for Observation.observed_at.
func WithClock(now func() time.Time) Option { return func(a *Adapter) { a.now = now } }
