package github

import (
	"net/http"
	"testing"
	"time"
)

func TestGraphQLEndpointUsesEnterpriseAPIPath(t *testing.T) {
	for _, tc := range []struct{ rest, want string }{
		{"https://api.github.com", "https://api.github.com/graphql"},
		{"https://ghe.example/api/v3", "https://ghe.example/api/graphql"},
		{"http://127.0.0.1:8080", "http://127.0.0.1:8080/graphql"},
	} {
		c := &client{a: New(WithBaseURL(tc.rest))}
		if got := c.graphqlURL(); got != tc.want {
			t.Errorf("GraphQL endpoint for %s = %s, want %s", tc.rest, got, tc.want)
		}
	}
}

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
