package tracing

import (
	"context"
	"net/http"

	"github.com/google/uuid"
)

// CorrelationID is an opaque token used to correlate requests across services.
type CorrelationID string

// correlationHeader is the canonical HTTP header name for correlation IDs.
const correlationHeader = "X-Helm-Correlation-ID"

// correlationContextKey is the unexported key used to store correlation IDs in
// a context. The struct type prevents collisions with other packages.
type correlationContextKey struct{}

// WithCorrelationID attaches a correlation ID to ctx and returns the derived context.
func WithCorrelationID(ctx context.Context, id CorrelationID) context.Context {
	return context.WithValue(ctx, correlationContextKey{}, id)
}

// GetCorrelationID extracts the correlation ID from ctx.
// The second return value is false when no ID is present.
func GetCorrelationID(ctx context.Context) (CorrelationID, bool) {
	id, ok := ctx.Value(correlationContextKey{}).(CorrelationID)
	return id, ok && id != ""
}

// NewCorrelationID generates a new cryptographically random correlation ID.
func NewCorrelationID() CorrelationID {
	return CorrelationID(uuid.New().String())
}

// IsValidCorrelationID reports whether v is a canonically formatted UUID
// (36-char, lowercase, hyphenated). Only canonical form is accepted:
// correlation IDs are compared as opaque strings downstream, so admitting
// aliases of the same UUID (uppercase, braced, urn-prefixed) would let one
// request appear under two identities.
func IsValidCorrelationID(v string) bool {
	u, err := uuid.Parse(v)
	return err == nil && u.String() == v
}

// AdoptOrMintFromHeaders implements the adopt-or-mint rule of the pilot
// business-telemetry contract (§2.2): a valid inbound X-Helm-Correlation-ID
// is adopted; anything else — absent, malformed, or non-canonical — is
// replaced with a freshly minted ID. The second return reports whether the
// inbound value was adopted. Validation is mandatory here: unvalidated
// adoption is an injection channel for unbounded attacker-chosen values.
func AdoptOrMintFromHeaders(headers http.Header) (CorrelationID, bool) {
	if v := headers.Get(correlationHeader); IsValidCorrelationID(v) {
		return CorrelationID(v), true
	}
	return NewCorrelationID(), false
}

// InjectHTTPHeaders writes the correlation ID from ctx into headers under the
// canonical X-Helm-Correlation-ID key. If no ID is present, the header is left
// unchanged.
func InjectHTTPHeaders(ctx context.Context, headers http.Header) {
	if id, ok := GetCorrelationID(ctx); ok {
		headers.Set(correlationHeader, string(id))
	}
}

// ExtractHTTPHeaders reads the correlation ID from headers.
// Returns (id, true) only when the header carries a canonically valid ID
// (see IsValidCorrelationID); malformed values are rejected as if absent.
func ExtractHTTPHeaders(headers http.Header) (CorrelationID, bool) {
	v := headers.Get(correlationHeader)
	if !IsValidCorrelationID(v) {
		return "", false
	}
	return CorrelationID(v), true
}
