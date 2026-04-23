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

// InjectHTTPHeaders writes the correlation ID from ctx into headers under the
// canonical X-Helm-Correlation-ID key. If no ID is present, the header is left
// unchanged.
func InjectHTTPHeaders(ctx context.Context, headers http.Header) {
	if id, ok := GetCorrelationID(ctx); ok {
		headers.Set(correlationHeader, string(id))
	}
}

// ExtractHTTPHeaders reads the correlation ID from headers.
// Returns (id, true) when the header is present and non-empty.
func ExtractHTTPHeaders(headers http.Header) (CorrelationID, bool) {
	v := headers.Get(correlationHeader)
	if v == "" {
		return "", false
	}
	return CorrelationID(v), true
}
