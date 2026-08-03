package tracing

import (
	"context"
	"net/http"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/correlation"
)

// The correlation identity moved to pkg/correlation, which depends on nothing
// but the standard library and a UUID implementation (HELM-460). Reading an ID
// out of a context is not a tracing concern, and importing it from here made
// the policy engine and the executor inherit an OpenTelemetry SDK and an OTLP
// exporter for a single map lookup.
//
// Everything below forwards to that package and exists only so consumers
// pinned to this import path keep compiling. CorrelationID is a type *alias*,
// not a definition, so the two names denote the same type and values cross the
// boundary freely.
//
// New code should import pkg/correlation directly.

// CorrelationID is an opaque token used to correlate requests across services.
//
// Deprecated: use correlation.ID.
type CorrelationID = correlation.ID

// WithCorrelationID attaches a correlation ID to ctx.
//
// Deprecated: use correlation.With.
func WithCorrelationID(ctx context.Context, id CorrelationID) context.Context {
	return correlation.With(ctx, id)
}

// GetCorrelationID extracts the correlation ID from ctx.
//
// Deprecated: use correlation.From.
func GetCorrelationID(ctx context.Context) (CorrelationID, bool) {
	return correlation.From(ctx)
}

// NewCorrelationID generates a new cryptographically random correlation ID.
//
// Deprecated: use correlation.New.
func NewCorrelationID() CorrelationID {
	return correlation.New()
}

// IsValidCorrelationID reports whether v is a canonically formatted UUID.
//
// Deprecated: use correlation.IsValid.
func IsValidCorrelationID(v string) bool {
	return correlation.IsValid(v)
}

// AdoptOrMintFromHeaders implements the adopt-or-mint rule of the pilot
// business-telemetry contract (§2.2).
//
// Deprecated: use correlation.AdoptOrMint.
func AdoptOrMintFromHeaders(headers http.Header) (CorrelationID, bool) {
	return correlation.AdoptOrMint(headers)
}

// InjectHTTPHeaders writes the correlation ID from ctx into headers.
//
// Deprecated: use correlation.Inject.
func InjectHTTPHeaders(ctx context.Context, headers http.Header) {
	correlation.Inject(ctx, headers)
}

// ExtractHTTPHeaders reads a canonically valid correlation ID from headers.
//
// Deprecated: use correlation.Extract.
func ExtractHTTPHeaders(headers http.Header) (CorrelationID, bool) {
	return correlation.Extract(headers)
}
