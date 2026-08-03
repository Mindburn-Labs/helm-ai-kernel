// Package correlation carries the product request identity of the pilot
// business-telemetry contract (§2.2): one opaque ID that joins a request
// across services, receipts and evidence.
//
// It deliberately depends on nothing but the standard library and a UUID
// implementation. Reading an ID out of a context is not a tracing concern, and
// the packages that do it — the policy engine, the executor — should not
// inherit an OpenTelemetry SDK and an OTLP exporter to do it.
//
// The contract keeps this identity separate from the OTel identity (§3):
// correlation_id survives sampling and is stamped onto receipts, while
// trace_id/span_id are infrastructure identity that may be dropped. Anything
// needing the latter belongs in pkg/tracing, not here.
package correlation

import (
	"context"
	"net/http"

	"github.com/google/uuid"
)

// ID is an opaque token used to correlate a request across services.
type ID string

// Header is the canonical HTTP header name for correlation IDs.
const Header = "X-Helm-Correlation-ID"

// contextKey is the unexported key used to store correlation IDs in a
// context. The struct type prevents collisions with other packages.
type contextKey struct{}

// With attaches a correlation ID to ctx and returns the derived context.
func With(ctx context.Context, id ID) context.Context {
	return context.WithValue(ctx, contextKey{}, id)
}

// From extracts the correlation ID from ctx. The second return value is false
// when no ID is present.
func From(ctx context.Context) (ID, bool) {
	id, ok := ctx.Value(contextKey{}).(ID)
	return id, ok && id != ""
}

// New generates a new cryptographically random correlation ID.
func New() ID {
	return ID(uuid.New().String())
}

// IsValid reports whether v is a canonically formatted UUID (36-char,
// lowercase, hyphenated). Only canonical form is accepted: correlation IDs are
// compared as opaque strings downstream, so admitting aliases of the same UUID
// (uppercase, braced, urn-prefixed) would let one request appear under two
// identities.
func IsValid(v string) bool {
	u, err := uuid.Parse(v)
	return err == nil && u.String() == v
}

// AdoptOrMint implements the adopt-or-mint rule of the contract (§2.2): a
// valid inbound X-Helm-Correlation-ID is adopted; anything else — absent,
// malformed, or non-canonical — is replaced with a freshly minted ID. The
// second return reports whether the inbound value was adopted.
//
// Validation is mandatory here: unvalidated adoption is an injection channel
// for unbounded attacker-chosen values.
func AdoptOrMint(headers http.Header) (ID, bool) {
	if v := headers.Get(Header); IsValid(v) {
		return ID(v), true
	}
	return New(), false
}

// Inject writes the correlation ID from ctx into headers under the canonical
// key. If no ID is present, the headers are left unchanged.
func Inject(ctx context.Context, headers http.Header) {
	if id, ok := From(ctx); ok {
		headers.Set(Header, string(id))
	}
}

// Extract reads the correlation ID from headers. Returns (id, true) only when
// the header carries a canonically valid ID; malformed values are rejected as
// if absent.
func Extract(headers http.Header) (ID, bool) {
	v := headers.Get(Header)
	if !IsValid(v) {
		return "", false
	}
	return ID(v), true
}
