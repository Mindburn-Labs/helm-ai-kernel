// Package correlation carries the product request identity of the pilot
// business-telemetry contract (§2.2): one opaque ID that joins a request
// across services, receipts and evidence.
//
// It deliberately depends on nothing but the standard library and a UUID
// implementation. Reading an ID out of a context is not a tracing concern, and
// the packages that do it — the policy engine, the executor — should not
// inherit an OpenTelemetry SDK and an OTLP exporter to do it (HELM-460).
//
// The contract keeps this identity separate from the OTel identity (§3):
// correlation_id survives sampling and is stamped onto receipts, while
// trace_id/span_id are infrastructure identity that may be dropped. Anything
// needing the latter belongs in pkg/tracing, not here.
//
// Subpackages group the authority-to-evidence correlation engines, which
// correlate observed host activity back to governed decisions — a different
// sense of "correlation" than the request identity above, and deliberately
// kept out of this package's dependency-free root.
package correlation
