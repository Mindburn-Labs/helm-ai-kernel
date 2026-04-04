// Package last30days — schemas.go re-exports the core output types for use
// by external validators (e.g., JSON Schema generators, OpenAPI tooling, or
// evidence-pack attestors) without requiring callers to import the full pack.
package last30days

// The following type aliases make the public API surface explicit and allow
// external packages to reference the types without embedding business logic.

// DigestSchema is an alias for Digest, provided so that schema generators
// can reference the output structure by a stable, intention-revealing name.
type DigestSchema = Digest

// SynthesisSchema is an alias for Synthesis.
type SynthesisSchema = Synthesis

// ConvergenceSignalSchema is an alias for ConvergenceSignal.
type ConvergenceSignalSchema = ConvergenceSignal

// ItemSchema is an alias for Item.
type ItemSchema = Item

// EngagementSchema is an alias for Engagement.
type EngagementSchema = Engagement

// ValidStances lists all accepted values for Item.Stance.
var ValidStances = []string{"bullish", "bearish", "neutral", "unknown"}
