// Package conform implements the HELM Conformance Standard v1.0 engine.
//
// It enumerates and runs gates deterministically, emits EvidencePacks,
// and signs conformance reports. Every action emits a cryptographic receipt.
package conform

import "time"

// Gate is the interface every conformance gate must implement.
// Each gate produces a GateResult containing pass/fail, reason codes,
// evidence paths, and timing metrics.
type Gate interface {
	// ID returns the stable gate identifier (e.g. "G0", "G1").
	ID() string

	// Name returns a human-readable name.
	Name() string

	// Run executes the gate check against the given RunContext.
	// It MUST NOT panic; all failures are expressed via GateResult.
	Run(ctx *RunContext) *GateResult
}

// GateResult is the §6.1 gate output contract.
type GateResult struct {
	GateID        string         `json:"gate_id"`
	Pass          bool           `json:"pass"`
	Reasons       []string       `json:"reasons"`
	EvidencePaths []string       `json:"evidence_paths"`
	Metrics       GateMetrics    `json:"metrics"`
	Details       map[string]any `json:"details,omitempty"`
}

// GateMetrics captures timing and count data per gate.
type GateMetrics struct {
	DurationMs int64          `json:"duration_ms"`
	Counts     map[string]int `json:"counts,omitempty"`
}

// RunContext provides the runtime context for gate execution.
type RunContext struct {
	RunID        string
	Profile      ProfileID
	Jurisdiction string
	EvidenceDir  string // Root of the EvidencePack directory
	ArtifactsDir string // Root of the project artifacts
	ProjectRoot  string // Root of the HELM project
	Clock        func() time.Time
	ExtraConfig  map[string]any
}
