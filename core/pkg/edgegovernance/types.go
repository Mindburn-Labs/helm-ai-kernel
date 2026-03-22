// Package edgegovernance defines the public contracts for HELM's local-first edge governance.
//
// Edge governance enables HELM-governed execution in disconnected, offline, or
// latency-sensitive environments. This OSS package defines the runtime interface,
// offline policy linting, receipt normalization, and disconnected fallback modes.
package edgegovernance

import "time"

// EdgeMode defines the current connectivity state of the edge runtime.
type EdgeMode string

const (
	ModeConnected    EdgeMode = "CONNECTED"
	ModeDisconnected EdgeMode = "DISCONNECTED"
	ModeDegraded     EdgeMode = "DEGRADED"
)

// EdgeRuntime is the canonical interface for local governance execution.
type EdgeRuntime interface {
	// GetMode returns the current connectivity mode.
	GetMode() EdgeMode
	// EvaluateLocally runs a policy evaluation using cached truth.
	EvaluateLocally(req *LocalEvalRequest) (*LocalEvalResult, error)
	// SyncOnReconnect pushes cached receipts and pulls fresh truth.
	SyncOnReconnect() error
}

// LocalEvalRequest is the input for offline policy evaluation.
type LocalEvalRequest struct {
	RequestID     string         `json:"request_id"`
	PrincipalID   string         `json:"principal_id"`
	EffectTypes   []string       `json:"effect_types"`
	CachedEpoch   string         `json:"cached_epoch"`
	Context       map[string]any `json:"context,omitempty"`
	Timestamp     time.Time      `json:"timestamp"`
}

// LocalEvalResult is the output of offline policy evaluation.
type LocalEvalResult struct {
	RequestID   string   `json:"request_id"`
	Allowed     bool     `json:"allowed"`
	ReasonCodes []string `json:"reason_codes"`
	CachedEpoch string   `json:"cached_epoch"`
	Degraded    bool     `json:"degraded"` // True if using stale truth
	ContentHash string   `json:"content_hash"`
}

// LintResult is the output of offline policy linting.
type LintResult struct {
	PolicyRef  string        `json:"policy_ref"`
	Valid      bool          `json:"valid"`
	Warnings   []LintWarning `json:"warnings,omitempty"`
	Errors     []LintError   `json:"errors,omitempty"`
}

// LintWarning is a non-blocking policy lint finding.
type LintWarning struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Line    int    `json:"line,omitempty"`
}

// LintError is a blocking policy lint finding.
type LintError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Line    int    `json:"line,omitempty"`
}

// PolicyLinter validates policies offline without network access.
type PolicyLinter interface {
	Lint(policyContent []byte) (*LintResult, error)
}
