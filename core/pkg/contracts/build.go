package contracts

import "time"

// BuildInfo contains build metadata.
type BuildInfo struct {
	Timestamp string `json:"timestamp"`
	Commit    string `json:"commit"`
	GitCommit string `json:"git_commit"` // Alias
	Builder   string `json:"builder"`
	Step      string `json:"step"`
}

// Attempt represents a single attempt with timestamp and status.
type Attempt struct {
	AttemptID string    `json:"attempt_id"`
	Timestamp time.Time `json:"timestamp"`
	Success   bool      `json:"success"`
	Error     string    `json:"error,omitempty"`
}

// VerificationResult contains the result of a verification.
//
//nolint:govet // fieldalignment: struct layout is human-readable
type VerificationResult struct {
	Success         bool      `json:"success"`
	Details         string    `json:"details"`
	ObligationID    string    `json:"obligation_id"`
	Status          string    `json:"status"`
	VerifiedAt      time.Time `json:"verified_at"`
	CapturedAt      time.Time `json:"captured_at"`
	Healthy         bool      `json:"healthy"`
	ExternalStatus  string    `json:"external_status,omitempty"` // Added
	MissingReceipts []string  `json:"missing_receipts"`
	OrphanReceipts  []string  `json:"orphan_receipts"`
}

// ReconciliationReport contains reconciliation findings.
type ReconciliationReport struct {
	Healthy         bool     `json:"healthy"`
	MissingReceipts []string `json:"missing_receipts"`
	OrphanReceipts  []string `json:"orphan_receipts"`
	Mismatches      []string `json:"mismatches"`
}

// PolicyBundle represents a compiled set of policies.
type PolicyBundle struct {
	CompiledAt string   `json:"compiled_at"`
	Rules      []string `json:"rules"`
	Revision   string   `json:"revision"`
}
