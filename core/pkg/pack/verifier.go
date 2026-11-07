// Package pack provides verification pipeline for pack integrity.
// Per Section 4.2 - verifies pack signatures, content hashes, and dependencies.
package pack

import (
	"time"
)

// Verifier provides pack verification capabilities.
type Verifier struct {
	registry     PackRegistry
	trustAnchors []TrustAnchor
}

// TrustAnchor represents a trusted signing identity.
type TrustAnchor struct {
	AnchorID   string    `json:"anchor_id"`
	Name       string    `json:"name"`
	PublicKey  string    `json:"public_key"`
	ValidFrom  time.Time `json:"valid_from"`
	ValidUntil time.Time `json:"valid_until"`
	TrustLevel int       `json:"trust_level"` // 1-5
}

// VerificationRequest specifies what to verify.
type VerificationRequest struct {
	RequestID string              `json:"request_id"`
	Packs     []ResolvedPack      `json:"packs"`
	Options   VerificationOptions `json:"options"`
}

// VerificationOptions controls verification behavior.
type VerificationOptions struct {
	MinimumTrustScore float64        `json:"min_trust_score"`
	RequiredChecks    []string       `json:"required_checks"` // e.g., ["signature", "coverage"]
	RequiredDrills    []string       `json:"required_drills"` // e.g., ["drill-network-partition"]
	TrustAnchors      map[string]int `json:"trust_anchors"`   // ID -> TrustLevel
}

// VerificationResult is the outcome of pack verification.
type VerificationResult struct {
	ResultID    string              `json:"result_id"`
	RequestID   string              `json:"request_id"`
	VerifiedAt  time.Time           `json:"verified_at"`
	Status      VerificationStatus  `json:"status"`
	PackResults []PackVerification  `json:"pack_results"`
	Summary     VerificationSummary `json:"summary"`
}

// VerificationStatus is the overall verification status.
type VerificationStatus string

const (
	VerificationPassed  VerificationStatus = "passed"
	VerificationFailed  VerificationStatus = "failed"
	VerificationPartial VerificationStatus = "partial"
)

// PackVerification is the verification result for a single pack.
type PackVerification struct {
	PackID        string             `json:"pack_id"`
	PackName      string             `json:"pack_name"`
	Version       string             `json:"version"`
	Checks        []CheckResult      `json:"checks"`
	OverallStatus VerificationStatus `json:"overall_status"`
	TrustScore    float64            `json:"trust_score"` // 0.0 - 1.0
}

// CheckResult is the result of a single verification check.
type CheckResult struct {
	CheckType CheckType `json:"check_type"`
	Passed    bool      `json:"passed"`
	Message   string    `json:"message"`
	Details   string    `json:"details,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// CheckType identifies the type of check.
type CheckType string

const (
	CheckSignature    CheckType = "signature"
	CheckContentHash  CheckType = "content_hash"
	CheckDependencies CheckType = "dependencies"
	CheckSecPolicy    CheckType = "security_policy"
	CheckIntegrity    CheckType = "integrity"
)

// VerificationSummary provides high-level statistics.
type VerificationSummary struct {
	TotalPacks    int     `json:"total_packs"`
	PassedPacks   int     `json:"passed_packs"`
	FailedPacks   int     `json:"failed_packs"`
	TotalChecks   int     `json:"total_checks"`
	PassedChecks  int     `json:"passed_checks"`
	FailedChecks  int     `json:"failed_checks"`
	AvgTrustScore float64 `json:"avg_trust_score"`
}
