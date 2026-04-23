// Package certification implements the HELM Agent Certification Framework.
//
// HELM acts as a certification authority for agent capabilities. Agents are
// evaluated against tiered criteria (Bronze through Platinum) based on their
// behavioral trust score, compliance score, observation period, violation
// history, and governance artifacts (AIBOM, ZK proofs).
//
// Certified agents receive W3C Verifiable Credential badges issued via the
// vcredentials package, creating a cryptographically verifiable chain of trust
// from observed behavior to certified capability.
//
// All certification results are content-addressed using JCS (RFC 8785)
// canonicalization for deterministic, cross-platform verification.
package certification

import "time"

// CertificationLevel defines the tier of certification achieved.
type CertificationLevel string

const (
	// CertBronze requires basic compliance: minimum trust and compliance scores
	// with a short observation period.
	CertBronze CertificationLevel = "BRONZE"

	// CertSilver requires sustained reliability: higher trust/compliance scores
	// and a longer observation period with fewer violations.
	CertSilver CertificationLevel = "SILVER"

	// CertGold requires full governance: high trust/compliance scores, extended
	// observation, minimal violations, and an AI Bill of Materials.
	CertGold CertificationLevel = "GOLD"

	// CertPlatinum requires the highest standard: near-perfect scores, extended
	// observation, zero violations, AIBOM, and ZK governance proof.
	CertPlatinum CertificationLevel = "PLATINUM"
)

// certLevelsDescending lists certification levels from highest to lowest.
// Used by the framework to find the highest qualifying level.
var certLevelsDescending = []CertificationLevel{
	CertPlatinum,
	CertGold,
	CertSilver,
	CertBronze,
}

// CertificationCriteria defines what is needed for a given certification level.
type CertificationCriteria struct {
	Level              CertificationLevel `json:"level"`
	MinTrustScore      int                `json:"min_trust_score"`      // Minimum behavioral trust score (0-1000)
	MinComplianceScore int                `json:"min_compliance_score"` // Minimum compliance score (0-100)
	MinObservationDays int                `json:"min_observation_days"` // Minimum observation period in days
	MaxViolations      int                `json:"max_violations"`       // Maximum policy violations allowed
	RequiresAIBOM      bool               `json:"requires_aibom"`       // Must have AI Bill of Materials
	RequiresZKProof    bool               `json:"requires_zk_proof"`    // Must have ZK governance proof
}

// CertificationScores captures the current measured scores for an agent.
type CertificationScores struct {
	TrustScore      int  `json:"trust_score"`      // Behavioral trust score (0-1000)
	ComplianceScore int  `json:"compliance_score"` // Compliance score (0-100)
	ObservationDays int  `json:"observation_days"` // Days under observation
	ViolationCount  int  `json:"violation_count"`  // Number of policy violations
	HasAIBOM        bool `json:"has_aibom"`        // Whether agent has an AIBOM
	HasZKProof      bool `json:"has_zk_proof"`     // Whether agent has ZK governance proof
}

// CertificationResult is the output of a certification evaluation.
type CertificationResult struct {
	ResultID    string                `json:"result_id"`
	AgentID     string                `json:"agent_id"`
	Level       CertificationLevel    `json:"level"`
	Passed      bool                  `json:"passed"`
	Criteria    CertificationCriteria `json:"criteria"`
	Scores      CertificationScores   `json:"scores"`
	Reason      string                `json:"reason,omitempty"`
	EvaluatedAt time.Time             `json:"evaluated_at"`
	ContentHash string                `json:"content_hash"`
}
