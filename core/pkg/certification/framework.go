package certification

import (
	"fmt"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
)

// Framework evaluates agents against certification criteria and determines
// the highest certification level each agent qualifies for.
//
// Default criteria are initialized by NewFramework and can be overridden via
// SetCriteria. The evaluation is deterministic: given the same scores, the
// same result is always produced.
type Framework struct {
	criteria map[CertificationLevel]CertificationCriteria
	clock    func() time.Time
}

// NewFramework creates a Framework with default certification criteria.
//
// Default levels:
//
//	BRONZE:   trust >= 400, compliance >= 60,  7 days, max 10 violations
//	SILVER:   trust >= 600, compliance >= 80, 30 days, max  5 violations
//	GOLD:     trust >= 700, compliance >= 90, 60 days, max  2 violations, requires AIBOM
//	PLATINUM: trust >= 800, compliance >= 95, 90 days, max  0 violations, requires AIBOM + ZK proof
func NewFramework() *Framework {
	f := &Framework{
		criteria: make(map[CertificationLevel]CertificationCriteria),
		clock:    time.Now,
	}

	f.criteria[CertBronze] = CertificationCriteria{
		Level:              CertBronze,
		MinTrustScore:      400,
		MinComplianceScore: 60,
		MinObservationDays: 7,
		MaxViolations:      10,
		RequiresAIBOM:      false,
		RequiresZKProof:    false,
	}

	f.criteria[CertSilver] = CertificationCriteria{
		Level:              CertSilver,
		MinTrustScore:      600,
		MinComplianceScore: 80,
		MinObservationDays: 30,
		MaxViolations:      5,
		RequiresAIBOM:      false,
		RequiresZKProof:    false,
	}

	f.criteria[CertGold] = CertificationCriteria{
		Level:              CertGold,
		MinTrustScore:      700,
		MinComplianceScore: 90,
		MinObservationDays: 60,
		MaxViolations:      2,
		RequiresAIBOM:      true,
		RequiresZKProof:    false,
	}

	f.criteria[CertPlatinum] = CertificationCriteria{
		Level:              CertPlatinum,
		MinTrustScore:      800,
		MinComplianceScore: 95,
		MinObservationDays: 90,
		MaxViolations:      0,
		RequiresAIBOM:      true,
		RequiresZKProof:    true,
	}

	return f
}

// WithClock returns the Framework with a custom clock function.
// Primarily useful for deterministic testing.
func (f *Framework) WithClock(clock func() time.Time) *Framework {
	f.clock = clock
	return f
}

// SetCriteria overrides the criteria for a given certification level.
func (f *Framework) SetCriteria(level CertificationLevel, criteria CertificationCriteria) {
	criteria.Level = level
	f.criteria[level] = criteria
}

// GetCriteria returns the criteria for a given certification level.
// The second return value is false if the level has no criteria defined.
func (f *Framework) GetCriteria(level CertificationLevel) (CertificationCriteria, bool) {
	c, ok := f.criteria[level]
	return c, ok
}

// Evaluate determines the highest certification level an agent qualifies for.
//
// Levels are tested from highest (PLATINUM) to lowest (BRONZE). The first
// level whose criteria the agent meets becomes the result. If the agent does
// not meet any level, the result has Passed=false with the BRONZE criteria
// and a reason explaining what was not met.
func (f *Framework) Evaluate(agentID string, scores CertificationScores) *CertificationResult {
	now := f.clock()

	// Try levels from highest to lowest.
	for _, level := range certLevelsDescending {
		criteria, ok := f.criteria[level]
		if !ok {
			continue
		}

		if reason := f.checkCriteria(criteria, scores); reason == "" {
			result := &CertificationResult{
				ResultID:    fmt.Sprintf("cert-%s-%d", agentID, now.UnixNano()),
				AgentID:     agentID,
				Level:       level,
				Passed:      true,
				Criteria:    criteria,
				Scores:      scores,
				EvaluatedAt: now,
			}
			result.ContentHash = f.computeHash(result)
			return result
		}
	}

	// Agent does not meet any level. Return failure against BRONZE criteria.
	bronzeCriteria := f.criteria[CertBronze]
	failReason := f.checkCriteria(bronzeCriteria, scores)

	result := &CertificationResult{
		ResultID:    fmt.Sprintf("cert-%s-%d", agentID, now.UnixNano()),
		AgentID:     agentID,
		Level:       CertBronze,
		Passed:      false,
		Criteria:    bronzeCriteria,
		Scores:      scores,
		Reason:      failReason,
		EvaluatedAt: now,
	}
	result.ContentHash = f.computeHash(result)
	return result
}

// checkCriteria returns an empty string if scores meet criteria,
// or a human-readable reason describing the first unmet requirement.
func (f *Framework) checkCriteria(c CertificationCriteria, s CertificationScores) string {
	if s.TrustScore < c.MinTrustScore {
		return fmt.Sprintf("trust score %d below minimum %d for %s", s.TrustScore, c.MinTrustScore, c.Level)
	}
	if s.ComplianceScore < c.MinComplianceScore {
		return fmt.Sprintf("compliance score %d below minimum %d for %s", s.ComplianceScore, c.MinComplianceScore, c.Level)
	}
	if s.ObservationDays < c.MinObservationDays {
		return fmt.Sprintf("observation days %d below minimum %d for %s", s.ObservationDays, c.MinObservationDays, c.Level)
	}
	if s.ViolationCount > c.MaxViolations {
		return fmt.Sprintf("violation count %d exceeds maximum %d for %s", s.ViolationCount, c.MaxViolations, c.Level)
	}
	if c.RequiresAIBOM && !s.HasAIBOM {
		return fmt.Sprintf("AIBOM required for %s but not present", c.Level)
	}
	if c.RequiresZKProof && !s.HasZKProof {
		return fmt.Sprintf("ZK governance proof required for %s but not present", c.Level)
	}
	return ""
}

// computeHash computes the JCS canonical SHA-256 hash of a certification result.
// The ContentHash field is zeroed before hashing to avoid circular dependency.
func (f *Framework) computeHash(result *CertificationResult) string {
	// Create a copy with ContentHash cleared for hashing.
	hashable := *result
	hashable.ContentHash = ""

	hash, err := canonicalize.CanonicalHash(hashable)
	if err != nil {
		// This should never fail for a well-formed struct. If it does,
		// return a sentinel so the result is still usable but obviously unhashed.
		return "hash-error"
	}
	return hash
}
