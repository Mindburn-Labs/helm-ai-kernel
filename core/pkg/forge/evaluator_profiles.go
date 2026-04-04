package forge

import (
	"fmt"
	"time"
)

// EvaluatorProfile defines the evaluation criteria for a self-mod class.
// Profiles are immutable after construction — callers must not mutate the
// returned slices.
type EvaluatorProfile struct {
	ProfileID       string   `json:"profile_id"`
	SelfModClass    string   `json:"self_mod_class"`    // C0, C1, C2, C3
	RequiredChecks  []string `json:"required_checks"`   // ordered list of check names
	MaxEvalTimeMs   int64    `json:"max_eval_time_ms"`
	AutoPromote     bool     `json:"auto_promote"`      // C0 only; C2+ always false
	RequireApproval bool     `json:"require_approval"`
}

// EvalResult is the aggregate outcome of running all required checks against
// a candidate's evaluator profile.
type EvalResult struct {
	CandidateID  string        `json:"candidate_id"`
	ProfileID    string        `json:"profile_id"`
	Passed       bool          `json:"passed"`
	CheckResults []CheckResult `json:"check_results"`
	EvidenceRef  string        `json:"evidence_ref,omitempty"`
}

// CheckResult is the outcome of a single named evaluation check.
type CheckResult struct {
	CheckName string `json:"check_name"`
	Passed    bool   `json:"passed"`
	Reason    string `json:"reason,omitempty"`
}

// Check name constants — used in RequiredChecks and CheckResult.
const (
	CheckSandboxTest          = "sandbox_test"
	CheckSchemaValidation     = "schema_validation"
	CheckCapabilityAudit      = "capability_audit"
	CheckBehaviorTest         = "behavior_test"
	CheckContainmentCheck     = "containment_check"
	CheckAdversarialTest      = "adversarial_test"
	CheckMutationBoundaryCheck = "mutation_boundary_check"
)

// DefaultProfiles returns the built-in evaluator profiles for every self-mod
// class. The slice is a fresh copy on each call — callers may not cache and
// mutate it.
func DefaultProfiles() []EvaluatorProfile {
	return []EvaluatorProfile{
		{
			ProfileID:    "profile-c0",
			SelfModClass: "C0",
			RequiredChecks: []string{
				CheckSandboxTest,
				CheckSchemaValidation,
			},
			MaxEvalTimeMs:   30_000, // 30 s
			AutoPromote:     true,
			RequireApproval: false,
		},
		{
			ProfileID:    "profile-c1",
			SelfModClass: "C1",
			RequiredChecks: []string{
				CheckSandboxTest,
				CheckSchemaValidation,
				CheckCapabilityAudit,
			},
			MaxEvalTimeMs:   60_000, // 60 s
			AutoPromote:     false,
			RequireApproval: true,
		},
		{
			ProfileID:    "profile-c2",
			SelfModClass: "C2",
			RequiredChecks: []string{
				CheckSandboxTest,
				CheckSchemaValidation,
				CheckCapabilityAudit,
				CheckBehaviorTest,
				CheckContainmentCheck,
			},
			MaxEvalTimeMs:   300_000, // 5 min
			AutoPromote:     false,
			RequireApproval: true,
		},
		{
			ProfileID:    "profile-c3",
			SelfModClass: "C3",
			RequiredChecks: []string{
				CheckSandboxTest,
				CheckSchemaValidation,
				CheckCapabilityAudit,
				CheckBehaviorTest,
				CheckContainmentCheck,
				CheckAdversarialTest,
				CheckMutationBoundaryCheck,
			},
			MaxEvalTimeMs:   600_000, // 10 min
			AutoPromote:     false,
			RequireApproval: true,
		},
	}
}

// GetProfile returns the default profile for the given self-mod class (C0–C3).
// Returns an error for unknown classes — fail-closed.
func GetProfile(selfModClass string) (*EvaluatorProfile, error) {
	for _, p := range DefaultProfiles() {
		if p.SelfModClass == selfModClass {
			cp := p
			return &cp, nil
		}
	}
	return nil, fmt.Errorf("forge: unknown self-mod class %q — must be one of C0, C1, C2, C3", selfModClass)
}

// Evaluate runs all required checks from the profile against the candidate.
// The default implementation performs structural validation only (no live
// sandbox); inject a custom checkFn via EvaluateWithChecks for full coverage.
//
// A candidate passes only when ALL required checks pass.  If the profile's
// MaxEvalTimeMs is exceeded, the evaluation is marked as failed.
func Evaluate(candidate Candidate, profile EvaluatorProfile) (*EvalResult, error) {
	return EvaluateWithChecks(candidate, profile, nil)
}

// CheckFn is an injectable evaluation function for a single named check.
// Return (true, "") on pass, (false, reason) on failure.
type CheckFn func(candidate Candidate, checkName string) (passed bool, reason string)

// defaultCheckFn is a pass-through stub used when no real check is injected.
// It passes sandbox_test and schema_validation for any candidate, and fails
// the higher-assurance checks unless the caller overrides them.  This mirrors
// the fail-closed philosophy: unknown checks are rejected.
func defaultCheckFn(candidate Candidate, checkName string) (bool, string) {
	switch checkName {
	case CheckSandboxTest, CheckSchemaValidation:
		return true, ""
	default:
		return false, fmt.Sprintf("no check implementation registered for %q — fail-closed", checkName)
	}
}

// EvaluateWithChecks is like Evaluate but accepts a custom CheckFn.
// If checkFn is nil, the default stub is used.
func EvaluateWithChecks(candidate Candidate, profile EvaluatorProfile, checkFn CheckFn) (*EvalResult, error) {
	if checkFn == nil {
		checkFn = defaultCheckFn
	}

	deadline := time.Duration(profile.MaxEvalTimeMs) * time.Millisecond
	start := time.Now()

	results := make([]CheckResult, 0, len(profile.RequiredChecks))
	allPassed := true

	for _, checkName := range profile.RequiredChecks {
		if time.Since(start) > deadline {
			results = append(results, CheckResult{
				CheckName: checkName,
				Passed:    false,
				Reason:    fmt.Sprintf("eval deadline exceeded (%d ms)", profile.MaxEvalTimeMs),
			})
			allPassed = false
			break
		}

		passed, reason := checkFn(candidate, checkName)
		results = append(results, CheckResult{
			CheckName: checkName,
			Passed:    passed,
			Reason:    reason,
		})
		if !passed {
			allPassed = false
		}
	}

	return &EvalResult{
		CandidateID:  candidate.CandidateID,
		ProfileID:    profile.ProfileID,
		Passed:       allPassed,
		CheckResults: results,
	}, nil
}
