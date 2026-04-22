package constitution

import (
	"sort"
	"strings"
)

// Aligner converts constitutional principles into HELM policy constraints.
type Aligner struct {
	categoryRules map[string][]PolicyConstraint
}

// NewAligner creates an Aligner initialized with default category-to-constraint mappings.
//
// Default rules per category:
//   - "safety"      -> deny high-risk actions without approval
//   - "privacy"     -> deny data exfiltration, require audit on data access
//   - "honesty"     -> audit all outputs for factual claims
//   - "fairness"    -> deny discriminatory actions
//   - "helpfulness" -> allow broad tool access (permissive)
func NewAligner() *Aligner {
	return &Aligner{
		categoryRules: map[string][]PolicyConstraint{
			"safety": {
				{
					Expression: `input.risk_level != "critical"`,
					Action:     "deny",
					Priority:   1,
				},
				{
					Expression: `input.risk_level != "high" || input.has_approval == true`,
					Action:     "require_approval",
					Priority:   2,
				},
			},
			"privacy": {
				{
					Expression: `!(input.action == "export" && input.contains_pii == true)`,
					Action:     "deny",
					Priority:   1,
				},
				{
					Expression: `input.action != "read" || input.data_classification != "restricted"`,
					Action:     "audit",
					Priority:   2,
				},
			},
			"honesty": {
				{
					Expression: `input.output_type != "factual_claim" || input.source_cited == true`,
					Action:     "audit",
					Priority:   3,
				},
			},
			"fairness": {
				{
					Expression: `!input.targets_protected_class`,
					Action:     "deny",
					Priority:   1,
				},
				{
					Expression: `input.decision_basis != "demographic"`,
					Action:     "deny",
					Priority:   2,
				},
			},
			"helpfulness": {
				{
					Expression: `true`,
					Action:     "audit",
					Priority:   10,
				},
			},
		},
	}
}

// Align converts a constitution into a set of policy constraints.
//
// For each principle it:
//  1. Looks up category default rules.
//  2. Applies principle-specific overrides if Constraints are specified.
//  3. Adjusts priority based on the principle's priority.
//  4. Returns constraints sorted by priority (highest/lowest number first = most important).
func (a *Aligner) Align(constitution *Constitution) ([]PolicyConstraint, error) {
	if constitution == nil {
		return nil, nil
	}

	var constraints []PolicyConstraint

	for _, pr := range constitution.Principles {
		if len(pr.Constraints) > 0 {
			// Principle specifies its own CEL expressions — use them directly.
			for i, expr := range pr.Constraints {
				constraints = append(constraints, PolicyConstraint{
					PrincipleID: pr.ID,
					Expression:  expr,
					Action:      inferAction(expr),
					Priority:    pr.Priority*100 + i,
				})
			}
			continue
		}

		// Fall back to category default rules.
		rules, ok := a.categoryRules[pr.Category]
		if !ok {
			// Unknown category — default to a deny-with-audit rule (fail-closed).
			constraints = append(constraints, PolicyConstraint{
				PrincipleID: pr.ID,
				Expression:  `false`,
				Action:      "deny",
				Priority:    pr.Priority * 100,
			})
			continue
		}

		for i, rule := range rules {
			constraints = append(constraints, PolicyConstraint{
				PrincipleID: rule.PrincipleID,
				Expression:  rule.Expression,
				Action:      rule.Action,
				Priority:    pr.Priority*100 + i,
			})
			// Bind the principle ID (category rules are templates without it).
			constraints[len(constraints)-1].PrincipleID = pr.ID
		}
	}

	// Sort by priority ascending (1 = highest importance).
	sort.Slice(constraints, func(i, j int) bool {
		return constraints[i].Priority < constraints[j].Priority
	})

	return constraints, nil
}

// Score evaluates how well a specific action aligns with a constitution.
//
// For each principle the scorer checks directional alignment:
//   - Safety principle + DENY on risky action  -> high score
//   - Helpfulness principle + DENY on safe action -> low score
//   - Conflicting signals are flagged as AlignmentConflicts
//
// The overall score is a priority-weighted average of per-principle scores.
func (a *Aligner) Score(constitution *Constitution, action, resource string, verdict string) *AlignmentScore {
	if constitution == nil || len(constitution.Principles) == 0 {
		return &AlignmentScore{OverallScore: 0}
	}

	scores := make(map[string]float64, len(constitution.Principles))
	var conflicts []AlignmentConflict
	var totalWeight float64

	isRisky := isRiskyAction(action, resource)
	isDeny := verdict == "DENY"
	isAllow := verdict == "ALLOW"

	for _, pr := range constitution.Principles {
		var score float64

		switch pr.Category {
		case "safety":
			if isRisky && isDeny {
				score = 1.0 // governance blocked a risky action — aligned with safety
			} else if isRisky && isAllow {
				score = 0.0 // governance allowed a risky action — misaligned
				conflicts = append(conflicts, AlignmentConflict{
					PrincipleID: pr.ID,
					Action:      action,
					Reason:      "governance allowed a risky action",
					Resolution:  "consider adding deny constraint for this action",
				})
			} else {
				score = 0.8 // non-risky action — mostly neutral
			}

		case "privacy":
			if isDataAction(action) && isDeny {
				score = 1.0
			} else if isDataAction(action) && isAllow {
				score = 0.3
				conflicts = append(conflicts, AlignmentConflict{
					PrincipleID: pr.ID,
					Action:      action,
					Reason:      "governance allowed data access without restriction",
					Resolution:  "consider requiring audit for data operations",
				})
			} else {
				score = 0.8
			}

		case "helpfulness":
			if !isRisky && isAllow {
				score = 1.0 // allowed a safe action — aligned with helpfulness
			} else if !isRisky && isDeny {
				score = 0.2 // denied a safe action — misaligned with helpfulness
				conflicts = append(conflicts, AlignmentConflict{
					PrincipleID: pr.ID,
					Action:      action,
					Reason:      "governance denied a low-risk action",
					Resolution:  "consider relaxing constraints for this action",
				})
			} else {
				score = 0.6 // risky action — helpfulness takes a back seat
			}

		case "honesty":
			// Honesty is about transparency, not about allow/deny.
			score = 0.7

		case "fairness":
			if isDiscriminatory(action) && isDeny {
				score = 1.0
			} else if isDiscriminatory(action) && isAllow {
				score = 0.0
			} else {
				score = 0.8
			}

		default:
			score = 0.5
		}

		scores[pr.ID] = score

		// Weight by inverse priority (priority 1 = most important = highest weight).
		weight := 1.0 / float64(pr.Priority)
		totalWeight += weight
	}

	// Compute weighted average.
	var weightedSum float64
	for _, pr := range constitution.Principles {
		weight := 1.0 / float64(pr.Priority)
		weightedSum += scores[pr.ID] * weight
	}

	overall := 0.0
	if totalWeight > 0 {
		overall = weightedSum / totalWeight
	}

	return &AlignmentScore{
		ConstitutionID:  constitution.ConstitutionID,
		OverallScore:    overall,
		PrincipleScores: scores,
		Conflicts:       conflicts,
	}
}

// isRiskyAction heuristically determines whether an action is high-risk.
func isRiskyAction(action, resource string) bool {
	riskyActions := []string{"delete", "execute", "deploy", "admin", "root", "sudo", "drop", "truncate"}
	lower := strings.ToLower(action)
	for _, r := range riskyActions {
		if strings.Contains(lower, r) {
			return true
		}
	}
	riskyResources := []string{"production", "database", "credentials", "secrets", "keys"}
	lowerRes := strings.ToLower(resource)
	for _, r := range riskyResources {
		if strings.Contains(lowerRes, r) {
			return true
		}
	}
	return false
}

// isDataAction checks if the action involves data access or export.
func isDataAction(action string) bool {
	dataActions := []string{"read", "export", "download", "query", "fetch", "extract"}
	lower := strings.ToLower(action)
	for _, d := range dataActions {
		if strings.Contains(lower, d) {
			return true
		}
	}
	return false
}

// isDiscriminatory checks if the action targets protected characteristics.
func isDiscriminatory(action string) bool {
	discriminatory := []string{"discriminat", "bias", "demographic", "profile_race", "profile_gender"}
	lower := strings.ToLower(action)
	for _, d := range discriminatory {
		if strings.Contains(lower, d) {
			return true
		}
	}
	return false
}

// inferAction guesses the appropriate governance action from a CEL expression.
func inferAction(expr string) string {
	lower := strings.ToLower(expr)
	if strings.Contains(lower, "deny") || strings.Contains(lower, "false") || strings.Contains(lower, "!=") {
		return "deny"
	}
	if strings.Contains(lower, "approv") {
		return "require_approval"
	}
	return "audit"
}
