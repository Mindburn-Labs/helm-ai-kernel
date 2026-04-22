package constitution_test

import (
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/constitution"
)

func safetyConstitution() *constitution.Constitution {
	return &constitution.Constitution{
		ConstitutionID: "const-safety",
		AgentID:        "agent-safe",
		Version:        "1.0.0",
		Principles: []constitution.Principle{
			{
				ID:          "p-safe",
				Name:        "Avoid harm",
				Description: "Do not take actions that could cause harm",
				Priority:    1,
				Category:    "safety",
			},
		},
	}
}

func privacyConstitution() *constitution.Constitution {
	return &constitution.Constitution{
		ConstitutionID: "const-privacy",
		AgentID:        "agent-priv",
		Version:        "1.0.0",
		Principles: []constitution.Principle{
			{
				ID:          "p-priv",
				Name:        "Protect privacy",
				Description: "Never expose personal data",
				Priority:    1,
				Category:    "privacy",
			},
		},
	}
}

func helpfulConstitution() *constitution.Constitution {
	return &constitution.Constitution{
		ConstitutionID: "const-helpful",
		AgentID:        "agent-help",
		Version:        "1.0.0",
		Principles: []constitution.Principle{
			{
				ID:          "p-help",
				Name:        "Be helpful",
				Description: "Assist users effectively",
				Priority:    1,
				Category:    "helpfulness",
			},
		},
	}
}

func TestAligner_AlignSafety(t *testing.T) {
	a := constitution.NewAligner()
	constraints, err := a.Align(safetyConstitution())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(constraints) == 0 {
		t.Fatal("expected at least one constraint for safety category")
	}

	// Safety category should produce deny rules.
	hasDeny := false
	for _, c := range constraints {
		if c.Action == "deny" {
			hasDeny = true
		}
		if c.PrincipleID != "p-safe" {
			t.Fatalf("expected principle ID p-safe, got %s", c.PrincipleID)
		}
	}
	if !hasDeny {
		t.Fatal("expected at least one deny constraint for safety")
	}
}

func TestAligner_AlignPrivacy(t *testing.T) {
	a := constitution.NewAligner()
	constraints, err := a.Align(privacyConstitution())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(constraints) == 0 {
		t.Fatal("expected at least one constraint for privacy category")
	}

	// Privacy category should produce audit rules.
	hasAudit := false
	for _, c := range constraints {
		if c.Action == "audit" {
			hasAudit = true
		}
		if c.PrincipleID != "p-priv" {
			t.Fatalf("expected principle ID p-priv, got %s", c.PrincipleID)
		}
	}
	if !hasAudit {
		t.Fatal("expected at least one audit constraint for privacy")
	}
}

func TestAligner_AlignHelpfulness(t *testing.T) {
	a := constitution.NewAligner()
	constraints, err := a.Align(helpfulConstitution())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(constraints) == 0 {
		t.Fatal("expected at least one constraint for helpfulness category")
	}

	// Helpfulness should produce permissive (audit) rules, not deny.
	for _, c := range constraints {
		if c.Action == "deny" {
			t.Fatalf("helpfulness should not produce deny constraints, got action=%s expr=%s", c.Action, c.Expression)
		}
	}
}

func TestAligner_Score(t *testing.T) {
	a := constitution.NewAligner()

	// Safety principle + DENY on risky action = high alignment.
	score := a.Score(safetyConstitution(), "delete", "production-database", "DENY")
	if score.OverallScore < 0.8 {
		t.Fatalf("expected high alignment score for deny on risky action, got %f", score.OverallScore)
	}

	principleScore, ok := score.PrincipleScores["p-safe"]
	if !ok {
		t.Fatal("expected score for principle p-safe")
	}
	if principleScore != 1.0 {
		t.Fatalf("expected perfect alignment for safety+deny+risky, got %f", principleScore)
	}
}

func TestAligner_ScoreConflict(t *testing.T) {
	a := constitution.NewAligner()

	// Constitution with both safety and helpfulness — denying a safe action
	// creates a conflict: safety is fine, helpfulness is not.
	c := &constitution.Constitution{
		ConstitutionID: "const-mixed",
		AgentID:        "agent-mixed",
		Version:        "1.0.0",
		Principles: []constitution.Principle{
			{
				ID:       "p-safe",
				Name:     "Safety first",
				Priority: 1,
				Category: "safety",
			},
			{
				ID:       "p-help",
				Name:     "Be helpful",
				Priority: 2,
				Category: "helpfulness",
			},
		},
	}

	// Deny a safe action — helpfulness should conflict.
	score := a.Score(c, "list_files", "documents", "DENY")

	if len(score.Conflicts) == 0 {
		t.Fatal("expected at least one conflict when denying a safe action with helpfulness principle")
	}

	foundHelpConflict := false
	for _, conflict := range score.Conflicts {
		if conflict.PrincipleID == "p-help" {
			foundHelpConflict = true
		}
	}
	if !foundHelpConflict {
		t.Fatal("expected helpfulness conflict")
	}
}

func TestAligner_PriorityOrdering(t *testing.T) {
	a := constitution.NewAligner()

	c := &constitution.Constitution{
		ConstitutionID: "const-multi",
		AgentID:        "agent-multi",
		Version:        "1.0.0",
		Principles: []constitution.Principle{
			{
				ID:       "p-low",
				Name:     "Low priority",
				Priority: 3,
				Category: "honesty",
			},
			{
				ID:       "p-high",
				Name:     "High priority",
				Priority: 1,
				Category: "safety",
			},
			{
				ID:       "p-mid",
				Name:     "Mid priority",
				Priority: 2,
				Category: "privacy",
			},
		},
	}

	constraints, err := a.Align(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(constraints) == 0 {
		t.Fatal("expected constraints")
	}

	// Verify sorted by priority ascending.
	for i := 1; i < len(constraints); i++ {
		if constraints[i].Priority < constraints[i-1].Priority {
			t.Fatalf("constraints not sorted by priority: %d < %d at index %d",
				constraints[i].Priority, constraints[i-1].Priority, i)
		}
	}

	// First constraint should come from the highest-priority principle (p-high / safety).
	if constraints[0].PrincipleID != "p-high" {
		t.Fatalf("expected first constraint from p-high, got %s", constraints[0].PrincipleID)
	}
}

func TestAligner_CustomConstraints(t *testing.T) {
	a := constitution.NewAligner()

	c := &constitution.Constitution{
		ConstitutionID: "const-custom",
		AgentID:        "agent-custom",
		Version:        "1.0.0",
		Principles: []constitution.Principle{
			{
				ID:       "p-custom",
				Name:     "Custom CEL rule",
				Priority: 1,
				Category: "safety",
				Constraints: []string{
					`input.tool != "rm"`,
					`input.path != "/etc/passwd"`,
				},
			},
		},
	}

	constraints, err := a.Align(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(constraints) != 2 {
		t.Fatalf("expected 2 custom constraints, got %d", len(constraints))
	}

	// Custom constraints should use the principle-provided expressions.
	if constraints[0].Expression != `input.tool != "rm"` {
		t.Fatalf("expected first expression input.tool != \"rm\", got %s", constraints[0].Expression)
	}
	if constraints[1].Expression != `input.path != "/etc/passwd"` {
		t.Fatalf("expected second expression input.path != \"/etc/passwd\", got %s", constraints[1].Expression)
	}

	// Both should reference the custom principle.
	for _, c := range constraints {
		if c.PrincipleID != "p-custom" {
			t.Fatalf("expected principle ID p-custom, got %s", c.PrincipleID)
		}
	}

	// Custom constraints with != should infer "deny" action.
	for _, c := range constraints {
		if c.Action != "deny" {
			t.Fatalf("expected deny action for != expression, got %s", c.Action)
		}
	}
}

func TestAligner_NilConstitution(t *testing.T) {
	a := constitution.NewAligner()

	constraints, err := a.Align(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if constraints != nil {
		t.Fatalf("expected nil constraints for nil constitution, got %v", constraints)
	}

	score := a.Score(nil, "read", "file", "ALLOW")
	if score.OverallScore != 0 {
		t.Fatalf("expected zero score for nil constitution, got %f", score.OverallScore)
	}
}
