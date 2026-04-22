package contracts

import "testing"

func TestCompensationRecipeCreate(t *testing.T) {
	steps := []CompensationStep{
		{StepID: "s1", Order: 1, Action: "revert_deploy", Target: "prod", Idempotent: true, Fallback: "notify_oncall"},
		{StepID: "s2", Order: 2, Action: "restore_backup", Target: "db", Idempotent: false, Fallback: "manual_restore"},
	}
	r := NewCompensationRecipe("run-1", steps, true)

	if r.RecipeID == "" {
		t.Fatal("expected recipe ID")
	}
	if len(r.Steps) != 2 {
		t.Fatalf("expected 2 steps, got %d", len(r.Steps))
	}
	if !r.AutoExecutable {
		t.Fatal("expected auto-executable")
	}
}

func TestCompensationRecipeIsComplete(t *testing.T) {
	empty := NewCompensationRecipe("run-1", nil, false)
	if empty.IsComplete() {
		t.Fatal("expected incomplete")
	}

	filled := NewCompensationRecipe("run-1", []CompensationStep{{StepID: "s1"}}, true)
	if !filled.IsComplete() {
		t.Fatal("expected complete")
	}
}

func TestCompensationRecipeHasFallbacks(t *testing.T) {
	with := NewCompensationRecipe("r1", []CompensationStep{
		{StepID: "s1", Fallback: "fallback-1"},
		{StepID: "s2", Fallback: "fallback-2"},
	}, true)
	if !with.HasFallbacks() {
		t.Fatal("expected all fallbacks present")
	}

	without := NewCompensationRecipe("r1", []CompensationStep{
		{StepID: "s1", Fallback: "fallback-1"},
		{StepID: "s2"},
	}, true)
	if without.HasFallbacks() {
		t.Fatal("expected missing fallback")
	}
}

func TestCompensationRecipeContentHash(t *testing.T) {
	r := NewCompensationRecipe("run-1", []CompensationStep{{StepID: "s1"}}, true)
	if r.ContentHash == "" {
		t.Fatal("expected content hash")
	}
}
