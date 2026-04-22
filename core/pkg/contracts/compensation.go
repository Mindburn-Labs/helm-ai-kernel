// Package contracts — CompensationRecipe.
//
// Per HELM 2030 Spec §1.3 / §3A:
//
//	Every EvidencePack includes a rollback/compensation recipe.
//	Compensation is structured, not ad-hoc.
package contracts

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// CompensationStep is one step in a compensation recipe.
type CompensationStep struct {
	StepID     string `json:"step_id"`
	Order      int    `json:"order"`
	Action     string `json:"action"` // e.g. "revert_deploy", "restore_backup", "notify_oncall"
	Target     string `json:"target"` // resource/service affected
	Idempotent bool   `json:"idempotent"`
	Timeout    string `json:"timeout,omitempty"`
	Fallback   string `json:"fallback,omitempty"` // what to do if this step fails
}

// CompensationRecipe is a structured rollback/undo plan.
type CompensationRecipe struct {
	RecipeID       string             `json:"recipe_id"`
	RunID          string             `json:"run_id"`
	Steps          []CompensationStep `json:"steps"`
	AutoExecutable bool               `json:"auto_executable"` // can be run without human
	EstimatedTime  string             `json:"estimated_time,omitempty"`
	CreatedAt      time.Time          `json:"created_at"`
	ContentHash    string             `json:"content_hash"`
}

// NewCompensationRecipe creates a recipe with computed hash.
func NewCompensationRecipe(runID string, steps []CompensationStep, autoExecutable bool) *CompensationRecipe {
	recipeID := fmt.Sprintf("comp-%s", runID)

	hashInput := fmt.Sprintf("%s:%d:%v", recipeID, len(steps), autoExecutable)
	h := sha256.Sum256([]byte(hashInput))

	return &CompensationRecipe{
		RecipeID:       recipeID,
		RunID:          runID,
		Steps:          steps,
		AutoExecutable: autoExecutable,
		CreatedAt:      time.Now(),
		ContentHash:    "sha256:" + hex.EncodeToString(h[:]),
	}
}

// IsComplete returns true if all steps are defined.
func (r *CompensationRecipe) IsComplete() bool {
	return len(r.Steps) > 0
}

// HasFallbacks returns true if every step has a fallback.
func (r *CompensationRecipe) HasFallbacks() bool {
	for _, s := range r.Steps {
		if s.Fallback == "" {
			return false
		}
	}
	return len(r.Steps) > 0
}
