package aibom

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
)

// Verify checks the content hash integrity of a BOM by recomputing the
// JCS-canonicalized SHA-256 digest and comparing it to the stored value.
func Verify(bom *AIBOM) error {
	if bom.ContentHash == "" {
		return fmt.Errorf("BOM has no content hash")
	}

	// Recompute hash with ContentHash and Signature cleared, matching
	// the same procedure used by computeContentHash during generation.
	saved := bom.ContentHash
	savedSig := bom.Signature
	bom.ContentHash = ""
	bom.Signature = ""

	data, err := canonicalize.JCS(bom)
	bom.ContentHash = saved
	bom.Signature = savedSig

	if err != nil {
		return fmt.Errorf("canonicalize BOM: %w", err)
	}

	h := sha256.Sum256(data)
	computed := "sha256:" + hex.EncodeToString(h[:])

	if computed != saved {
		return fmt.Errorf("content hash mismatch: computed %s != stored %s", computed, saved)
	}

	return nil
}

// Diff compares two BOMs and returns the differences in models and
// dependencies. It matches models by ModelID and dependencies by Name.
func Diff(old, new *AIBOM) *BOMDiff {
	diff := &BOMDiff{
		OldBomID: old.BomID,
		NewBomID: new.BomID,
	}

	// Model diffs.
	oldModels := make(map[string]ModelProvenance)
	for _, m := range old.Models {
		oldModels[m.ModelID] = m
	}
	for _, m := range new.Models {
		if _, exists := oldModels[m.ModelID]; !exists {
			diff.ModelsAdded = append(diff.ModelsAdded, m)
		}
		delete(oldModels, m.ModelID)
	}
	for _, m := range oldModels {
		diff.ModelsRemoved = append(diff.ModelsRemoved, m)
	}

	// Dependency diffs.
	oldDeps := make(map[string]DependencyEntry)
	for _, d := range old.Dependencies {
		oldDeps[d.Name] = d
	}
	for _, d := range new.Dependencies {
		if oldDep, exists := oldDeps[d.Name]; !exists {
			diff.DepsAdded = append(diff.DepsAdded, d)
		} else if oldDep.Version != d.Version {
			diff.DepsChanged = append(diff.DepsChanged, DepChange{
				Name:       d.Name,
				OldVersion: oldDep.Version,
				NewVersion: d.Version,
			})
		}
		delete(oldDeps, d.Name)
	}
	for _, d := range oldDeps {
		diff.DepsRemoved = append(diff.DepsRemoved, d)
	}

	return diff
}
