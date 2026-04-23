package contracts_test

import (
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
)

// ──────────────────────────────────────────────────────────────
// Capability diff taxonomy determinism tests (D3)
// ──────────────────────────────────────────────────────────────

func TestDefaultOpMappings_AllUnique(t *testing.T) {
	seen := make(map[string]bool)
	for _, m := range contracts.DefaultOpMappings {
		if seen[m.OpKind] {
			t.Errorf("duplicate OpKind in DefaultOpMappings: %s", m.OpKind)
		}
		seen[m.OpKind] = true
	}
}

func TestDefaultOpMappings_AllHaveTemplates(t *testing.T) {
	for _, m := range contracts.DefaultOpMappings {
		if m.TitleTemplate == "" {
			t.Errorf("OpKind %q has empty TitleTemplate", m.OpKind)
		}
		if m.DescriptionTemplate == "" {
			t.Errorf("OpKind %q has empty DescriptionTemplate", m.OpKind)
		}
		if m.OpKind == "" {
			t.Error("found mapping with empty OpKind")
		}
	}
}

func TestDefaultOpMappings_CoverAllCategories(t *testing.T) {
	allCategories := map[contracts.DiffCategory]bool{
		contracts.DiffCategoryCapability: false,
		contracts.DiffCategoryControl:    false,
		contracts.DiffCategoryWorkflow:   false,
		contracts.DiffCategoryData:       false,
		contracts.DiffCategoryBudget:     false,
		contracts.DiffCategoryPosture:    false,
	}

	for _, m := range contracts.DefaultOpMappings {
		allCategories[m.Category] = true
	}

	for cat, covered := range allCategories {
		if !covered {
			t.Errorf("DiffCategory %q has no mapping in DefaultOpMappings", cat)
		}
	}
}

func TestOpMappingIndex_DeterministicAcrossCalls(t *testing.T) {
	idx1 := contracts.OpMappingIndex()
	idx2 := contracts.OpMappingIndex()

	if len(idx1) != len(idx2) {
		t.Fatalf("OpMappingIndex length mismatch: %d vs %d", len(idx1), len(idx2))
	}

	for key, m1 := range idx1 {
		m2, ok := idx2[key]
		if !ok {
			t.Errorf("key %q in first index but not second", key)
			continue
		}
		if m1.Category != m2.Category {
			t.Errorf("key %q: category %s vs %s", key, m1.Category, m2.Category)
		}
		if m1.TitleTemplate != m2.TitleTemplate {
			t.Errorf("key %q: title template mismatch", key)
		}
	}
}

func TestOpMappingIndex_MatchesDefaultOpMappings(t *testing.T) {
	idx := contracts.OpMappingIndex()

	if len(idx) != len(contracts.DefaultOpMappings) {
		t.Errorf("index has %d entries but DefaultOpMappings has %d", len(idx), len(contracts.DefaultOpMappings))
	}

	for _, m := range contracts.DefaultOpMappings {
		mapped, ok := idx[m.OpKind]
		if !ok {
			t.Errorf("OpKind %q missing from index", m.OpKind)
			continue
		}
		if mapped.Category != m.Category {
			t.Errorf("OpKind %q: index category %s != mapping category %s", m.OpKind, mapped.Category, m.Category)
		}
	}
}
