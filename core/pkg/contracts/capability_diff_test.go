package contracts_test

import (
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
)

func TestOpMappingIndex(t *testing.T) {
	index := contracts.OpMappingIndex()

	if len(index) != len(contracts.DefaultOpMappings) {
		t.Errorf("expected %d mappings in index, got %d",
			len(contracts.DefaultOpMappings), len(index))
	}

	// Verify known ops are indexed
	knownOps := []string{
		"posture.change",
		"budget.update",
		"budget.exhausted",
		"capability.add",
		"capability.remove",
		"capability.modify",
		"policy.update",
		"corridor.update",
		"approval.rule.change",
		"workflow.add",
		"workflow.modify",
		"workflow.remove",
		"data.access.grant",
		"data.access.revoke",
		"connector.add",
		"connector.remove",
	}

	for _, op := range knownOps {
		m, ok := index[op]
		if !ok {
			t.Errorf("missing mapping for op %q", op)
			continue
		}
		if m.Category == "" {
			t.Errorf("op %q has empty category", op)
		}
		if m.TitleTemplate == "" {
			t.Errorf("op %q has empty title template", op)
		}
	}
}

func TestOpMappingIndex_Categories(t *testing.T) {
	index := contracts.OpMappingIndex()

	categories := map[contracts.DiffCategory]int{}
	for _, m := range index {
		categories[m.Category]++
	}

	expectedCategories := []contracts.DiffCategory{
		contracts.DiffCategoryCapability,
		contracts.DiffCategoryControl,
		contracts.DiffCategoryWorkflow,
		contracts.DiffCategoryData,
		contracts.DiffCategoryBudget,
		contracts.DiffCategoryPosture,
	}

	for _, c := range expectedCategories {
		if categories[c] == 0 {
			t.Errorf("no mappings found for category %q", c)
		}
	}
}

func TestOpMappingIndex_Deterministic(t *testing.T) {
	// Verify that calling OpMappingIndex twice gives the same result
	idx1 := contracts.OpMappingIndex()
	idx2 := contracts.OpMappingIndex()

	if len(idx1) != len(idx2) {
		t.Fatal("index sizes differ between calls")
	}

	for k, v1 := range idx1 {
		v2, ok := idx2[k]
		if !ok {
			t.Errorf("key %q missing in second call", k)
			continue
		}
		if v1.Category != v2.Category || v1.TitleTemplate != v2.TitleTemplate {
			t.Errorf("values differ for key %q", k)
		}
	}
}
