package compliance

import (
	"testing"
)

func TestScorecardBuild(t *testing.T) {
	b := NewScorecardBuilder()
	b.AddDimension(ParityDimension{DimensionID: "safety", Name: "Safety", Weight: 1.0})
	b.AddDimension(ParityDimension{DimensionID: "enterprise", Name: "Enterprise", Weight: 0.8})
	b.AddProduct("helm", "HELM")
	b.AddProduct("competitor", "Competitor X")

	b.RecordScore(ParityScore{DimensionID: "safety", ProductID: "helm", Score: 95, EvidenceRef: "test:safety_suite"})
	b.RecordScore(ParityScore{DimensionID: "enterprise", ProductID: "helm", Score: 85, EvidenceRef: "test:enterprise_suite"})
	b.RecordScore(ParityScore{DimensionID: "safety", ProductID: "competitor", Score: 80, EvidenceRef: "doc:competitor_review"})

	card := b.Build()
	if card.ContentHash == "" {
		t.Fatal("expected content hash")
	}
	if len(card.Entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(card.Entries))
	}
}

func TestScorecardWeightedAvg(t *testing.T) {
	b := NewScorecardBuilder()
	b.AddDimension(ParityDimension{DimensionID: "a", Name: "A", Weight: 1.0})
	b.AddDimension(ParityDimension{DimensionID: "b", Name: "B", Weight: 1.0})
	b.AddProduct("p1", "Product 1")

	b.RecordScore(ParityScore{DimensionID: "a", ProductID: "p1", Score: 100, EvidenceRef: "test:a"})
	b.RecordScore(ParityScore{DimensionID: "b", ProductID: "p1", Score: 50, EvidenceRef: "test:b"})

	card := b.Build()
	for _, e := range card.Entries {
		if e.ProductID == "p1" {
			if e.WeightedAvg != 75.0 {
				t.Fatalf("expected 75.0 weighted avg, got %.1f", e.WeightedAvg)
			}
		}
	}
}

func TestScorecardRequiresEvidence(t *testing.T) {
	b := NewScorecardBuilder()
	err := b.RecordScore(ParityScore{DimensionID: "a", ProductID: "p1", Score: 100, EvidenceRef: ""})
	if err == nil {
		t.Fatal("expected error for missing evidence")
	}
}

func TestScorecardDimensions(t *testing.T) {
	b := NewScorecardBuilder()
	b.AddDimension(ParityDimension{DimensionID: "a", Name: "A", Weight: 1.0})
	b.AddDimension(ParityDimension{DimensionID: "b", Name: "B", Weight: 0.5})

	card := b.Build()
	if len(card.Dimensions) != 2 {
		t.Fatalf("expected 2 dimensions, got %d", len(card.Dimensions))
	}
}
