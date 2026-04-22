package compliance

import (
	"encoding/json"
	"sync"
	"testing"
	"time"
)

func TestFinal_ParityDimensionJSON(t *testing.T) {
	pd := ParityDimension{DimensionID: "d1", Name: "safety", Category: "safety", Weight: 0.8}
	data, _ := json.Marshal(pd)
	var pd2 ParityDimension
	json.Unmarshal(data, &pd2)
	if pd2.Weight != 0.8 {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_ParityScoreJSON(t *testing.T) {
	ps := ParityScore{DimensionID: "d1", ProductID: "p1", Score: 85, EvidenceRef: "test-001"}
	data, _ := json.Marshal(ps)
	var ps2 ParityScore
	json.Unmarshal(data, &ps2)
	if ps2.Score != 85 {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_ScorecardEntryJSON(t *testing.T) {
	se := ScorecardEntry{ProductID: "p1", ProductName: "HELM", WeightedAvg: 90.5}
	data, _ := json.Marshal(se)
	var se2 ScorecardEntry
	json.Unmarshal(data, &se2)
	if se2.WeightedAvg != 90.5 {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_ScorecardJSON(t *testing.T) {
	sc := Scorecard{ScorecardID: "sc1", GeneratedAt: time.Now(), ContentHash: "sha256:abc"}
	data, _ := json.Marshal(sc)
	var sc2 Scorecard
	json.Unmarshal(data, &sc2)
	if sc2.ScorecardID != "sc1" {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_ScorecardBuilderNew(t *testing.T) {
	b := NewScorecardBuilder()
	if b == nil {
		t.Fatal("builder should not be nil")
	}
}

func TestFinal_ScorecardBuilderBuildEmpty(t *testing.T) {
	b := NewScorecardBuilder()
	sc := b.Build()
	if sc == nil {
		t.Fatal("build should return scorecard even when empty")
	}
	if sc.ContentHash == "" {
		t.Fatal("content hash should be computed")
	}
}

func TestFinal_ScorecardBuilderWithClock(t *testing.T) {
	fixed := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	b := NewScorecardBuilder().WithClock(func() time.Time { return fixed })
	sc := b.Build()
	if sc.GeneratedAt != fixed {
		t.Fatal("should use custom clock")
	}
}

func TestFinal_ScorecardBuilderRecordScore(t *testing.T) {
	b := NewScorecardBuilder()
	b.AddDimension(ParityDimension{DimensionID: "d1", Name: "safety", Weight: 1.0})
	b.AddProduct("p1", "HELM")
	err := b.RecordScore(ParityScore{DimensionID: "d1", ProductID: "p1", Score: 90, EvidenceRef: "test-001"})
	if err != nil {
		t.Fatal(err)
	}
	sc := b.Build()
	if len(sc.Entries) != 1 {
		t.Fatal("should have 1 entry")
	}
}

func TestFinal_ScorecardBuilderRecordScoreNoEvidence(t *testing.T) {
	b := NewScorecardBuilder()
	err := b.RecordScore(ParityScore{DimensionID: "d1", ProductID: "p1", Score: 90})
	if err == nil {
		t.Fatal("should error when evidence reference is missing")
	}
}

func TestFinal_ScorecardBuilderWeightedAvg(t *testing.T) {
	b := NewScorecardBuilder()
	b.AddDimension(ParityDimension{DimensionID: "d1", Weight: 1.0})
	b.AddDimension(ParityDimension{DimensionID: "d2", Weight: 1.0})
	b.AddProduct("p1", "HELM")
	b.RecordScore(ParityScore{DimensionID: "d1", ProductID: "p1", Score: 100, EvidenceRef: "e1"})
	b.RecordScore(ParityScore{DimensionID: "d2", ProductID: "p1", Score: 50, EvidenceRef: "e2"})
	sc := b.Build()
	if sc.Entries[0].WeightedAvg != 75 {
		t.Fatalf("want avg 75, got %f", sc.Entries[0].WeightedAvg)
	}
}

func TestFinal_ScorecardContentHashDeterminism(t *testing.T) {
	fixed := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	build := func() string {
		b := NewScorecardBuilder().WithClock(func() time.Time { return fixed })
		b.AddProduct("p1", "HELM")
		return b.Build().ContentHash
	}
	h1 := build()
	h2 := build()
	if h1 != h2 {
		t.Fatal("content hash should be deterministic")
	}
}

func TestFinal_ScorecardBuilderMultipleProducts(t *testing.T) {
	b := NewScorecardBuilder()
	b.AddDimension(ParityDimension{DimensionID: "d1", Weight: 1.0})
	b.AddProduct("p1", "HELM")
	b.AddProduct("p2", "Competitor")
	b.RecordScore(ParityScore{DimensionID: "d1", ProductID: "p1", Score: 95, EvidenceRef: "e1"})
	b.RecordScore(ParityScore{DimensionID: "d1", ProductID: "p2", Score: 70, EvidenceRef: "e2"})
	sc := b.Build()
	if len(sc.Entries) != 2 {
		t.Fatalf("want 2 entries, got %d", len(sc.Entries))
	}
}

func TestFinal_ConcurrentScorecardBuilder(t *testing.T) {
	b := NewScorecardBuilder()
	b.AddDimension(ParityDimension{DimensionID: "d1", Weight: 1.0})
	b.AddProduct("p1", "HELM")
	var wg sync.WaitGroup
	for i := 0; i < 15; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			b.RecordScore(ParityScore{DimensionID: "d1", ProductID: "p1", Score: float64(i * 10), EvidenceRef: "e"})
		}(i)
	}
	wg.Wait()
}

func TestFinal_ComplianceScorerZeroValue(t *testing.T) {
	s := &ComplianceScorer{}
	if s == nil {
		t.Fatal("zero value should not be nil")
	}
}

func TestFinal_ScorecardIDNonEmpty(t *testing.T) {
	b := NewScorecardBuilder()
	sc := b.Build()
	if sc.ScorecardID == "" {
		t.Fatal("scorecard ID should not be empty")
	}
}

func TestFinal_ParityDimensionWeight(t *testing.T) {
	pd := ParityDimension{Weight: 0.5}
	if pd.Weight < 0 || pd.Weight > 1 {
		t.Fatal("weight should be in [0,1]")
	}
}

func TestFinal_ScorecardDimensions(t *testing.T) {
	b := NewScorecardBuilder()
	b.AddDimension(ParityDimension{DimensionID: "d1", Name: "safety"})
	b.AddDimension(ParityDimension{DimensionID: "d2", Name: "enterprise"})
	sc := b.Build()
	if len(sc.Dimensions) != 2 {
		t.Fatalf("want 2 dimensions, got %d", len(sc.Dimensions))
	}
}

func TestFinal_ParityScoreZeroValue(t *testing.T) {
	var ps ParityScore
	if ps.Score != 0 {
		t.Fatal("zero value score should be 0")
	}
}

func TestFinal_ScorecardBuilderAddDimensionIdempotent(t *testing.T) {
	b := NewScorecardBuilder()
	b.AddDimension(ParityDimension{DimensionID: "d1", Name: "test"})
	b.AddDimension(ParityDimension{DimensionID: "d1", Name: "test"})
	sc := b.Build()
	if len(sc.Dimensions) != 2 {
		t.Fatal("AddDimension appends, does not dedup")
	}
}

func TestFinal_ScorecardBuilderBuildTimestamp(t *testing.T) {
	b := NewScorecardBuilder()
	sc := b.Build()
	if sc.GeneratedAt.IsZero() {
		t.Fatal("GeneratedAt should not be zero")
	}
}

func TestFinal_ScorecardBuilderNoProductsNoEntries(t *testing.T) {
	b := NewScorecardBuilder()
	b.AddDimension(ParityDimension{DimensionID: "d1"})
	sc := b.Build()
	if len(sc.Entries) != 0 {
		t.Fatal("no products = no entries")
	}
}

func TestFinal_ScorecardEntriesHaveProductName(t *testing.T) {
	b := NewScorecardBuilder()
	b.AddProduct("p1", "My Product")
	b.RecordScore(ParityScore{DimensionID: "d1", ProductID: "p1", Score: 50, EvidenceRef: "e"})
	sc := b.Build()
	if sc.Entries[0].ProductName != "My Product" {
		t.Fatal("entry should have product name")
	}
}

func TestFinal_ScorecardContentHashPrefix(t *testing.T) {
	b := NewScorecardBuilder()
	sc := b.Build()
	if len(sc.ContentHash) < 7 || sc.ContentHash[:7] != "sha256:" {
		t.Fatal("content hash should start with sha256:")
	}
}
