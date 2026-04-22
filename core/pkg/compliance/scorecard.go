// Package compliance — Competitor Parity Scorecard.
//
// Per HELM 2030 Spec:
//   - Evidence-backed parity scoring
//   - Each score references a test result or code artifact
//   - Machine-verifiable claims
package compliance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// ParityDimension is one comparison axis.
type ParityDimension struct {
	DimensionID string  `json:"dimension_id"`
	Name        string  `json:"name"`
	Category    string  `json:"category"` // safety, enterprise, compliance, etc.
	Weight      float64 `json:"weight"`   // 0-1
}

// ParityScore is a score for one competitor on one dimension.
type ParityScore struct {
	DimensionID string  `json:"dimension_id"`
	ProductID   string  `json:"product_id"`
	Score       float64 `json:"score"`        // 0-100
	EvidenceRef string  `json:"evidence_ref"` // Test ID or artifact path
	Notes       string  `json:"notes,omitempty"`
}

// ScorecardEntry aggregates scores for one competitor.
type ScorecardEntry struct {
	ProductID   string        `json:"product_id"`
	ProductName string        `json:"product_name"`
	Scores      []ParityScore `json:"scores"`
	WeightedAvg float64       `json:"weighted_avg"`
}

// Scorecard is the complete parity assessment.
type Scorecard struct {
	ScorecardID string            `json:"scorecard_id"`
	GeneratedAt time.Time         `json:"generated_at"`
	Dimensions  []ParityDimension `json:"dimensions"`
	Entries     []ScorecardEntry  `json:"entries"`
	ContentHash string            `json:"content_hash"`
}

// ScorecardBuilder constructs evidence-backed scorecards.
type ScorecardBuilder struct {
	mu         sync.Mutex
	dimensions []ParityDimension
	scores     map[string][]ParityScore // productID → scores
	products   map[string]string        // productID → productName
	clock      func() time.Time
}

// NewScorecardBuilder creates a new builder.
func NewScorecardBuilder() *ScorecardBuilder {
	return &ScorecardBuilder{
		scores:   make(map[string][]ParityScore),
		products: make(map[string]string),
		clock:    time.Now,
	}
}

// WithClock overrides clock for testing.
func (b *ScorecardBuilder) WithClock(clock func() time.Time) *ScorecardBuilder {
	b.clock = clock
	return b
}

// AddDimension adds a comparison axis.
func (b *ScorecardBuilder) AddDimension(d ParityDimension) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.dimensions = append(b.dimensions, d)
}

// AddProduct registers a competitor product.
func (b *ScorecardBuilder) AddProduct(productID, productName string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.products[productID] = productName
}

// RecordScore records a score with evidence reference.
func (b *ScorecardBuilder) RecordScore(score ParityScore) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if score.EvidenceRef == "" {
		return fmt.Errorf("score must have evidence reference")
	}

	b.scores[score.ProductID] = append(b.scores[score.ProductID], score)
	return nil
}

// Build creates the final scorecard.
func (b *ScorecardBuilder) Build() *Scorecard {
	b.mu.Lock()
	defer b.mu.Unlock()

	var entries []ScorecardEntry

	dimWeights := make(map[string]float64)
	for _, d := range b.dimensions {
		dimWeights[d.DimensionID] = d.Weight
	}

	for productID, name := range b.products {
		scores := b.scores[productID]

		// Compute weighted average
		totalWeight := 0.0
		weightedSum := 0.0
		for _, s := range scores {
			w := dimWeights[s.DimensionID]
			if w == 0 {
				w = 1.0
			}
			weightedSum += s.Score * w
			totalWeight += w
		}

		avg := 0.0
		if totalWeight > 0 {
			avg = weightedSum / totalWeight
		}

		entries = append(entries, ScorecardEntry{
			ProductID:   productID,
			ProductName: name,
			Scores:      scores,
			WeightedAvg: avg,
		})
	}

	now := b.clock()
	data, _ := json.Marshal(entries)
	h := sha256.Sum256(data)

	return &Scorecard{
		ScorecardID: fmt.Sprintf("sc-%d", now.UnixNano()),
		GeneratedAt: now,
		Dimensions:  b.dimensions,
		Entries:     entries,
		ContentHash: "sha256:" + hex.EncodeToString(h[:]),
	}
}
