package sources

import (
	"context"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/packs/last30days"
)

// PolymarketSource collects prediction-market outcomes from the Polymarket
// CLOB API (https://clob.polymarket.com).
type PolymarketSource struct {
	// Endpoint is the base URL; defaults to https://clob.polymarket.com.
	Endpoint string
}

// Name implements last30days.Source.
func (s *PolymarketSource) Name() string { return "polymarket" }

// Collect implements last30days.Source.
//
// Stub: returns placeholder Items including an Odds field representing the
// current probability of a YES outcome.
// Replace with live calls to the Polymarket CLOB markets endpoint.
func (s *PolymarketSource) Collect(_ context.Context, topic string, since time.Time) ([]last30days.Item, error) {
	odds := 0.62
	item := last30days.Item{
		Source:      s.Name(),
		Title:       "Polymarket stub: " + topic,
		URL:         "https://polymarket.com/",
		PublishedAt: since.Add(30 * time.Minute),
		Engagement:  last30days.Engagement{Score: 0, Comments: 0, Views: 5000, Odds: &odds},
		Entities:    []string{topic},
		Stance:      "bullish",
	}
	item.ContentHash = last30days.ContentHashFor(item.Source, item.URL, item.Title)
	return []last30days.Item{item}, nil
}
