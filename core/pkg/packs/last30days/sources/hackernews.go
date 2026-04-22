package sources

import (
	"context"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/packs/last30days"
)

// HackerNewsSource collects stories from the Algolia HN Search API
// (https://hn.algolia.com/api).  No API key is required.
type HackerNewsSource struct {
	// MinScore filters out stories below this engagement threshold.
	MinScore int
}

// Name implements last30days.Source.
func (s *HackerNewsSource) Name() string { return "hackernews" }

// Collect implements last30days.Source.
//
// Stub: returns placeholder data exercising the Item schema.
// Replace with live calls to https://hn.algolia.com/api/v1/search when ready.
func (s *HackerNewsSource) Collect(_ context.Context, topic string, since time.Time) ([]last30days.Item, error) {
	item := last30days.Item{
		Source:      s.Name(),
		Title:       "HN stub: " + topic,
		URL:         "https://news.ycombinator.com/",
		PublishedAt: since.Add(2 * time.Hour),
		Engagement:  last30days.Engagement{Score: 128, Comments: 34, Views: 0},
		Entities:    []string{topic},
		Stance:      "neutral",
	}
	item.ContentHash = last30days.ContentHashFor(item.Source, item.URL, item.Title)
	return []last30days.Item{item}, nil
}
