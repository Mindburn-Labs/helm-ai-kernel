package sources

import (
	"context"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/packs/last30days"
)

// WebSource collects results from a generic web-search endpoint
// (e.g. SerpAPI, Brave Search, or a self-hosted Searxng instance).
type WebSource struct {
	// SearchEndpoint is the base URL of the search service.
	SearchEndpoint string
	// APIKey is the authentication credential for the search service.
	APIKey string
}

// Name implements last30days.Source.
func (s *WebSource) Name() string { return "web" }

// Collect implements last30days.Source.
//
// Stub: returns a placeholder Item representing a generic web search result.
// Replace with live HTTP calls to the configured SearchEndpoint.
func (s *WebSource) Collect(_ context.Context, topic string, since time.Time) ([]last30days.Item, error) {
	item := last30days.Item{
		Source:      s.Name(),
		Title:       "Web stub: " + topic,
		URL:         "https://example.com/search?q=" + topic,
		PublishedAt: since.Add(4 * time.Hour),
		Engagement:  last30days.Engagement{Score: 0, Comments: 0, Views: 1200},
		Entities:    []string{topic},
		Stance:      "unknown",
	}
	item.ContentHash = last30days.ContentHashFor(item.Source, item.URL, item.Title)
	return []last30days.Item{item}, nil
}
