package sources

import (
	"context"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/packs/last30days"
)

// YouTubeSource collects video results from the YouTube Data API v3.
type YouTubeSource struct {
	// APIKey is the YouTube Data API key (required for live queries).
	APIKey string
	// MaxResults caps the number of videos returned per query.
	MaxResults int
}

// Name implements last30days.Source.
func (s *YouTubeSource) Name() string { return "youtube" }

// Collect implements last30days.Source.
//
// Stub: returns a placeholder Item with view count encoded in Engagement.Views.
// Replace with live calls to https://www.googleapis.com/youtube/v3/search.
func (s *YouTubeSource) Collect(_ context.Context, topic string, since time.Time) ([]last30days.Item, error) {
	item := last30days.Item{
		Source:      s.Name(),
		Title:       "YouTube stub: " + topic,
		URL:         "https://www.youtube.com/results?search_query=" + topic,
		PublishedAt: since.Add(6 * time.Hour),
		Engagement:  last30days.Engagement{Score: 0, Comments: 120, Views: 15000},
		Entities:    []string{topic},
		Stance:      "neutral",
	}
	item.ContentHash = last30days.ContentHashFor(item.Source, item.URL, item.Title)
	return []last30days.Item{item}, nil
}
