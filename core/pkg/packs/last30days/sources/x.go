package sources

import (
	"context"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/packs/last30days"
)

// XSource collects tweets and spaces from the X (formerly Twitter) API v2.
type XSource struct {
	// BearerToken is the OAuth 2.0 app-only bearer token for the X API.
	BearerToken string
	// MaxResults caps the number of tweets returned per query (max 100 per page).
	MaxResults int
}

// Name implements last30days.Source.
func (s *XSource) Name() string { return "x" }

// Collect implements last30days.Source.
//
// Stub: returns a placeholder Item.
// Replace with live calls to https://api.twitter.com/2/tweets/search/recent.
func (s *XSource) Collect(_ context.Context, topic string, since time.Time) ([]last30days.Item, error) {
	item := last30days.Item{
		Source:      s.Name(),
		Title:       "X stub: " + topic,
		URL:         "https://x.com/search?q=" + topic,
		PublishedAt: since.Add(15 * time.Minute),
		Engagement:  last30days.Engagement{Score: 320, Comments: 45, Views: 9800},
		Entities:    []string{topic},
		Stance:      "bearish",
	}
	item.ContentHash = last30days.ContentHashFor(item.Source, item.URL, item.Title)
	return []last30days.Item{item}, nil
}
