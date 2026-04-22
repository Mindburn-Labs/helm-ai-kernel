// Package sources provides per-source data collectors for the last30days pack.
// Each collector implements the last30days.Source interface and returns a slice
// of last30days.Item values normalised into the common schema.
package sources

import (
	"context"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/packs/last30days"
)

// RedditSource collects posts and comments from a configurable set of
// subreddits via the Reddit JSON API (no OAuth required for read-only access).
type RedditSource struct {
	// Subreddits is the list of subreddit names to search (without the r/ prefix).
	Subreddits []string
	// APIKey is an optional OAuth2 bearer token for elevated rate limits.
	APIKey string
}

// Name implements last30days.Source.
func (s *RedditSource) Name() string { return "reddit" }

// Collect implements last30days.Source.
//
// Currently a structural stub: returns placeholder data that exercises the
// full Item schema.  Replace the body with real HTTP calls against
// https://www.reddit.com/search.json when credentials are available.
func (s *RedditSource) Collect(_ context.Context, topic string, since time.Time) ([]last30days.Item, error) {
	odds := 0.0
	item := last30days.Item{
		Source:      s.Name(),
		Title:       "Reddit stub: " + topic,
		URL:         "https://www.reddit.com/search?q=" + topic,
		PublishedAt: since.Add(1 * time.Hour),
		Engagement:  last30days.Engagement{Score: 42, Comments: 7, Views: 0, Odds: &odds},
		Entities:    []string{topic},
		Stance:      "neutral",
	}
	item.ContentHash = last30days.ContentHashFor(item.Source, item.URL, item.Title)
	return []last30days.Item{item}, nil
}
