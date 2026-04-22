package search

import (
	"context"
	"time"
)

// Result is a single search result returned by a search provider.
type Result struct {
	URL       string    `json:"url"`
	Title     string    `json:"title"`
	Snippet   string    `json:"snippet"`
	Source    string    `json:"source"`
	FetchedAt time.Time `json:"fetched_at"`
}

// Request carries parameters for a search operation.
type Request struct {
	Query      string
	MaxResults int
	MissionID  string
}

// Client is the interface for search providers.
type Client interface {
	Search(ctx context.Context, req Request) ([]Result, error)
}
