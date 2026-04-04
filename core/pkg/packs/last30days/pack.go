// Package last30days provides a 30-day alternative data synthesis pipeline.
// It collects, scores, and synthesizes signals from multiple data sources
// (Reddit, Hacker News, Polymarket, YouTube, X, and the open web) to produce
// a structured Digest for a given research topic.
package last30days

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sort"
	"time"
)

// Source is the interface every data-source collector must implement.
type Source interface {
	// Name returns the unique identifier for this source (e.g. "reddit").
	Name() string
	// Collect fetches all items published after since that match topic.
	Collect(ctx context.Context, topic string, since time.Time) ([]Item, error)
}

// Item represents a single signal collected from a Source.
type Item struct {
	Source      string     `json:"source"`
	Title       string     `json:"title"`
	URL         string     `json:"url"`
	PublishedAt time.Time  `json:"published_at"`
	Engagement  Engagement `json:"engagement"`
	Entities    []string   `json:"entities"`
	// Stance is one of: bullish, bearish, neutral, unknown.
	Stance      string `json:"stance"`
	ContentHash string `json:"content_hash"`
}

// Engagement captures audience-interaction signals for an Item.
type Engagement struct {
	Score    int      `json:"score"`
	Comments int      `json:"comments"`
	Views    int      `json:"views"`
	Odds     *float64 `json:"odds,omitempty"`
}

// Pack orchestrates a 30-day alternative data synthesis across multiple sources.
type Pack struct {
	// Sources is the ordered list of data-source collectors to run.
	Sources []Source
	// WindowDays controls how far back to look; defaults to 30 when zero.
	WindowDays int
}

// windowDays returns the effective window size (minimum 1).
func (p *Pack) windowDays() int {
	if p.WindowDays <= 0 {
		return 30
	}
	return p.WindowDays
}

// Run executes the full pack pipeline: collect → score → synthesize.
// It fans out to all registered Sources in parallel and aggregates the
// results into a single Digest.
func (p *Pack) Run(ctx context.Context, topic string) (*Digest, error) {
	since := time.Now().UTC().AddDate(0, 0, -p.windowDays())

	// Fan out to all sources; accumulate errors but do not short-circuit so
	// partial data from healthy sources is still surfaced.
	type result struct {
		items []Item
		err   error
	}

	ch := make(chan result, len(p.Sources))

	for _, src := range p.Sources {
		src := src // capture
		go func() {
			items, err := src.Collect(ctx, topic, since)
			ch <- result{items: items, err: err}
		}()
	}

	var allItems []Item
	var errs []error

	for range p.Sources {
		r := <-ch
		if r.err != nil {
			errs = append(errs, r.err)
		} else {
			allItems = append(allItems, r.items...)
		}
	}

	// Sort items deterministically before scoring.
	sort.Slice(allItems, func(i, j int) bool {
		if allItems[i].ContentHash != allItems[j].ContentHash {
			return allItems[i].ContentHash < allItems[j].ContentHash
		}
		return allItems[i].PublishedAt.Before(allItems[j].PublishedAt)
	})

	signals := DetectConvergence(allItems)
	contradictions := FindContradictions(allItems)
	digest := Synthesize(topic, p.windowDays(), allItems, signals, contradictions)

	// Surface a combined error only when every source failed.
	if len(errs) == len(p.Sources) && len(p.Sources) > 0 {
		return digest, fmt.Errorf("last30days: all sources failed (%d errors); first: %w", len(errs), errs[0])
	}

	return digest, nil
}

// ContentHashFor computes the canonical SHA-256 content hash for an item
// using the triple (source, url, title).  This function is exported so that
// source implementations can call it without duplicating the algorithm.
func ContentHashFor(source, url, title string) string {
	h := sha256.Sum256([]byte(source + "\x00" + url + "\x00" + title))
	return fmt.Sprintf("%x", h)
}
