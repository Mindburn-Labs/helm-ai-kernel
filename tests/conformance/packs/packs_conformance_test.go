package packs_conformance

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/packs/last30days"
)

// stubSource is a deterministic, in-memory Source implementation for conformance tests.
type stubSource struct {
	name    string
	items   []last30days.Item
	failErr error // when non-nil, Collect returns this error
}

func (s *stubSource) Name() string { return s.name }

func (s *stubSource) Collect(_ context.Context, _ string, since time.Time) ([]last30days.Item, error) {
	if s.failErr != nil {
		return nil, s.failErr
	}
	var out []last30days.Item
	for _, item := range s.items {
		if !item.PublishedAt.Before(since) {
			out = append(out, item)
		}
	}
	return out, nil
}

// makeItem is a helper that builds a fully-populated last30days.Item with a deterministic ContentHash.
func makeItem(source, title, url, stance string, entities []string, daysAgo int) last30days.Item {
	publishedAt := time.Now().UTC().AddDate(0, 0, -daysAgo)
	return last30days.Item{
		Source:      source,
		Title:       title,
		URL:         url,
		PublishedAt: publishedAt,
		Engagement:  last30days.Engagement{Score: 100, Comments: 10},
		Entities:    entities,
		Stance:      stance,
		ContentHash: last30days.ContentHashFor(source, url, title),
	}
}

// allSixSources builds one stub source per canonical name.
func allSixSources(items map[string][]last30days.Item) []last30days.Source {
	names := []string{"reddit", "hackernews", "polymarket", "youtube", "x", "web"}
	sources := make([]last30days.Source, 0, len(names))
	for _, name := range names {
		sources = append(sources, &stubSource{
			name:  name,
			items: items[name],
		})
	}
	return sources
}

// TestPackConformance_Last30DaysWithAllSixSources creates a pack with all 6 sources and runs collection.
func TestPackConformance_Last30DaysWithAllSixSources(t *testing.T) {
	items := map[string][]last30days.Item{
		"reddit":      {makeItem("reddit", "BTC surge", "https://reddit.com/r/1", "bullish", []string{"BTC"}, 5)},
		"hackernews":  {makeItem("hackernews", "BTC analysis", "https://news.ycombinator.com/1", "bullish", []string{"BTC"}, 3)},
		"polymarket":  {makeItem("polymarket", "BTC market", "https://polymarket.com/1", "bullish", []string{"BTC"}, 2)},
		"youtube":     {makeItem("youtube", "BTC video", "https://youtube.com/1", "neutral", []string{"BTC"}, 10)},
		"x":           {makeItem("x", "BTC tweet", "https://x.com/1", "bearish", []string{"BTC"}, 1)},
		"web":         {makeItem("web", "BTC article", "https://example.com/1", "neutral", []string{"BTC"}, 7)},
	}

	pack := &last30days.Pack{
		Sources:    allSixSources(items),
		WindowDays: 30,
	}

	t.Run("run_returns_non_nil_digest", func(t *testing.T) {
		digest, err := pack.Run(context.Background(), "BTC")
		require.NoError(t, err)
		require.NotNil(t, digest)
	})
}

// TestPackConformance_DigestStructure verifies the digest has all required fields.
func TestPackConformance_DigestStructure(t *testing.T) {
	items := map[string][]last30days.Item{
		"reddit":     {makeItem("reddit", "ETH DeFi", "https://reddit.com/defi", "bullish", []string{"ETH"}, 2)},
		"hackernews": {makeItem("hackernews", "ETH layer2", "https://news.ycombinator.com/eth", "neutral", []string{"ETH"}, 4)},
		"polymarket": {},
		"youtube":    {},
		"x":          {},
		"web":        {},
	}

	pack := &last30days.Pack{
		Sources:    allSixSources(items),
		WindowDays: 30,
	}

	digest, err := pack.Run(context.Background(), "ETH")
	require.NoError(t, err)
	require.NotNil(t, digest)

	t.Run("digest_id_is_non_empty", func(t *testing.T) {
		assert.NotEmpty(t, digest.DigestID)
	})

	t.Run("topic_matches_input", func(t *testing.T) {
		assert.Equal(t, "ETH", digest.Topic)
	})

	t.Run("window_days_matches_input", func(t *testing.T) {
		assert.Equal(t, 30, digest.WindowDays)
	})

	t.Run("generated_at_is_recent", func(t *testing.T) {
		assert.WithinDuration(t, time.Now().UTC(), digest.GeneratedAt, 5*time.Second)
	})

	t.Run("content_hash_is_non_empty", func(t *testing.T) {
		assert.NotEmpty(t, digest.ContentHash)
	})

	t.Run("synthesis_summary_is_non_empty", func(t *testing.T) {
		assert.NotEmpty(t, digest.Synthesis.Summary)
	})
}

// TestPackConformance_ConvergenceSignalsDetected verifies that multi-source entities produce signals.
func TestPackConformance_ConvergenceSignalsDetected(t *testing.T) {
	// "BTC" appears in both reddit and hackernews — must produce a convergence signal.
	items := []last30days.Item{
		makeItem("reddit", "BTC rises", "https://reddit.com/btc1", "bullish", []string{"BTC"}, 1),
		makeItem("hackernews", "BTC layer2", "https://hn.com/btc2", "neutral", []string{"BTC"}, 2),
	}

	signals := last30days.DetectConvergence(items)

	t.Run("btc_produces_convergence_signal", func(t *testing.T) {
		require.NotEmpty(t, signals, "BTC mentioned in 2 sources must produce at least one convergence signal")
		assert.Equal(t, "BTC", signals[0].Entity)
	})

	t.Run("signal_strength_is_in_range", func(t *testing.T) {
		assert.GreaterOrEqual(t, signals[0].Strength, 0.0)
		assert.LessOrEqual(t, signals[0].Strength, 1.0)
	})
}

// TestPackConformance_ContentHashIsDeterministic verifies ContentHashFor produces stable output.
func TestPackConformance_ContentHashIsDeterministic(t *testing.T) {
	t.Run("same_inputs_produce_same_hash", func(t *testing.T) {
		h1 := last30days.ContentHashFor("reddit", "https://example.com", "Some Title")
		h2 := last30days.ContentHashFor("reddit", "https://example.com", "Some Title")
		assert.Equal(t, h1, h2)
	})

	t.Run("different_inputs_produce_different_hashes", func(t *testing.T) {
		h1 := last30days.ContentHashFor("reddit", "https://example.com/a", "Title A")
		h2 := last30days.ContentHashFor("reddit", "https://example.com/b", "Title B")
		assert.NotEqual(t, h1, h2)
	})
}

// TestPackConformance_SynthesisContradictions verifies that contradicting stances are surfaced.
func TestPackConformance_SynthesisContradictions(t *testing.T) {
	items := []last30days.Item{
		makeItem("reddit", "BTC moon", "https://reddit.com/moon", "bullish", []string{"BTC"}, 1),
		makeItem("x", "BTC dump", "https://x.com/dump", "bearish", []string{"BTC"}, 2),
	}

	contradictions := last30days.FindContradictions(items)

	t.Run("contradictions_detected_for_mixed_stance_entity", func(t *testing.T) {
		require.NotEmpty(t, contradictions)
		assert.Contains(t, contradictions, "BTC")
	})
}

// TestPackConformance_SynthesisWatchItems verifies that high-strength signals produce watch items.
func TestPackConformance_SynthesisWatchItems(t *testing.T) {
	// Create items with SOL across 3 sources so strength = 3/3 = 1.0 (>= 0.5).
	items := []last30days.Item{
		makeItem("reddit", "SOL fast", "https://reddit.com/sol1", "bullish", []string{"SOL"}, 1),
		makeItem("x", "SOL ecosystem", "https://x.com/sol2", "neutral", []string{"SOL"}, 2),
		makeItem("web", "SOL TVL", "https://example.com/sol3", "bullish", []string{"SOL"}, 3),
	}

	signals := last30days.DetectConvergence(items)
	var watchItems []string
	for _, sig := range signals {
		if sig.Strength >= 0.5 {
			watchItems = append(watchItems, sig.Entity)
		}
	}

	t.Run("high_strength_entity_appears_in_watch_items", func(t *testing.T) {
		assert.Contains(t, watchItems, "SOL")
	})
}

// TestPackConformance_PartialSourceFailureDoesNotCrash verifies that one failing source
// does not prevent other sources from contributing to the digest.
func TestPackConformance_PartialSourceFailureDoesNotCrash(t *testing.T) {
	sources := []last30days.Source{
		&stubSource{
			name:    "healthy-source",
			items:   []last30days.Item{makeItem("healthy-source", "Good data", "https://good.com/1", "bullish", []string{"ETH"}, 1)},
			failErr: nil,
		},
		&stubSource{
			name:    "failing-source",
			failErr: errors.New("upstream API unavailable"),
		},
	}

	pack := &last30days.Pack{
		Sources:    sources,
		WindowDays: 30,
	}

	t.Run("partial_failure_returns_digest_without_error", func(t *testing.T) {
		digest, err := pack.Run(context.Background(), "ETH")
		// Only one source failed out of two — should NOT return an error.
		require.NoError(t, err)
		require.NotNil(t, digest)
	})

	t.Run("partial_failure_digest_contains_healthy_source_items", func(t *testing.T) {
		digest, _ := pack.Run(context.Background(), "ETH")
		assert.NotEmpty(t, digest.Items)
	})
}

// TestPackConformance_AllSourcesFailReturnsError verifies that when every source fails,
// Run surfaces a combined error.
func TestPackConformance_AllSourcesFailReturnsError(t *testing.T) {
	sources := []last30days.Source{
		&stubSource{name: "src-a", failErr: errors.New("timeout")},
		&stubSource{name: "src-b", failErr: errors.New("rate limited")},
	}

	pack := &last30days.Pack{
		Sources:    sources,
		WindowDays: 30,
	}

	t.Run("all_sources_failing_returns_error", func(t *testing.T) {
		digest, err := pack.Run(context.Background(), "ETH")
		require.Error(t, err)
		// Digest is still returned (may be empty but non-nil).
		assert.NotNil(t, digest)
	})
}
