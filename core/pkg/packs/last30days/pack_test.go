package last30days_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/packs/last30days"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/packs/last30days/sources"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// staticSource is a test double that always returns a fixed set of items.
type staticSource struct {
	name  string
	items []last30days.Item
}

func (s *staticSource) Name() string { return s.name }
func (s *staticSource) Collect(_ context.Context, _ string, _ time.Time) ([]last30days.Item, error) {
	return s.items, nil
}

// errorSource always returns an error.
type errorSource struct{ name string }

func (s *errorSource) Name() string { return s.name }
func (s *errorSource) Collect(_ context.Context, _ string, _ time.Time) ([]last30days.Item, error) {
	return nil, errors.New("source unavailable: " + s.name)
}

// makeItem constructs a test Item with a precomputed ContentHash.
func makeItem(src, title, entity, stance string) last30days.Item {
	url := "https://example.com/" + src
	item := last30days.Item{
		Source:      src,
		Title:       title,
		URL:         url,
		PublishedAt: time.Now().UTC(),
		Engagement:  last30days.Engagement{Score: 10},
		Entities:    []string{entity},
		Stance:      stance,
	}
	item.ContentHash = last30days.ContentHashFor(src, url, title)
	return item
}

// ---------------------------------------------------------------------------
// Pack.Run orchestration
// ---------------------------------------------------------------------------

func TestPack_Run_AllSourcesSucceed(t *testing.T) {
	topic := "bitcoin"
	pack := &last30days.Pack{
		WindowDays: 30,
		Sources: []last30days.Source{
			&staticSource{name: "s1", items: []last30days.Item{makeItem("s1", "t1", topic, "bullish")}},
			&staticSource{name: "s2", items: []last30days.Item{makeItem("s2", "t2", topic, "bearish")}},
		},
	}

	digest, err := pack.Run(context.Background(), topic)
	require.NoError(t, err)
	require.NotNil(t, digest)

	assert.Equal(t, topic, digest.Topic)
	assert.Equal(t, 30, digest.WindowDays)
	assert.Len(t, digest.Items, 2)
	assert.NotEmpty(t, digest.DigestID)
	assert.NotEmpty(t, digest.ContentHash)
	assert.False(t, digest.GeneratedAt.IsZero())
}

func TestPack_Run_PartialFailure_DoesNotReturnError(t *testing.T) {
	// One source fails; the pack should still succeed with data from the healthy source.
	pack := &last30days.Pack{
		Sources: []last30days.Source{
			&staticSource{name: "ok", items: []last30days.Item{makeItem("ok", "good", "eth", "neutral")}},
			&errorSource{name: "broken"},
		},
	}

	digest, err := pack.Run(context.Background(), "eth")
	require.NoError(t, err, "partial failure should not surface as an error")
	assert.Len(t, digest.Items, 1, "only items from the healthy source are present")
}

func TestPack_Run_AllSourcesFail_ReturnsError(t *testing.T) {
	pack := &last30days.Pack{
		Sources: []last30days.Source{
			&errorSource{name: "a"},
			&errorSource{name: "b"},
		},
	}

	digest, err := pack.Run(context.Background(), "topic")
	assert.Error(t, err)
	// digest is still returned even on total failure (empty digest is valid output)
	assert.NotNil(t, digest)
}

func TestPack_Run_DefaultWindowDays(t *testing.T) {
	pack := &last30days.Pack{
		Sources: []last30days.Source{
			&staticSource{name: "s", items: nil},
		},
	}
	digest, err := pack.Run(context.Background(), "test")
	require.NoError(t, err)
	assert.Equal(t, 30, digest.WindowDays, "zero WindowDays should default to 30")
}

// ---------------------------------------------------------------------------
// Convergence detection
// ---------------------------------------------------------------------------

func TestDetectConvergence_EntityAcross3Sources_HighStrength(t *testing.T) {
	// "solana" appears in reddit, hackernews, and polymarket — 3 of 3 sources.
	items := []last30days.Item{
		makeItem("reddit", "solana post", "solana", "bullish"),
		makeItem("hackernews", "solana thread", "solana", "neutral"),
		makeItem("polymarket", "solana market", "solana", "bullish"),
	}

	signals := last30days.DetectConvergence(items)
	require.Len(t, signals, 1)
	assert.Equal(t, "solana", signals[0].Entity)
	assert.Equal(t, 3, len(signals[0].Sources))
	assert.InDelta(t, 1.0, signals[0].Strength, 0.001, "3 of 3 sources → strength 1.0")
}

func TestDetectConvergence_EntityInOnlyOneSource_NoSignal(t *testing.T) {
	items := []last30days.Item{
		makeItem("reddit", "unique post", "rare-token", "neutral"),
	}
	signals := last30days.DetectConvergence(items)
	assert.Empty(t, signals, "single-source entity should not produce a convergence signal")
}

func TestDetectConvergence_MultipleEntities(t *testing.T) {
	items := []last30days.Item{
		makeItem("reddit", "r1", "eth", "bullish"),
		makeItem("x", "x1", "eth", "bearish"),
		makeItem("reddit", "r2", "sol", "neutral"),
		// sol only in one source → no signal
	}

	signals := last30days.DetectConvergence(items)
	require.Len(t, signals, 1)
	assert.Equal(t, "eth", signals[0].Entity)
}

func TestDetectConvergence_SortedByStrengthDescending(t *testing.T) {
	// "a" in 2 sources out of 3; "b" in 3 sources out of 3.
	items := []last30days.Item{
		makeItem("s1", "t1", "a", "neutral"),
		makeItem("s2", "t2", "a", "neutral"),
		makeItem("s1", "t3", "b", "neutral"),
		makeItem("s2", "t4", "b", "neutral"),
		makeItem("s3", "t5", "b", "neutral"),
	}

	signals := last30days.DetectConvergence(items)
	require.True(t, len(signals) >= 2)
	assert.GreaterOrEqual(t, signals[0].Strength, signals[1].Strength,
		"signals must be sorted by descending strength")
}

// ---------------------------------------------------------------------------
// Novelty scoring
// ---------------------------------------------------------------------------

func TestScoreNovelty_UniqueItems_ScoreOne(t *testing.T) {
	items := []last30days.Item{
		makeItem("reddit", "unique-a", "tok", "neutral"),
		makeItem("x", "unique-b", "tok", "neutral"),
	}

	scores := last30days.ScoreNovelty(items)
	for _, item := range items {
		score, ok := scores[item.ContentHash]
		require.True(t, ok)
		assert.InDelta(t, 1.0, score, 0.001, "unique item should score 1.0")
	}
}

func TestScoreNovelty_DuplicateHash_HalvedScore(t *testing.T) {
	// Two items with the same ContentHash.
	base := makeItem("reddit", "dup", "tok", "neutral")
	items := []last30days.Item{base, base}

	scores := last30days.ScoreNovelty(items)
	score, ok := scores[base.ContentHash]
	require.True(t, ok)
	assert.InDelta(t, 0.5, score, 0.001, "duplicate item should score 0.5")
}

// ---------------------------------------------------------------------------
// Contradiction finding
// ---------------------------------------------------------------------------

func TestFindContradictions_BullishAndBearishOnSameEntity(t *testing.T) {
	items := []last30days.Item{
		makeItem("reddit", "r1", "btc", "bullish"),
		makeItem("x", "x1", "btc", "bearish"),
	}

	contradictions := last30days.FindContradictions(items)
	assert.Contains(t, contradictions, "btc")
}

func TestFindContradictions_NoConflict(t *testing.T) {
	items := []last30days.Item{
		makeItem("reddit", "r1", "btc", "bullish"),
		makeItem("x", "x1", "btc", "neutral"),
	}

	contradictions := last30days.FindContradictions(items)
	assert.Empty(t, contradictions, "neutral does not constitute a contradiction")
}

func TestFindContradictions_MultipleEntities(t *testing.T) {
	items := []last30days.Item{
		makeItem("s1", "t1", "eth", "bullish"),
		makeItem("s2", "t2", "eth", "bearish"),
		makeItem("s1", "t3", "sol", "bullish"),
		makeItem("s2", "t4", "sol", "bullish"),
	}

	contradictions := last30days.FindContradictions(items)
	assert.Contains(t, contradictions, "eth")
	assert.NotContains(t, contradictions, "sol")
}

func TestFindContradictions_Sorted(t *testing.T) {
	items := []last30days.Item{
		makeItem("s1", "t1", "zzz", "bullish"),
		makeItem("s2", "t2", "zzz", "bearish"),
		makeItem("s1", "t3", "aaa", "bullish"),
		makeItem("s2", "t4", "aaa", "bearish"),
	}
	contradictions := last30days.FindContradictions(items)
	require.Len(t, contradictions, 2)
	assert.Equal(t, "aaa", contradictions[0], "contradictions must be sorted alphabetically")
	assert.Equal(t, "zzz", contradictions[1])
}

// ---------------------------------------------------------------------------
// Digest generation and content hashing
// ---------------------------------------------------------------------------

func TestSynthesize_DigestFields(t *testing.T) {
	items := []last30days.Item{makeItem("s1", "t1", "tok", "neutral")}
	signals := []last30days.ConvergenceSignal{{Entity: "tok", Sources: []string{"s1"}, Strength: 1.0}}
	contradictions := []string{}

	digest := last30days.Synthesize("tok", 30, items, signals, contradictions)

	assert.Equal(t, "tok", digest.Topic)
	assert.Equal(t, 30, digest.WindowDays)
	assert.Len(t, digest.Items, 1)
	assert.NotEmpty(t, digest.DigestID)
	assert.NotEmpty(t, digest.ContentHash)
	assert.NotEmpty(t, digest.Synthesis.Summary)
	assert.False(t, digest.GeneratedAt.IsZero())
}

func TestSynthesize_ContentHash_DeterministicAcrossRuns(t *testing.T) {
	items := []last30days.Item{makeItem("reddit", "hello", "btc", "bullish")}
	signals := []last30days.ConvergenceSignal{}

	d1 := last30days.Synthesize("btc", 30, items, signals, nil)
	d2 := last30days.Synthesize("btc", 30, items, signals, nil)

	assert.Equal(t, d1.ContentHash, d2.ContentHash,
		"same inputs must produce the same ContentHash")
}

func TestSynthesize_ContentHash_DiffersForDifferentInputs(t *testing.T) {
	items1 := []last30days.Item{makeItem("s1", "A", "tok", "bullish")}
	items2 := []last30days.Item{makeItem("s1", "B", "tok", "bearish")}

	d1 := last30days.Synthesize("tok", 30, items1, nil, nil)
	d2 := last30days.Synthesize("tok", 30, items2, nil, nil)

	assert.NotEqual(t, d1.ContentHash, d2.ContentHash)
}

func TestSynthesize_WatchItems_PopulatedFromHighStrengthSignals(t *testing.T) {
	signals := []last30days.ConvergenceSignal{
		{Entity: "alpha", Strength: 0.9},
		{Entity: "beta", Strength: 0.3}, // below threshold
	}

	digest := last30days.Synthesize("topic", 7, nil, signals, nil)
	assert.Contains(t, digest.Synthesis.WatchItems, "alpha")
	assert.NotContains(t, digest.Synthesis.WatchItems, "beta")
}

func TestSynthesize_ContradictionsInSynthesis(t *testing.T) {
	contradictions := []string{"btc", "eth"}
	digest := last30days.Synthesize("topic", 30, nil, nil, contradictions)
	assert.Equal(t, contradictions, digest.Synthesis.Contradictions)
}

// ---------------------------------------------------------------------------
// ContentHashFor
// ---------------------------------------------------------------------------

func TestContentHashFor_DifferentInputs_DifferentHashes(t *testing.T) {
	h1 := last30days.ContentHashFor("reddit", "http://a.com", "title A")
	h2 := last30days.ContentHashFor("x", "http://a.com", "title A")
	assert.NotEqual(t, h1, h2)
}

func TestContentHashFor_SameInputs_SameHash(t *testing.T) {
	h1 := last30days.ContentHashFor("reddit", "http://a.com", "title A")
	h2 := last30days.ContentHashFor("reddit", "http://a.com", "title A")
	assert.Equal(t, h1, h2)
}

func TestContentHashFor_Length(t *testing.T) {
	h := last30days.ContentHashFor("s", "u", "t")
	assert.Len(t, h, 64, "SHA-256 hex must be 64 characters")
}

// ---------------------------------------------------------------------------
// Source stubs compile and satisfy the interface
// ---------------------------------------------------------------------------

func TestSourceStubs_Interface(t *testing.T) {
	ctx := context.Background()
	since := time.Now().UTC().AddDate(0, 0, -30)
	topic := "ethereum"

	srcs := []last30days.Source{
		&sources.RedditSource{Subreddits: []string{"CryptoCurrency"}},
		&sources.HackerNewsSource{MinScore: 10},
		&sources.PolymarketSource{},
		&sources.YouTubeSource{MaxResults: 5},
		&sources.XSource{BearerToken: "tok"},
		&sources.WebSource{SearchEndpoint: "https://example.com"},
	}

	for _, src := range srcs {
		t.Run(src.Name(), func(t *testing.T) {
			items, err := src.Collect(ctx, topic, since)
			require.NoError(t, err)
			require.NotEmpty(t, items)
			for _, item := range items {
				assert.Equal(t, src.Name(), item.Source)
				assert.NotEmpty(t, item.ContentHash)
				assert.Len(t, item.ContentHash, 64)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Integration: full pipeline with all stub sources
// ---------------------------------------------------------------------------

func TestPack_Run_WithAllStubSources(t *testing.T) {
	topic := "ethereum"
	pack := &last30days.Pack{
		WindowDays: 30,
		Sources: []last30days.Source{
			&sources.RedditSource{Subreddits: []string{"ethereum"}},
			&sources.HackerNewsSource{MinScore: 0},
			&sources.PolymarketSource{},
			&sources.YouTubeSource{MaxResults: 3},
			&sources.XSource{BearerToken: "stub"},
			&sources.WebSource{SearchEndpoint: "https://example.com"},
		},
	}

	digest, err := pack.Run(context.Background(), topic)
	require.NoError(t, err)
	require.NotNil(t, digest)

	assert.Equal(t, topic, digest.Topic)
	assert.Equal(t, 30, digest.WindowDays)
	assert.NotEmpty(t, digest.Items)
	assert.NotEmpty(t, digest.ContentHash)
	assert.NotEmpty(t, digest.Synthesis.Summary)

	// All stub sources return the topic entity — expect convergence.
	assert.NotEmpty(t, digest.ConvergenceSignals)

	// reddit and x stubs return different stances for the same entity → contradiction.
	assert.Contains(t, digest.Synthesis.Contradictions, topic)
}
