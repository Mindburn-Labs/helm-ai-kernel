package trust

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLeaderboard_DeterministicRanking(t *testing.T) {
	// Create scores in random order
	scores := map[string]*TrustScore{
		"org-c": {ScoreID: "s3", OverallScore: 0.85, ComputedAt: time.Now()},
		"org-a": {ScoreID: "s1", OverallScore: 0.95, ComputedAt: time.Now()},
		"org-b": {ScoreID: "s2", OverallScore: 0.75, ComputedAt: time.Now()},
	}
	orgNames := map[string]string{
		"org-a": "Alpha Corp",
		"org-b": "Beta Inc",
		"org-c": "Charlie LLC",
	}

	// Create leaderboard multiple times
	lb1 := NewLeaderboardFromScores(scores, orgNames)
	lb2 := NewLeaderboardFromScores(scores, orgNames)

	// Verify same ordering
	require.Equal(t, 3, lb1.Count())
	require.Equal(t, 3, lb2.Count())

	for i := range lb1.Entries {
		assert.Equal(t, lb1.Entries[i].OrgID, lb2.Entries[i].OrgID)
		assert.Equal(t, lb1.Entries[i].Rank, lb2.Entries[i].Rank)
	}

	// Verify correct ordering (highest score first)
	assert.Equal(t, "org-a", lb1.Entries[0].OrgID)
	assert.Equal(t, 1, lb1.Entries[0].Rank)
	assert.Equal(t, "org-c", lb1.Entries[1].OrgID)
	assert.Equal(t, 2, lb1.Entries[1].Rank)
	assert.Equal(t, "org-b", lb1.Entries[2].OrgID)
	assert.Equal(t, 3, lb1.Entries[2].Rank)
}

func TestLeaderboard_DeterministicRanking_TieBreaker(t *testing.T) {
	// Same scores - should order by OrgID
	scores := map[string]*TrustScore{
		"org-z": {ScoreID: "s1", OverallScore: 0.80, ComputedAt: time.Now()},
		"org-a": {ScoreID: "s2", OverallScore: 0.80, ComputedAt: time.Now()},
		"org-m": {ScoreID: "s3", OverallScore: 0.80, ComputedAt: time.Now()},
	}
	orgNames := map[string]string{}

	lb := NewLeaderboardFromScores(scores, orgNames)

	// Same score, so ordered by OrgID alphabetically
	assert.Equal(t, "org-a", lb.Entries[0].OrgID)
	assert.Equal(t, "org-m", lb.Entries[1].OrgID)
	assert.Equal(t, "org-z", lb.Entries[2].OrgID)
}

func TestLeaderboard_BadgeLevels(t *testing.T) {
	scores := map[string]*TrustScore{
		"platinum": {ScoreID: "s1", OverallScore: 0.98, ComputedAt: time.Now()},
		"gold":     {ScoreID: "s2", OverallScore: 0.90, ComputedAt: time.Now()},
		"silver":   {ScoreID: "s3", OverallScore: 0.75, ComputedAt: time.Now()},
		"bronze":   {ScoreID: "s4", OverallScore: 0.60, ComputedAt: time.Now()},
		"none":     {ScoreID: "s5", OverallScore: 0.30, ComputedAt: time.Now()},
	}
	orgNames := map[string]string{}

	lb := NewLeaderboardFromScores(scores, orgNames)

	platinumEntry, _ := lb.GetEntry("platinum")
	goldEntry, _ := lb.GetEntry("gold")
	silverEntry, _ := lb.GetEntry("silver")
	bronzeEntry, _ := lb.GetEntry("bronze")
	noneEntry, _ := lb.GetEntry("none")

	assert.Equal(t, BadgePlatinum, platinumEntry.BadgeLevel)
	assert.Equal(t, BadgeGold, goldEntry.BadgeLevel)
	assert.Equal(t, BadgeSilver, silverEntry.BadgeLevel)
	assert.Equal(t, BadgeBronze, bronzeEntry.BadgeLevel)
	assert.Equal(t, BadgeNone, noneEntry.BadgeLevel)
}

func TestLeaderboard_UpdateAndRerank(t *testing.T) {
	lb := NewLeaderboard()

	// Add initial scores
	lb.UpdateScore("org-a", "Alpha Corp", &TrustScore{
		ScoreID:      "s1",
		OverallScore: 0.70,
		ComputedAt:   time.Now(),
	})
	lb.UpdateScore("org-b", "Beta Inc", &TrustScore{
		ScoreID:      "s2",
		OverallScore: 0.80,
		ComputedAt:   time.Now(),
	})
	lb.Rank()

	// org-b should be first
	assert.Equal(t, "org-b", lb.Entries[0].OrgID)
	assert.Equal(t, 1, lb.Entries[0].Rank)

	// Update org-a to have higher score
	lb.UpdateScore("org-a", "Alpha Corp", &TrustScore{
		ScoreID:      "s3",
		OverallScore: 0.95,
		ComputedAt:   time.Now(),
	})
	lb.Rank()

	// Now org-a should be first
	assert.Equal(t, "org-a", lb.Entries[0].OrgID)
	assert.Equal(t, 1, lb.Entries[0].Rank)
}

func TestLeaderboard_GetTopN(t *testing.T) {
	scores := map[string]*TrustScore{
		"org-1": {ScoreID: "s1", OverallScore: 0.90, ComputedAt: time.Now()},
		"org-2": {ScoreID: "s2", OverallScore: 0.85, ComputedAt: time.Now()},
		"org-3": {ScoreID: "s3", OverallScore: 0.80, ComputedAt: time.Now()},
		"org-4": {ScoreID: "s4", OverallScore: 0.75, ComputedAt: time.Now()},
		"org-5": {ScoreID: "s5", OverallScore: 0.70, ComputedAt: time.Now()},
	}
	orgNames := map[string]string{}

	lb := NewLeaderboardFromScores(scores, orgNames)

	top3 := lb.GetTopN(3)
	require.Len(t, top3, 3)
	assert.Equal(t, "org-1", top3[0].OrgID)
	assert.Equal(t, "org-2", top3[1].OrgID)
	assert.Equal(t, "org-3", top3[2].OrgID)

	// Request more than available
	top10 := lb.GetTopN(10)
	assert.Len(t, top10, 5)
}

func TestLeaderboard_GetByBadge(t *testing.T) {
	scores := map[string]*TrustScore{
		"platinum-1": {ScoreID: "s1", OverallScore: 0.98, ComputedAt: time.Now()},
		"platinum-2": {ScoreID: "s2", OverallScore: 0.96, ComputedAt: time.Now()},
		"gold-1":     {ScoreID: "s3", OverallScore: 0.90, ComputedAt: time.Now()},
		"silver-1":   {ScoreID: "s4", OverallScore: 0.75, ComputedAt: time.Now()},
	}
	orgNames := map[string]string{}

	lb := NewLeaderboardFromScores(scores, orgNames)

	platinumOrgs := lb.GetByBadge(BadgePlatinum)
	goldOrgs := lb.GetByBadge(BadgeGold)
	silverOrgs := lb.GetByBadge(BadgeSilver)
	bronzeOrgs := lb.GetByBadge(BadgeBronze)

	assert.Len(t, platinumOrgs, 2)
	assert.Len(t, goldOrgs, 1)
	assert.Len(t, silverOrgs, 1)
	assert.Len(t, bronzeOrgs, 0)
}

func TestLeaderboard_Export(t *testing.T) {
	scores := map[string]*TrustScore{
		"org-a": {ScoreID: "s1", OverallScore: 0.95, ComputedAt: time.Now()},
		"org-b": {ScoreID: "s2", OverallScore: 0.75, ComputedAt: time.Now()},
	}
	orgNames := map[string]string{
		"org-a": "Alpha Corp",
		"org-b": "Beta Inc",
	}

	lb := NewLeaderboardFromScores(scores, orgNames)
	export := lb.Export()

	assert.Equal(t, 2, export.TotalOrgs)
	assert.Equal(t, 2, len(export.Entries))
	assert.NotEmpty(t, export.Hash)
	assert.Equal(t, 0.85, export.AverageScore) // (0.95 + 0.75) / 2

	// Badge summary: org-a at 0.95 is GOLD (>0.95 for Platinum), org-b at 0.75 is SILVER
	assert.Equal(t, 1, export.BadgeSummary["GOLD"])
	assert.Equal(t, 1, export.BadgeSummary["SILVER"])
}

func TestLeaderboard_Hash_Deterministic(t *testing.T) {
	scores := map[string]*TrustScore{
		"org-a": {ScoreID: "s1", OverallScore: 0.95, ComputedAt: time.Now()},
		"org-b": {ScoreID: "s2", OverallScore: 0.75, ComputedAt: time.Now()},
	}
	orgNames := map[string]string{}

	lb1 := NewLeaderboardFromScores(scores, orgNames)
	lb2 := NewLeaderboardFromScores(scores, orgNames)

	// Need to sync LeaderboardID for hash comparison
	lb2.LeaderboardID = lb1.LeaderboardID

	hash1 := lb1.Hash()
	hash2 := lb2.Hash()

	assert.Equal(t, hash1, hash2)
	assert.NotEmpty(t, hash1)
}

func TestGetBadgeLevel(t *testing.T) {
	tests := []struct {
		score    float64
		expected BadgeLevel
	}{
		{0.98, BadgePlatinum},
		{0.96, BadgePlatinum},
		{0.951, BadgePlatinum},
		{0.95, BadgeGold}, // Exactly 0.95 is Gold (> 0.95 is Platinum)
		{0.90, BadgeGold},
		{0.86, BadgeGold},
		{0.85, BadgeSilver},
		{0.75, BadgeSilver},
		{0.70, BadgeBronze},
		{0.60, BadgeBronze},
		{0.50, BadgeNone},
		{0.30, BadgeNone},
	}

	for _, tc := range tests {
		t.Run("", func(t *testing.T) {
			assert.Equal(t, tc.expected, GetBadgeLevel(tc.score))
		})
	}
}
