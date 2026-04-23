// Package trust - leaderboard.go
// Provides trust leaderboard for ranking organizations.
// Per Section 6.4 - multi-dimensional trust scoring and ranking.

package trust

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
)

// BadgeLevel represents trust certification levels.
type BadgeLevel string

const (
	BadgePlatinum BadgeLevel = "PLATINUM" // > 0.95
	BadgeGold     BadgeLevel = "GOLD"     // > 0.85
	BadgeSilver   BadgeLevel = "SILVER"   // > 0.70
	BadgeBronze   BadgeLevel = "BRONZE"   // > 0.50
	BadgeNone     BadgeLevel = ""         // <= 0.50
)

// GetBadgeLevel calculates badge level from overall score.
func GetBadgeLevel(score float64) BadgeLevel {
	switch {
	case score > 0.95:
		return BadgePlatinum
	case score > 0.85:
		return BadgeGold
	case score > 0.70:
		return BadgeSilver
	case score > 0.50:
		return BadgeBronze
	default:
		return BadgeNone
	}
}

// LeaderboardEntry represents a ranked organization.
type LeaderboardEntry struct {
	Rank       int         `json:"rank"`
	OrgID      string      `json:"org_id"`
	OrgName    string      `json:"org_name"`
	TrustScore *TrustScore `json:"trust_score"`
	BadgeLevel BadgeLevel  `json:"badge_level"`
	UpdatedAt  time.Time   `json:"updated_at"`
}

// Leaderboard ranks organizations by trust scores.
type Leaderboard struct {
	LeaderboardID string             `json:"leaderboard_id"`
	ComputedAt    time.Time          `json:"computed_at"`
	Entries       []LeaderboardEntry `json:"entries"`
	scoresByOrg   map[string]*TrustScore
	orgNames      map[string]string
	mu            sync.RWMutex
}

// NewLeaderboard creates a new leaderboard.
func NewLeaderboard() *Leaderboard {
	return &Leaderboard{
		LeaderboardID: uuid.New().String(),
		ComputedAt:    time.Now(),
		Entries:       []LeaderboardEntry{},
		scoresByOrg:   make(map[string]*TrustScore),
		orgNames:      make(map[string]string),
	}
}

// NewLeaderboardFromScores creates a ranked leaderboard from existing scores.
func NewLeaderboardFromScores(scores map[string]*TrustScore, orgNames map[string]string) *Leaderboard {
	lb := NewLeaderboard()

	for orgID, score := range scores {
		name := orgNames[orgID]
		if name == "" {
			name = orgID
		}
		lb.scoresByOrg[orgID] = score
		lb.orgNames[orgID] = name
	}

	lb.Rank()
	return lb
}

// UpdateScore adds or updates an organization's score.
func (l *Leaderboard) UpdateScore(orgID, orgName string, score *TrustScore) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.scoresByOrg[orgID] = score
	l.orgNames[orgID] = orgName
}

// Rank re-computes deterministic rankings.
// Uses SliceStable with ordering by (OverallScore DESC, OrgID ASC).
func (l *Leaderboard) Rank() {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Build entries from scores
	l.Entries = make([]LeaderboardEntry, 0, len(l.scoresByOrg))
	for orgID, score := range l.scoresByOrg {
		name := l.orgNames[orgID]
		if name == "" {
			name = orgID
		}

		l.Entries = append(l.Entries, LeaderboardEntry{
			OrgID:      orgID,
			OrgName:    name,
			TrustScore: score,
			BadgeLevel: GetBadgeLevel(score.OverallScore),
			UpdatedAt:  score.ComputedAt,
		})
	}

	// Deterministic sort: highest score first, then by OrgID for ties
	sort.SliceStable(l.Entries, func(i, j int) bool {
		if l.Entries[i].TrustScore.OverallScore != l.Entries[j].TrustScore.OverallScore {
			return l.Entries[i].TrustScore.OverallScore > l.Entries[j].TrustScore.OverallScore
		}
		return l.Entries[i].OrgID < l.Entries[j].OrgID
	})

	// Assign ranks
	for i := range l.Entries {
		l.Entries[i].Rank = i + 1
	}

	l.ComputedAt = time.Now()
}

// GetEntry retrieves an organization's entry.
func (l *Leaderboard) GetEntry(orgID string) (*LeaderboardEntry, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	for i := range l.Entries {
		if l.Entries[i].OrgID == orgID {
			return &l.Entries[i], true
		}
	}
	return nil, false
}

// GetTopN returns the top N entries.
func (l *Leaderboard) GetTopN(n int) []LeaderboardEntry {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if n > len(l.Entries) {
		n = len(l.Entries)
	}

	result := make([]LeaderboardEntry, n)
	copy(result, l.Entries[:n])
	return result
}

// GetByBadge returns entries with a specific badge level.
func (l *Leaderboard) GetByBadge(badge BadgeLevel) []LeaderboardEntry {
	l.mu.RLock()
	defer l.mu.RUnlock()

	result := []LeaderboardEntry{}
	for _, entry := range l.Entries {
		if entry.BadgeLevel == badge {
			result = append(result, entry)
		}
	}
	return result
}

// LeaderboardExport is a JSON-serializable view.
type LeaderboardExport struct {
	LeaderboardID string             `json:"leaderboard_id"`
	ComputedAt    time.Time          `json:"computed_at"`
	TotalOrgs     int                `json:"total_orgs"`
	Entries       []LeaderboardEntry `json:"entries"`
	BadgeSummary  map[string]int     `json:"badge_summary"`
	AverageScore  float64            `json:"average_score"`
	Hash          string             `json:"hash"`
}

// Export returns a JSON-serializable view of the leaderboard.
func (l *Leaderboard) Export() *LeaderboardExport {
	l.mu.RLock()
	defer l.mu.RUnlock()

	export := &LeaderboardExport{
		LeaderboardID: l.LeaderboardID,
		ComputedAt:    l.ComputedAt,
		TotalOrgs:     len(l.Entries),
		Entries:       l.Entries,
		BadgeSummary:  make(map[string]int),
	}

	// Compute badge summary and average
	var totalScore float64
	for _, entry := range l.Entries {
		export.BadgeSummary[string(entry.BadgeLevel)]++
		totalScore += entry.TrustScore.OverallScore
	}

	if len(l.Entries) > 0 {
		export.AverageScore = totalScore / float64(len(l.Entries))
	}

	// Compute deterministic hash
	export.Hash = l.computeHash()

	return export
}

// computeHash computes a deterministic hash of the leaderboard state.
func (l *Leaderboard) computeHash() string {
	// Create deterministic representation
	hashData := struct {
		LeaderboardID string `json:"leaderboard_id"`
		OrgCount      int    `json:"org_count"`
		Rankings      []struct {
			Rank  int     `json:"rank"`
			OrgID string  `json:"org_id"`
			Score float64 `json:"score"`
		} `json:"rankings"`
	}{
		LeaderboardID: l.LeaderboardID,
		OrgCount:      len(l.Entries),
	}

	for _, entry := range l.Entries {
		hashData.Rankings = append(hashData.Rankings, struct {
			Rank  int     `json:"rank"`
			OrgID string  `json:"org_id"`
			Score float64 `json:"score"`
		}{
			Rank:  entry.Rank,
			OrgID: entry.OrgID,
			Score: entry.TrustScore.OverallScore,
		})
	}

	data, _ := json.Marshal(hashData)
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// Hash returns the current hash of the leaderboard.
func (l *Leaderboard) Hash() string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.computeHash()
}

// Count returns the number of organizations.
func (l *Leaderboard) Count() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.Entries)
}
