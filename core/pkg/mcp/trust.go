// trust.go computes trust scores for MCP tools based on behavioral history.
//
// Scoring factors:
//   - Schema stability: tools that change descriptions/schemas get lower scores
//   - Uptime: tools that consistently respond get higher scores
//   - Error rate: tools with frequent errors get lower scores
//   - Age: longer-registered tools get stability bonus
//
// Design invariants:
//   - Scores are deterministic given the same history
//   - New tools start at 500 (neutral)
//   - Score range: 0-1000
//   - Thread-safe for concurrent updates
package mcp

import (
	"sort"
	"sync"
	"time"
)

// TrustTier classifies an MCP tool's trust level based on its score.
type TrustTier string

const (
	TrustTierUntrusted    TrustTier = "UNTRUSTED"    // 0-199
	TrustTierProbationary TrustTier = "PROBATIONARY"  // 200-399
	TrustTierStandard     TrustTier = "STANDARD"      // 400-599
	TrustTierTrusted      TrustTier = "TRUSTED"       // 600-799
	TrustTierVerified     TrustTier = "VERIFIED"      // 800-1000
)

// TrustScore represents the computed trust assessment for an MCP tool.
type TrustScore struct {
	ToolName        string    `json:"tool_name"`
	ServerID        string    `json:"server_id"`
	Score           int       `json:"score"`       // 0-1000
	Tier            TrustTier `json:"tier"`
	SchemaChanges   int       `json:"schema_changes"`
	TotalCalls      int64     `json:"total_calls"`
	SuccessfulCalls int64     `json:"successful_calls"`
	FailedCalls     int64     `json:"failed_calls"`
	FirstSeen       time.Time `json:"first_seen"`
	LastSeen        time.Time `json:"last_seen"`
	LastScoreChange time.Time `json:"last_score_change"`
}

// TrustScorerOption configures a TrustScorer.
type TrustScorerOption func(*TrustScorer)

// WithTrustClock sets a custom clock for deterministic testing.
func WithTrustClock(clock func() time.Time) TrustScorerOption {
	return func(s *TrustScorer) {
		s.clock = clock
	}
}

// FederatedTrustReport represents trust information received from a federated peer.
type FederatedTrustReport struct {
	PeerID     string    `json:"peer_id"`
	ServerID   string    `json:"server_id"`
	ToolName   string    `json:"tool_name"`
	Score      int       `json:"score"`       // 0-1000
	ReportedAt time.Time `json:"reported_at"`
}

// TrustScorer computes and tracks trust scores for MCP tools.
type TrustScorer struct {
	mu               sync.RWMutex
	scores           map[string]*TrustScore            // key: "serverID:toolName"
	federatedReports map[string][]FederatedTrustReport  // key: "serverID:toolName"
	clock            func() time.Time
}

// NewTrustScorer creates a new TrustScorer with the given options.
func NewTrustScorer(opts ...TrustScorerOption) *TrustScorer {
	s := &TrustScorer{
		scores:           make(map[string]*TrustScore),
		federatedReports: make(map[string][]FederatedTrustReport),
		clock:            time.Now,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

func trustKey(serverID, toolName string) string {
	return serverID + ":" + toolName
}

// getOrCreate returns the TrustScore for the given tool, creating one if it
// does not yet exist. Caller must hold s.mu for writing.
func (s *TrustScorer) getOrCreate(serverID, toolName string) *TrustScore {
	key := trustKey(serverID, toolName)
	ts, ok := s.scores[key]
	if !ok {
		now := s.clock()
		ts = &TrustScore{
			ToolName:        toolName,
			ServerID:        serverID,
			Score:           500,
			Tier:            TrustTierStandard,
			FirstSeen:       now,
			LastSeen:        now,
			LastScoreChange: now,
		}
		s.scores[key] = ts
	}
	return ts
}

// recalculate recomputes the score from the tool's accumulated history.
// Caller must hold s.mu for writing.
//
// Algorithm:
//
//	base                = 500
//	success_rate_bonus  = (successful / total) * 300       (max +300)
//	stability_penalty   = schema_changes * -50             (max -250)
//	age_bonus           = min(days_since_first_seen, 30)*5 (max +150)
//	error_penalty       = min(failed / total, 1.0) * -200  (max -200)
//	score = clamp(base + success_rate_bonus + stability_penalty + age_bonus + error_penalty, 0, 1000)
func (s *TrustScorer) recalculate(ts *TrustScore) {
	now := s.clock()
	oldScore := ts.Score

	score := 500.0

	// Success rate bonus (max +300)
	if ts.TotalCalls > 0 {
		successRate := float64(ts.SuccessfulCalls) / float64(ts.TotalCalls)
		score += successRate * 300.0
	}

	// Schema stability penalty (max -250)
	penalty := ts.SchemaChanges * 50
	if penalty > 250 {
		penalty = 250
	}
	score -= float64(penalty)

	// Age bonus (max +150)
	daysSinceFirst := now.Sub(ts.FirstSeen).Hours() / 24.0
	if daysSinceFirst > 30 {
		daysSinceFirst = 30
	}
	score += daysSinceFirst * 5.0

	// Error penalty (max -200)
	if ts.TotalCalls > 0 {
		errorRate := float64(ts.FailedCalls) / float64(ts.TotalCalls)
		if errorRate > 1.0 {
			errorRate = 1.0
		}
		score -= errorRate * 200.0
	}

	// Blend with federated reports: final = 0.7 * local + 0.3 * avg(federated)
	key := trustKey(ts.ServerID, ts.ToolName)
	if reports, ok := s.federatedReports[key]; ok && len(reports) > 0 {
		var fedSum int
		for _, r := range reports {
			fedSum += r.Score
		}
		fedAvg := float64(fedSum) / float64(len(reports))
		score = 0.7*score + 0.3*fedAvg
	}

	// Clamp
	intScore := int(score)
	if intScore < 0 {
		intScore = 0
	}
	if intScore > 1000 {
		intScore = 1000
	}

	ts.Score = intScore
	ts.Tier = tierFromScore(intScore)
	ts.LastSeen = now
	if intScore != oldScore {
		ts.LastScoreChange = now
	}
}

// RecordSuccess records a successful tool invocation and recalculates the score.
func (s *TrustScorer) RecordSuccess(serverID, toolName string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ts := s.getOrCreate(serverID, toolName)
	ts.TotalCalls++
	ts.SuccessfulCalls++
	s.recalculate(ts)
}

// RecordFailure records a failed tool invocation and recalculates the score.
func (s *TrustScorer) RecordFailure(serverID, toolName string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ts := s.getOrCreate(serverID, toolName)
	ts.TotalCalls++
	ts.FailedCalls++
	s.recalculate(ts)
}

// RecordSchemaChange records a schema mutation (description or input schema
// changed) and penalizes the tool's trust score.
func (s *TrustScorer) RecordSchemaChange(serverID, toolName string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ts := s.getOrCreate(serverID, toolName)
	ts.SchemaChanges++
	s.recalculate(ts)
}

// GetScore returns the current trust score for a tool, or (nil, false) if
// the tool has never been observed.
func (s *TrustScorer) GetScore(serverID, toolName string) (*TrustScore, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key := trustKey(serverID, toolName)
	ts, ok := s.scores[key]
	if !ok {
		return nil, false
	}
	// Return a copy so the caller cannot mutate internal state.
	cp := *ts
	return &cp, true
}

// AllScores returns a snapshot of all tracked trust scores, sorted by
// server ID then tool name.
func (s *TrustScorer) AllScores() []*TrustScore {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*TrustScore, 0, len(s.scores))
	for _, ts := range s.scores {
		cp := *ts
		result = append(result, &cp)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].ServerID != result[j].ServerID {
			return result[i].ServerID < result[j].ServerID
		}
		return result[i].ToolName < result[j].ToolName
	})
	return result
}

// RecordFederatedReport incorporates a trust report from a federated peer.
// Federated scores are blended with local scores: final = 0.7*local + 0.3*avg(federated).
// This implements trust-but-verify: local observations dominate, but peer
// intelligence is factored in to detect threats seen elsewhere.
func (s *TrustScorer) RecordFederatedReport(report FederatedTrustReport) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := trustKey(report.ServerID, report.ToolName)
	s.federatedReports[key] = append(s.federatedReports[key], report)

	// Recalculate if we already have a local score for this tool.
	if ts, ok := s.scores[key]; ok {
		s.recalculate(ts)
	}
}

// tierFromScore maps a numeric score to its TrustTier.
func tierFromScore(score int) TrustTier {
	switch {
	case score < 200:
		return TrustTierUntrusted
	case score < 400:
		return TrustTierProbationary
	case score < 600:
		return TrustTierStandard
	case score < 800:
		return TrustTierTrusted
	default:
		return TrustTierVerified
	}
}
