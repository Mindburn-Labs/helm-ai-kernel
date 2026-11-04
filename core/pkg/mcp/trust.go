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
	"sync"
	"time"
)

// TrustTier classifies an MCP tool's trust level based on its score.
type TrustTier string

const (
	TrustTierUntrusted    TrustTier = "UNTRUSTED"    // 0-199
	TrustTierProbationary TrustTier = "PROBATIONARY" // 200-399
	TrustTierStandard     TrustTier = "STANDARD"     // 400-599
	TrustTierTrusted      TrustTier = "TRUSTED"      // 600-799
	TrustTierVerified     TrustTier = "VERIFIED"     // 800-1000
)

// TrustScore represents the computed trust assessment for an MCP tool.
type TrustScore struct {
	ToolName        string    `json:"tool_name"`
	ServerID        string    `json:"server_id"`
	Score           int       `json:"score"` // 0-1000
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

// FederatedTrustReport represents trust information received from a federated peer.
type FederatedTrustReport struct {
	PeerID     string    `json:"peer_id"`
	ServerID   string    `json:"server_id"`
	ToolName   string    `json:"tool_name"`
	Score      int       `json:"score"` // 0-1000
	ReportedAt time.Time `json:"reported_at"`
}

// TrustScorer computes and tracks trust scores for MCP tools.
type TrustScorer struct {
	mu               sync.RWMutex
	scores           map[string]*TrustScore            // key: "serverID:toolName"
	federatedReports map[string][]FederatedTrustReport // key: "serverID:toolName"
	clock            func() time.Time
}
