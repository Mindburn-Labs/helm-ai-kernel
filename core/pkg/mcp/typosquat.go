// typosquat.go implements typosquatting detection for MCP tool names.
// When tools from different servers have suspiciously similar names
// (Levenshtein distance <= threshold), a finding is generated.
//
// Design invariants:
//   - Only cross-server comparisons (same-server duplicates are legitimate)
//   - Distance threshold is configurable (default: 2)
//   - Deterministic: same tool set → same findings
//   - Thread-safe for concurrent server connections
package mcp

import (
	"sync"
	"time"
)

// TyposquatFinding describes a detected case of suspicious name similarity
// between tools registered on different MCP servers.
type TyposquatFinding struct {
	ToolName      string    `json:"tool_name"`
	ServerID      string    `json:"server_id"`
	SimilarTool   string    `json:"similar_tool"`
	SimilarServer string    `json:"similar_server"`
	Distance      int       `json:"distance"`
	DetectedAt    time.Time `json:"detected_at"`
}

// TyposquatOption configures optional TyposquatDetector settings.
type TyposquatOption func(*TyposquatDetector)

// TyposquatDetector checks MCP tool names for potential typosquatting by
// comparing names across servers using Levenshtein edit distance.
type TyposquatDetector struct {
	mu        sync.RWMutex
	tools     map[string]string // toolName -> serverID
	threshold int
	clock     func() time.Time
}

// defaultTyposquatThreshold is the maximum Levenshtein distance to flag as suspicious.
const defaultTyposquatThreshold = 2
