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
	"log/slog"
	"sort"
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

// NewTyposquatDetector creates a new typosquatting detector with the given options.
func NewTyposquatDetector(opts ...TyposquatOption) *TyposquatDetector {
	d := &TyposquatDetector{
		tools:     make(map[string]string),
		threshold: defaultTyposquatThreshold,
		clock:     time.Now,
	}
	for _, opt := range opts {
		opt(d)
	}
	return d
}

// WithTyposquatThreshold sets the maximum Levenshtein distance for flagging
// tool names as suspicious. Distance must be >= 1; values < 1 are ignored.
func WithTyposquatThreshold(n int) TyposquatOption {
	return func(d *TyposquatDetector) {
		if n >= 1 {
			d.threshold = n
		}
	}
}

// WithTyposquatClock injects a deterministic clock for testing.
func WithTyposquatClock(clock func() time.Time) TyposquatOption {
	return func(d *TyposquatDetector) {
		d.clock = clock
	}
}

// Check compares a tool name against all registered tools from OTHER servers.
// If any existing tool from a different server has a Levenshtein distance
// within the threshold (and the names are not identical), a finding is returned
// for each match. Identical names on different servers are NOT flagged
// (distance 0 means it is the same tool, not a typosquat).
//
// Check does NOT register the tool. Call Register separately after Check
// if the tool should be added to the known set.
func (d *TyposquatDetector) Check(serverID, toolName string) []TyposquatFinding {
	now := d.clock()

	d.mu.RLock()
	// Snapshot the tools map under read lock for deterministic iteration.
	type entry struct {
		name     string
		serverID string
	}
	entries := make([]entry, 0, len(d.tools))
	for name, sid := range d.tools {
		entries = append(entries, entry{name: name, serverID: sid})
	}
	d.mu.RUnlock()

	// Sort entries for deterministic output.
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].name < entries[j].name
	})

	var findings []TyposquatFinding
	for _, e := range entries {
		// Skip same-server tools — duplicates on the same server are legitimate.
		if e.serverID == serverID {
			continue
		}
		// Skip identical names (distance 0). Same tool name on a different server
		// is not typosquatting — it could be a legitimate tool.
		if e.name == toolName {
			continue
		}

		dist := levenshtein(toolName, e.name)
		if dist <= d.threshold {
			finding := TyposquatFinding{
				ToolName:      toolName,
				ServerID:      serverID,
				SimilarTool:   e.name,
				SimilarServer: e.serverID,
				Distance:      dist,
				DetectedAt:    now,
			}
			findings = append(findings, finding)

			slog.Warn("typosquat: suspicious tool name similarity detected",
				"tool", toolName,
				"server", serverID,
				"similar_tool", e.name,
				"similar_server", e.serverID,
				"distance", dist,
			)
		}
	}

	return findings
}

// Register adds a tool to the known set for future comparisons.
// If a tool with the same name already exists, it is overwritten with the
// new server ID.
func (d *TyposquatDetector) Register(serverID, toolName string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.tools[toolName] = serverID
}

// levenshtein computes the Levenshtein edit distance between two strings
// using a standard dynamic-programming algorithm. The distance is the minimum
// number of single-character edits (insertions, deletions, substitutions)
// required to transform a into b.
func levenshtein(a, b string) int {
	la := len(a)
	lb := len(b)

	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}

	// Use a single row for space efficiency: O(min(la, lb)).
	// Ensure b is the shorter string to minimise memory.
	if la < lb {
		a, b = b, a
		la, lb = lb, la
	}

	prev := make([]int, lb+1)
	curr := make([]int, lb+1)

	for j := 0; j <= lb; j++ {
		prev[j] = j
	}

	for i := 1; i <= la; i++ {
		curr[0] = i
		for j := 1; j <= lb; j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			ins := curr[j-1] + 1
			del := prev[j] + 1
			sub := prev[j-1] + cost
			curr[j] = min3(ins, del, sub)
		}
		prev, curr = curr, prev
	}

	return prev[lb]
}

// min3 returns the minimum of three integers.
func min3(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}
