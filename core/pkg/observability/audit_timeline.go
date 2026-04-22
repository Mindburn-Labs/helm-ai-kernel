// Package observability — Unified Audit Timeline.
//
// Per HELM 2030 Spec:
//   - Every action, tool call, decision, proof, and reconciliation
//     result appears in a unified, queryable timeline
//   - Queryable by run, tenant, time range
package observability

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"
)

// TimelineEntryType categorizes audit entries.
type TimelineEntryType string

const (
	EntryTypeAction         TimelineEntryType = "ACTION"
	EntryTypeToolCall       TimelineEntryType = "TOOL_CALL"
	EntryTypeDecision       TimelineEntryType = "DECISION"
	EntryTypeProof          TimelineEntryType = "PROOF"
	EntryTypeReconciliation TimelineEntryType = "RECONCILIATION"
	EntryTypeEscalation     TimelineEntryType = "ESCALATION"
	EntryTypeEvidence       TimelineEntryType = "EVIDENCE"
)

// TimelineEntry is a single auditable event.
type TimelineEntry struct {
	EntryID     string                 `json:"entry_id"`
	EntryType   TimelineEntryType      `json:"entry_type"`
	RunID       string                 `json:"run_id"`
	TenantID    string                 `json:"tenant_id"`
	Timestamp   time.Time              `json:"timestamp"`
	Actor       string                 `json:"actor,omitempty"`
	Summary     string                 `json:"summary"`
	ContentHash string                 `json:"content_hash"`
	Details     map[string]interface{} `json:"details,omitempty"`
}

// TimelineQuery filters timeline entries.
type TimelineQuery struct {
	RunID     string             `json:"run_id,omitempty"`
	TenantID  string             `json:"tenant_id,omitempty"`
	EntryType *TimelineEntryType `json:"entry_type,omitempty"`
	After     *time.Time         `json:"after,omitempty"`
	Before    *time.Time         `json:"before,omitempty"`
	Limit     int                `json:"limit,omitempty"`
}

// AuditTimeline collects and queries audit events.
type AuditTimeline struct {
	mu      sync.RWMutex
	entries []TimelineEntry
	index   map[string][]int // runID → entry indices
	seq     int64
	clock   func() time.Time
}

// NewAuditTimeline creates a new timeline.
func NewAuditTimeline() *AuditTimeline {
	return &AuditTimeline{
		entries: make([]TimelineEntry, 0),
		index:   make(map[string][]int),
		clock:   time.Now,
	}
}

// WithClock overrides clock for testing.
func (t *AuditTimeline) WithClock(clock func() time.Time) *AuditTimeline {
	t.clock = clock
	return t
}

// Record adds an entry to the timeline.
func (t *AuditTimeline) Record(entry TimelineEntry) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.seq++
	if entry.EntryID == "" {
		entry.EntryID = fmt.Sprintf("tl-%d", t.seq)
	}
	if entry.Timestamp.IsZero() {
		entry.Timestamp = t.clock()
	}

	// Compute content hash
	data, err := json.Marshal(entry.Details)
	if err != nil {
		return err
	}
	h := sha256.Sum256(data)
	entry.ContentHash = "sha256:" + hex.EncodeToString(h[:])

	idx := len(t.entries)
	t.entries = append(t.entries, entry)

	if entry.RunID != "" {
		t.index[entry.RunID] = append(t.index[entry.RunID], idx)
	}

	return nil
}

// Query retrieves entries matching the query.
func (t *AuditTimeline) Query(q TimelineQuery) []TimelineEntry {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var candidates []TimelineEntry

	if q.RunID != "" {
		indices, ok := t.index[q.RunID]
		if !ok {
			return nil
		}
		for _, i := range indices {
			candidates = append(candidates, t.entries[i])
		}
	} else {
		candidates = make([]TimelineEntry, len(t.entries))
		copy(candidates, t.entries)
	}

	// Apply filters
	var results []TimelineEntry
	for _, e := range candidates {
		if q.TenantID != "" && e.TenantID != q.TenantID {
			continue
		}
		if q.EntryType != nil && e.EntryType != *q.EntryType {
			continue
		}
		if q.After != nil && e.Timestamp.Before(*q.After) {
			continue
		}
		if q.Before != nil && e.Timestamp.After(*q.Before) {
			continue
		}
		results = append(results, e)
	}

	// Sort by timestamp
	sort.Slice(results, func(i, j int) bool {
		return results[i].Timestamp.Before(results[j].Timestamp)
	})

	if q.Limit > 0 && len(results) > q.Limit {
		results = results[:q.Limit]
	}

	return results
}

// Count returns total entries.
func (t *AuditTimeline) Count() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.entries)
}
