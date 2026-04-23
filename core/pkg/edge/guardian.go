// Package edge provides a minimal Guardian runtime for resource-constrained
// environments (IoT, mobile, embedded, browser via WASM).
//
// The Edge Guardian (µ-HELM) implements the core governance loop with a
// minimal footprint (~2-5MB compiled to WASM). It evaluates policies locally
// using an in-memory rule set and anchors proofs asynchronously to a
// cloud-based Rekor transparency log.
//
// Designed for environments where:
//   - Network round-trips to a HELM server are too slow or unavailable
//   - Resources are constrained (memory, CPU, storage)
//   - Governance must happen at the edge (latency-sensitive decisions)
//   - Proofs must be anchored eventually (async, not synchronous)
package edge

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// EdgeConfig configures the minimal edge guardian.
type EdgeConfig struct {
	DeviceID       string        `json:"device_id"`
	PolicyRules    []PolicyRule  `json:"policy_rules"`
	DefaultVerdict string        `json:"default_verdict"` // "DENY" (fail-closed) or "ALLOW"
	MaxQueueSize   int           `json:"max_queue_size"`  // proof anchor queue depth
	SyncInterval   time.Duration `json:"sync_interval"`   // how often to flush proofs
}

// PolicyRule is a lightweight policy rule for edge evaluation.
// Simpler than full CEL — designed for O(1) lookup.
type PolicyRule struct {
	Action  string `json:"action"`  // effect type to match
	Verdict string `json:"verdict"` // "ALLOW" or "DENY"
	Reason  string `json:"reason,omitempty"`
}

// EdgeDecision is the result of an edge governance evaluation.
type EdgeDecision struct {
	DecisionID  string    `json:"decision_id"`
	DeviceID    string    `json:"device_id"`
	Action      string    `json:"action"`
	Principal   string    `json:"principal"`
	Verdict     string    `json:"verdict"`
	Reason      string    `json:"reason"`
	Timestamp   time.Time `json:"timestamp"`
	ContentHash string    `json:"content_hash"`
	Anchored    bool      `json:"anchored"`
	QueueFull   bool      `json:"queue_full"` // true when the proof anchor queue was at capacity
}

// EdgeGuardian is a minimal governance engine for edge/IoT deployment.
// It evaluates policies locally and queues proofs for async anchoring.
type EdgeGuardian struct {
	config    EdgeConfig
	rules     map[string]PolicyRule // action -> rule (O(1) lookup)
	queue     []EdgeDecision        // proof anchor queue
	decisions []EdgeDecision        // audit trail
	clock     func() time.Time
	mu        sync.Mutex
	seq       uint64
}

// NewEdgeGuardian creates a minimal edge guardian.
func NewEdgeGuardian(config EdgeConfig) *EdgeGuardian {
	if config.DefaultVerdict == "" {
		config.DefaultVerdict = "DENY" // fail-closed
	}
	if config.MaxQueueSize == 0 {
		config.MaxQueueSize = 1000
	}

	rules := make(map[string]PolicyRule, len(config.PolicyRules))
	for _, r := range config.PolicyRules {
		rules[r.Action] = r
	}

	return &EdgeGuardian{
		config: config,
		rules:  rules,
		clock:  func() time.Time { return time.Now() },
	}
}

// WithClock injects a deterministic clock for testing.
func (g *EdgeGuardian) WithClock(clock func() time.Time) {
	g.clock = clock
}

// Evaluate performs a lightweight governance decision at the edge.
// This is the hot path — must be fast (target: <10µs).
func (g *EdgeGuardian) Evaluate(principal, action string) *EdgeDecision {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.seq++
	now := g.clock()

	verdict := g.config.DefaultVerdict
	reason := "default policy"

	if rule, ok := g.rules[action]; ok {
		verdict = rule.Verdict
		reason = rule.Reason
		if reason == "" {
			reason = fmt.Sprintf("rule match: %s", action)
		}
	}

	decision := EdgeDecision{
		DecisionID: fmt.Sprintf("edge-%s-%d", g.config.DeviceID, g.seq),
		DeviceID:   g.config.DeviceID,
		Action:     action,
		Principal:  principal,
		Verdict:    verdict,
		Reason:     reason,
		Timestamp:  now,
		Anchored:   false,
	}

	// Compute content hash
	hashData, _ := json.Marshal(struct {
		DeviceID  string `json:"device_id"`
		Action    string `json:"action"`
		Principal string `json:"principal"`
		Verdict   string `json:"verdict"`
		Seq       uint64 `json:"seq"`
	}{g.config.DeviceID, action, principal, verdict, g.seq})
	h := sha256.Sum256(hashData)
	decision.ContentHash = "sha256:" + hex.EncodeToString(h[:])

	// Queue for async anchoring
	if len(g.queue) < g.config.MaxQueueSize {
		g.queue = append(g.queue, decision)
	} else {
		decision.QueueFull = true
	}

	// Audit trail
	g.decisions = append(g.decisions, decision)

	return &decision
}

// FlushQueue returns all unanchored decisions and clears the queue.
// The caller is responsible for anchoring these to a transparency log.
func (g *EdgeGuardian) FlushQueue() []EdgeDecision {
	g.mu.Lock()
	defer g.mu.Unlock()

	flushed := make([]EdgeDecision, len(g.queue))
	copy(flushed, g.queue)
	g.queue = g.queue[:0]
	return flushed
}

// QueueSize returns the number of unanchored decisions.
func (g *EdgeGuardian) QueueSize() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.queue)
}

// DecisionCount returns the total number of decisions made.
func (g *EdgeGuardian) DecisionCount() uint64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.seq
}

// UpdateRules replaces the policy rules at runtime (e.g., after cloud sync).
func (g *EdgeGuardian) UpdateRules(rules []PolicyRule) {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.rules = make(map[string]PolicyRule, len(rules))
	for _, r := range rules {
		g.rules[r.Action] = r
	}
	g.config.PolicyRules = rules
}
