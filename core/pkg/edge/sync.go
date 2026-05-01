package edge

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// AnchorSink is the interface for submitting edge decisions to a transparency log.
type AnchorSink interface {
	// Anchor submits a batch of decisions for anchoring.
	// Returns the anchor IDs for each decision.
	Anchor(ctx context.Context, decisions []EdgeDecision) ([]string, error)
}

// SyncManager handles async proof anchoring from edge to cloud.
type SyncManager struct {
	guardian *EdgeGuardian
	sink     AnchorSink
	interval time.Duration
	stop     chan struct{}
}

// NewSyncManager creates a sync manager that periodically flushes
// the edge guardian's proof queue to the anchor sink.
func NewSyncManager(guardian *EdgeGuardian, sink AnchorSink, interval time.Duration) *SyncManager {
	return &SyncManager{
		guardian: guardian,
		sink:     sink,
		interval: interval,
		stop:     make(chan struct{}),
	}
}

// Start begins periodic sync. Call in a goroutine.
func (s *SyncManager) Start(ctx context.Context) error {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// Final flush before shutdown
			s.flush(context.Background())
			return ctx.Err()
		case <-s.stop:
			return nil
		case <-ticker.C:
			s.flush(ctx)
		}
	}
}

// Stop gracefully shuts down the sync manager.
func (s *SyncManager) Stop() {
	close(s.stop)
}

// Flush manually triggers a sync cycle.
func (s *SyncManager) Flush(ctx context.Context) error {
	return s.flush(ctx)
}

func (s *SyncManager) flush(ctx context.Context) error {
	decisions := s.guardian.FlushQueue()
	if len(decisions) == 0 {
		return nil
	}

	_, err := s.sink.Anchor(ctx, decisions)
	if err != nil {
		// Re-queue failed decisions (best effort)
		s.guardian.mu.Lock()
		s.guardian.queue = append(s.guardian.queue, decisions...)
		s.guardian.mu.Unlock()
		return fmt.Errorf("anchor failed: %w", err)
	}

	return nil
}

// MemoryAnchorSink is an in-memory anchor sink for testing.
type MemoryAnchorSink struct {
	mu       sync.Mutex
	anchored []EdgeDecision
}

// NewMemoryAnchorSink creates a test anchor sink.
func NewMemoryAnchorSink() *MemoryAnchorSink {
	return &MemoryAnchorSink{}
}

// Anchor stores decisions in memory and returns generated anchor IDs.
func (m *MemoryAnchorSink) Anchor(_ context.Context, decisions []EdgeDecision) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	ids := make([]string, len(decisions))
	for i, d := range decisions {
		data, _ := json.Marshal(d)
		h := sha256.Sum256(data)
		ids[i] = "anchor-" + hex.EncodeToString(h[:8])
		d.Anchored = true
		m.anchored = append(m.anchored, d)
	}
	return ids, nil
}

// Anchored returns all anchored decisions.
func (m *MemoryAnchorSink) Anchored() []EdgeDecision {
	m.mu.Lock()
	defer m.mu.Unlock()

	out := make([]EdgeDecision, len(m.anchored))
	copy(out, m.anchored)
	return out
}
