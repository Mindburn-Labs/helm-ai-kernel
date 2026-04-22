package actiongraph

import "sync"

// ActionDeduplicator tracks proposal content hashes to prevent duplicate
// proposals from being created for the same underlying signal cluster.
type ActionDeduplicator struct {
	mu   sync.RWMutex
	seen map[string]struct{}
}

// NewActionDeduplicator returns a ready-to-use deduplicator.
func NewActionDeduplicator() *ActionDeduplicator {
	return &ActionDeduplicator{
		seen: make(map[string]struct{}),
	}
}

// IsDuplicate returns true if the given content hash has already been recorded.
func (d *ActionDeduplicator) IsDuplicate(contentHash string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	_, exists := d.seen[contentHash]
	return exists
}

// Record marks the given content hash as seen.
func (d *ActionDeduplicator) Record(contentHash string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.seen[contentHash] = struct{}{}
}
