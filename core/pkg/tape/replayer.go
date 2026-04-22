package tape

import (
	"fmt"
	"sync"
)

// Replayer serves taped outputs during replay and blocks external I/O per §5.2.
type Replayer struct {
	mu      sync.Mutex
	entries map[uint64]*Entry // keyed by seq
	byKey   map[string]*Entry // keyed by type:key for lookup
	cursor  uint64
}

// NewReplayer creates a replayer from recorded entries.
func NewReplayer(entries []Entry) *Replayer {
	m := make(map[uint64]*Entry, len(entries))
	byKey := make(map[string]*Entry, len(entries))
	for i := range entries {
		e := entries[i]
		m[e.Seq] = &e
		key := fmt.Sprintf("%s:%s", e.Type, e.Key)
		byKey[key] = &e
	}
	return &Replayer{
		entries: m,
		byKey:   byKey,
	}
}

// Lookup returns the taped value for a given seq.
// Returns REPLAY_TAPE_MISS error if not found — fail-closed per §5.2.
func (r *Replayer) Lookup(seq uint64) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	entry, ok := r.entries[seq]
	if !ok {
		return nil, fmt.Errorf("REPLAY_TAPE_MISS: seq=%d not found in tape", seq)
	}
	return entry.Value, nil
}

// LookupByKey returns the taped value for a type:key combination.
// Returns REPLAY_TAPE_MISS error if not found — fail-closed per §5.2.
func (r *Replayer) LookupByKey(entryType EntryType, key string) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	lookupKey := fmt.Sprintf("%s:%s", entryType, key)
	entry, ok := r.byKey[lookupKey]
	if !ok {
		return nil, fmt.Errorf("REPLAY_TAPE_MISS: key=%s not found in tape", lookupKey)
	}
	return entry.Value, nil
}

// Next returns the next taped entry in sequence.
// Returns REPLAY_TAPE_MISS if exhausted.
func (r *Replayer) Next() (*Entry, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.cursor++
	entry, ok := r.entries[r.cursor]
	if !ok {
		return nil, fmt.Errorf("REPLAY_TAPE_MISS: seq=%d exhausted", r.cursor)
	}
	return entry, nil
}

// BlockNetwork returns an error — network is blocked during replay per §5.2.
func (r *Replayer) BlockNetwork(url string) error {
	return fmt.Errorf("REPLAY_TAPE_MISS: network blocked during replay, url=%s", url)
}

// Count returns the number of entries available.
func (r *Replayer) Count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.entries)
}
