package tape

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// Recorder captures nondeterministic inputs during live execution per §5.1.
type Recorder struct {
	mu      sync.Mutex
	runID   string
	entries []Entry
	seq     uint64
	clock   func() time.Time
}

// NewRecorder creates a new tape recorder.
func NewRecorder(runID string) *Recorder {
	return &Recorder{
		runID:   runID,
		entries: make([]Entry, 0),
		clock:   time.Now,
	}
}

// WithClock overrides the clock for testing.
func (r *Recorder) WithClock(clock func() time.Time) *Recorder {
	r.clock = clock
	return r
}

// Record captures a nondeterministic input.
func (r *Recorder) Record(entryType EntryType, componentID, key string, value []byte) *Entry {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.seq++
	h := sha256.Sum256(value)

	entry := Entry{
		Seq:         r.seq,
		Type:        entryType,
		ComponentID: componentID,
		Key:         key,
		ValueHash:   hex.EncodeToString(h[:]),
		Value:       value,
		Timestamp:   r.clock(),
	}
	r.entries = append(r.entries, entry)
	return &entry
}

// RecordTime captures a time value.
func (r *Recorder) RecordTime(componentID string) *Entry {
	t := r.clock()
	return r.Record(EntryTypeTime, componentID, "time", []byte(t.Format(time.RFC3339Nano)))
}

// RecordRNGSeed captures an RNG seed.
func (r *Recorder) RecordRNGSeed(componentID string, seed []byte) *Entry {
	return r.Record(EntryTypeRNGSeed, componentID, "rng_seed", seed)
}

// RecordNetwork captures a network response.
func (r *Recorder) RecordNetwork(componentID, url string, response []byte) *Entry {
	return r.Record(EntryTypeNetwork, componentID, url, response)
}

// RecordToolOutput captures a tool execution output.
func (r *Recorder) RecordToolOutput(componentID, toolID string, output []byte) *Entry {
	return r.Record(EntryTypeToolOutput, componentID, toolID, output)
}

// Entries returns all recorded entries.
func (r *Recorder) Entries() []Entry {
	r.mu.Lock()
	defer r.mu.Unlock()
	result := make([]Entry, len(r.entries))
	copy(result, r.entries)
	return result
}

// BuildManifest creates a tape manifest from recorded entries.
func (r *Recorder) BuildManifest() *Manifest {
	r.mu.Lock()
	defer r.mu.Unlock()

	items := make([]ManifestItem, len(r.entries))
	for i, e := range r.entries {
		items[i] = ManifestItem{
			Seq:       e.Seq,
			Type:      e.Type,
			Key:       e.Key,
			SHA256:    e.ValueHash,
			SizeBytes: int64(len(e.Value)),
		}
	}

	return &Manifest{
		RunID:   r.runID,
		Entries: items,
	}
}

// Ref returns a TapeRef for a given entry.
func (r *Recorder) Ref(entry *Entry) *Ref {
	if entry == nil {
		return nil
	}
	return &Ref{
		Seq:  entry.Seq,
		Hash: entry.ValueHash,
	}
}

// Count returns the number of recorded entries.
func (r *Recorder) Count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.entries)
}

// GetEntry returns an entry by sequence number.
func (r *Recorder) GetEntry(seq uint64) (*Entry, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range r.entries {
		if e.Seq == seq {
			return &e, nil
		}
	}
	return nil, fmt.Errorf("tape entry seq=%d not found", seq)
}
