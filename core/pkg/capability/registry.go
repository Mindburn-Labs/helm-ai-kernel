package capability

import (
	"sort"
)

// Entry is a registered manifest plus its content hash and provenance.
type Entry struct {
	Manifest   Manifest `json:"manifest"`
	Hash       string   `json:"hash"` // sha256:<hex> over canonical manifest JSON
	SourcePath string   `json:"source_path"`
}

// Registry is a hash-pinned, content-addressed capability manifest store.
// Load-time validation is strict: any invalid manifest fails the whole load
// (fail closed).
type Registry struct {
	entries map[string]Entry
}

// Resolve returns the entry for capabilityID, or nil if unregistered.
func (r *Registry) Resolve(capabilityID string) *Entry {
	if r == nil {
		return nil
	}
	e, ok := r.entries[capabilityID]
	if !ok {
		return nil
	}
	return &e
}

// Len returns the number of registered capabilities.
func (r *Registry) Len() int {
	if r == nil {
		return 0
	}
	return len(r.entries)
}

// IDs returns the sorted registered capability ids.
func (r *Registry) IDs() []string {
	ids := make([]string, 0, len(r.entries))
	for id := range r.entries {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
