package capability

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
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

// LoadDir loads every *.json manifest in dir (non-recursive), validates each
// against capability-manifest/v1, and pins its canonical hash.
func LoadDir(dir string) (*Registry, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, fmt.Errorf("capability registry: glob %s: %w", dir, err)
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("capability registry: no manifest files in %s", dir)
	}
	sort.Strings(files)
	reg := &Registry{entries: make(map[string]Entry, len(files))}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("capability registry: read %s: %w", f, err)
		}
		var m Manifest
		dec := json.NewDecoder(strings.NewReader(string(raw)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&m); err != nil {
			return nil, fmt.Errorf("capability registry: parse %s: %w", f, err)
		}
		if err := m.Validate(); err != nil {
			return nil, fmt.Errorf("capability registry: validate %s: %w", f, err)
		}
		if _, dup := reg.entries[m.CapabilityID]; dup {
			return nil, fmt.Errorf("capability registry: duplicate capability_id %q (%s)", m.CapabilityID, f)
		}
		hash, err := HashManifest(&m)
		if err != nil {
			return nil, fmt.Errorf("capability registry: hash %s: %w", f, err)
		}
		reg.entries[m.CapabilityID] = Entry{Manifest: m, Hash: hash, SourcePath: f}
	}
	return reg, nil
}

// HashManifest computes the content hash (sha256 over JCS-canonical JSON).
func HashManifest(m *Manifest) (string, error) {
	canonical, err := canonicalize.JCS(m)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
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
