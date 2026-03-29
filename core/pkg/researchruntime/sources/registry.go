package sources

import (
	"sync"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime"
)

// Registry tracks discovered sources in memory and deduplicates by content hash and canonical URL.
type Registry struct {
	mu     sync.RWMutex
	byHash map[string]*researchruntime.SourceSnapshot
	byURL  map[string]*researchruntime.SourceSnapshot
}

func NewRegistry() *Registry {
	return &Registry{
		byHash: make(map[string]*researchruntime.SourceSnapshot),
		byURL:  make(map[string]*researchruntime.SourceSnapshot),
	}
}

func (r *Registry) Register(s researchruntime.SourceSnapshot) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.byHash[s.ContentHash] = &s
	if s.CanonicalURL != "" {
		r.byURL[s.CanonicalURL] = &s
	}
}

func (r *Registry) IsDuplicate(s researchruntime.SourceSnapshot) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if s.ContentHash != "" {
		if _, ok := r.byHash[s.ContentHash]; ok {
			return true
		}
	}
	if s.CanonicalURL != "" {
		if _, ok := r.byURL[s.CanonicalURL]; ok {
			return true
		}
	}
	return false
}

func (r *Registry) All() []*researchruntime.SourceSnapshot {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*researchruntime.SourceSnapshot, 0, len(r.byHash))
	for _, s := range r.byHash {
		out = append(out, s)
	}
	return out
}

func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.byHash)
}
