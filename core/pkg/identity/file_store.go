package identity

import (
	"sync"
)

// FileStore retains the directory of the former local delegation store.
type FileStore struct {
	mu  sync.RWMutex
	dir string
}

// Compile-time check: FileStore implements DelegationStore.

// ── helpers ──
