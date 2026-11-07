package identity

import (
	"sync"
)

// FileStore implements DelegationStore with JSON files on disk.
// Sessions are stored as individual JSON files in the configured directory.
//
// Thread-safe via sync.RWMutex. Suitable for CLI and single-node usage.
// Production multi-node deployments should use PostgresStore.
type FileStore struct {
	mu  sync.RWMutex
	dir string
}

// Compile-time check: FileStore implements DelegationStore.

// ── helpers ──
