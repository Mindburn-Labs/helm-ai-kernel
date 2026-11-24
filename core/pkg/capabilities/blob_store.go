package capabilities

import (
	"context"
	"sync"
)

// BlobStore defines the content-addressed storage contract used by capabilities.
type BlobStore interface {
	// Store persists data and returns its content hash (SHA-256).
	Store(ctx context.Context, data []byte) (string, error)
	// Get retrieves data by its content hash.
	Get(ctx context.Context, hash string) ([]byte, error)
}

// FileBlobStore retains the local root of the former filesystem blob store.
type FileBlobStore struct {
	baseDir string
	mu      sync.RWMutex
}
