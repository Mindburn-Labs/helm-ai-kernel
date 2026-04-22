package capabilities

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// BlobStore defines the contract for Content-Addressed Storage (CAS).
// Ideally this interface would be in `pkg/contracts` or `internal/kernel`,
// but sticking to `effector` for now as it's the primary consumer.
type BlobStore interface {
	// Store persists data and returns its content hash (SHA-256).
	Store(ctx context.Context, data []byte) (string, error)
	// Get retrieves data by its content hash.
	Get(ctx context.Context, hash string) ([]byte, error)
}

// FileBlobStore is a filesystem-backed implementation of BlobStore.
type FileBlobStore struct {
	baseDir string
	mu      sync.RWMutex
}

// NewFileBlobStore creates a new CAS store at the specified directory.
func NewFileBlobStore(baseDir string) (*FileBlobStore, error) {
	//nolint:gosec // G301: Directory permissions for demo CAS store
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to ensure blob dir: %w", err)
	}
	return &FileBlobStore{baseDir: baseDir}, nil
}

func (s *FileBlobStore) Store(ctx context.Context, data []byte) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 1. Compute Hash
	h := sha256.New()
	//nolint:wrapcheck // io.Writer Write error
	if _, err := h.Write(data); err != nil {
		return "", err
	}
	hashBytes := h.Sum(nil)
	hashStr := hex.EncodeToString(hashBytes) // e.g., "a3f5..."
	prefixedHash := "sha256:" + hashStr

	// 2. Determine Path (sharding could be added here, e.g. ab/cd/...)
	path := filepath.Join(s.baseDir, hashStr+".blob")

	// 3. Atomic Write (idempotent: if exists, it's the same content)
	// For simplicity, we just overwrite or check existence.
	if _, err := os.Stat(path); err == nil {
		return prefixedHash, nil // Already exists
	}

	// Write to temp, then rename
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return "", fmt.Errorf("failed to write blob: %w", err)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		return "", fmt.Errorf("failed to commit blob: %w", err)
	}

	return prefixedHash, nil
}

func (s *FileBlobStore) Get(ctx context.Context, hash string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Parse "sha256:..."
	if len(hash) < 7 || hash[:7] != "sha256:" {
		return nil, fmt.Errorf("invalid hash format: %s", hash)
	}
	rawHash := hash[7:]

	path := filepath.Join(s.baseDir, rawHash+".blob")

	//nolint:wrapcheck // caller provides context
	f, err := os.Open(path) //nolint:gosec
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("blob not found: %s", hash)
		}
		return nil, err
	}
	defer func() { _ = f.Close() }() //nolint:errcheck // best-effort close

	//nolint:wrapcheck // caller provides context
	return io.ReadAll(f)
}
