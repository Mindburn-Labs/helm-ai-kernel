package artifacts

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

// Store defines the contract for Content-Addressed Storage (CAS) of Artifacts.
type Store interface {
	// Store persists data and returns its content hash (SHA-256).
	// Equivalent to Put in the backlog specification.
	Store(ctx context.Context, data []byte) (string, error)
	// Get retrieves data by its content hash.
	Get(ctx context.Context, hash string) ([]byte, error)
	// Exists checks if an artifact exists by its content hash.
	Exists(ctx context.Context, hash string) (bool, error)
	// Delete removes an artifact by its content hash.
	Delete(ctx context.Context, hash string) error
}

// FileStore is a filesystem-backed implementation of Store.
type FileStore struct {
	baseDir string
	mu      sync.RWMutex
}

// NewFileStore creates a new CAS store at the specified directory.
func NewFileStore(baseDir string) (*FileStore, error) {
	//nolint:gosec // G301: 0755 is intentional for shared artifact directory
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to ensure artifact dir: %w", err)
	}
	return &FileStore{baseDir: baseDir}, nil
}

func (s *FileStore) Store(ctx context.Context, data []byte) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 1. Compute Hash
	h := sha256.New()
	//nolint:wrapcheck // error from Write is interface method
	if _, err := h.Write(data); err != nil {
		return "", err
	}
	hashBytes := h.Sum(nil)
	hashStr := hex.EncodeToString(hashBytes) // e.g., "a3f5..."
	prefixedHash := "sha256:" + hashStr

	// 2. Determine Path
	path := filepath.Join(s.baseDir, hashStr+".blob")

	// 3. Atomic Write (idempotent)
	if _, err := os.Stat(path); err == nil {
		return prefixedHash, nil // Already exists
	}

	// Write to temp, then rename
	tmpPath := path + ".tmp"
	//nolint:gosec // G306: 0644 is intentional for readable blob files
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return "", fmt.Errorf("failed to write blob: %w", err)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		return "", fmt.Errorf("failed to commit blob: %w", err)
	}

	return prefixedHash, nil
}

func (s *FileStore) Get(ctx context.Context, hash string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Parse "sha256:..."
	if len(hash) < 7 || hash[:7] != "sha256:" {
		return nil, fmt.Errorf("invalid hash format: %s", hash)
	}
	rawHash := hash[7:]
	if _, err := hex.DecodeString(rawHash); err != nil {
		return nil, fmt.Errorf("invalid hash hex: %w", err)
	}

	path := filepath.Join(s.baseDir, rawHash+".blob")

	f, err := os.Open(path) //nolint:gosec // Hash validated as hex
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("artifact not found: %s", hash)
		}
		//nolint:wrapcheck // caller provides context
		return nil, err
	}
	defer f.Close() //nolint:errcheck // best-effort close

	//nolint:wrapcheck // caller provides context
	return io.ReadAll(f)
}

func (s *FileStore) Exists(ctx context.Context, hash string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Parse "sha256:..."
	if len(hash) < 7 || hash[:7] != "sha256:" {
		return false, fmt.Errorf("invalid hash format: %s", hash)
	}
	rawHash := hash[7:]
	if _, err := hex.DecodeString(rawHash); err != nil {
		return false, fmt.Errorf("invalid hash hex: %w", err)
	}

	path := filepath.Join(s.baseDir, rawHash+".blob")
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	//nolint:wrapcheck // caller provides context
	return false, err
}

func (s *FileStore) Delete(ctx context.Context, hash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Parse "sha256:..."
	if len(hash) < 7 || hash[:7] != "sha256:" {
		return fmt.Errorf("invalid hash format: %s", hash)
	}
	rawHash := hash[7:]
	if _, err := hex.DecodeString(rawHash); err != nil {
		return fmt.Errorf("invalid hash hex: %w", err)
	}

	path := filepath.Join(s.baseDir, rawHash+".blob")
	err := os.Remove(path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete artifact: %w", err)
	}
	return nil
}
