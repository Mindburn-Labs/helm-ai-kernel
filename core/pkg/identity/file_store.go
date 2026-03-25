package identity

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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
var _ DelegationStore = (*FileStore)(nil)

// NewFileStore creates a file-based delegation store.
// Creates the directory if it doesn't exist.
func NewFileStore(dir string) (*FileStore, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("identity: cannot create store directory: %w", err)
	}
	return &FileStore{dir: dir}, nil
}

// Store persists a delegation session to disk.
func (fs *FileStore) Store(session *DelegationSession) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	data, err := json.MarshalIndent(session, "", "  ")
	if err != nil {
		return fmt.Errorf("identity: marshal error: %w", err)
	}

	path := filepath.Join(fs.dir, session.SessionID+".json")
	return os.WriteFile(path, data, 0600)
}

// Load retrieves a delegation session from disk.
func (fs *FileStore) Load(sessionID string) (*DelegationSession, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	// Check if revoked first.
	revoked := fs.loadRevoked()
	if revoked[sessionID] {
		return nil, &DelegationError{
			Code:    "DELEGATION_INVALID",
			Message: "session has been revoked",
		}
	}

	path := filepath.Join(fs.dir, sessionID+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // Not found → nil (matches InMemoryDelegationStore)
		}
		return nil, fmt.Errorf("identity: read error: %w", err)
	}

	var session DelegationSession
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, fmt.Errorf("identity: unmarshal error: %w", err)
	}
	return &session, nil
}

// Revoke marks a session as revoked.
func (fs *FileStore) Revoke(sessionID string) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	revoked := fs.loadRevoked()
	revoked[sessionID] = true
	return fs.saveJSON(filepath.Join(fs.dir, ".revoked"), revoked)
}

// IsNonceUsed checks if a nonce has been seen before (anti-replay).
func (fs *FileStore) IsNonceUsed(nonce string) bool {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	nonces := fs.loadNonces()
	return nonces[nonce]
}

// MarkNonceUsed records a nonce as used.
func (fs *FileStore) MarkNonceUsed(nonce string) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	nonces := fs.loadNonces()
	nonces[nonce] = true
	fs.saveJSON(filepath.Join(fs.dir, ".nonces"), nonces)
}

// ListSessions returns all stored session IDs.
func (fs *FileStore) ListSessions() ([]string, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	entries, err := os.ReadDir(fs.dir)
	if err != nil {
		return nil, err
	}

	var ids []string
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".json" {
			ids = append(ids, e.Name()[:len(e.Name())-5])
		}
	}
	return ids, nil
}

// ── helpers ──

func (fs *FileStore) loadNonces() map[string]bool {
	return fs.loadBoolMap(filepath.Join(fs.dir, ".nonces"))
}

func (fs *FileStore) loadRevoked() map[string]bool {
	return fs.loadBoolMap(filepath.Join(fs.dir, ".revoked"))
}

func (fs *FileStore) loadBoolMap(path string) map[string]bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return make(map[string]bool)
	}
	var m map[string]bool
	if err := json.Unmarshal(data, &m); err != nil {
		return make(map[string]bool)
	}
	return m
}

func (fs *FileStore) saveJSON(path string, v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}
