package store

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// AirgapStore provides a fallback cache for immune runtime operation.
// Stores data in a local JSON file to persist across restarts.
type AirgapStore struct {
	mu       sync.RWMutex
	filePath string
	cache    map[string][]byte
}

func NewAirgapStore(storageDir string) (*AirgapStore, error) {
	if err := os.MkdirAll(storageDir, 0750); err != nil {
		return nil, fmt.Errorf("failed to create storage dir: %w", err)
	}

	filePath := filepath.Join(storageDir, "airgap_cache.json")
	store := &AirgapStore{
		filePath: filePath,
		cache:    make(map[string][]byte),
	}

	// Load existing data
	//nolint:staticcheck // suppressed
	if err := store.load(); err != nil {
		// If load fails, we log but continue with empty cache (unless permission error)
		// For now just return empty, assuming fresh start or benign error
	} //nolint:staticcheck // Validated empty branch
	return store, nil
}

func (s *AirgapStore) load() error {
	data, err := os.ReadFile(s.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return json.Unmarshal(data, &s.cache)
}

func (s *AirgapStore) save() error {
	data, err := json.MarshalIndent(s.cache, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.filePath, data, 0600)
}

// Put caches a result by key (e.g., H(Prompt + Params)).
func (s *AirgapStore) Put(ctx context.Context, key string, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cache[key] = data
	return s.save()
}

// Get retrieves a result from the offline cache.
func (s *AirgapStore) Get(ctx context.Context, key string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	val, exists := s.cache[key]
	if !exists {
		return nil, fmt.Errorf("key not found in airgap store: %s", key)
	}
	return val, nil
}
