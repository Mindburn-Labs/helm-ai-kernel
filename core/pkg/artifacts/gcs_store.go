//go:build gcp

package artifacts

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"cloud.google.com/go/storage"
)

// GCSStore implements Store interface using Google Cloud Storage.
// Artifacts are stored with their SHA-256 hash as the key prefix.
type GCSStore struct {
	client *storage.Client
	bucket string
	prefix string // Optional key prefix (e.g., "artifacts/")
}

// GCSStoreConfig holds configuration for GCSStore.
type GCSStoreConfig struct {
	Bucket string
	Prefix string // Optional key prefix
}

// NewGCSStore creates a new GCS-backed artifact store.
func NewGCSStore(ctx context.Context, cfg GCSStoreConfig) (*GCSStore, error) {
	// Create GCS client (uses ADC by default)
	client, err := storage.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCS client: %w", err)
	}

	return &GCSStore{
		client: client,
		bucket: cfg.Bucket,
		prefix: cfg.Prefix,
	}, nil
}

// Store persists data to GCS and returns its content hash.
func (s *GCSStore) Store(ctx context.Context, data []byte) (string, error) {
	// 1. Compute Hash
	h := sha256.New()
	if _, err := h.Write(data); err != nil {
		return "", fmt.Errorf("hash computation failed: %w", err)
	}
	hashBytes := h.Sum(nil)
	hashStr := hex.EncodeToString(hashBytes)
	prefixedHash := "sha256:" + hashStr

	// 2. Determine object path
	objectPath := s.prefix + hashStr + ".blob"

	// 3. Check if object already exists (idempotent)
	obj := s.client.Bucket(s.bucket).Object(objectPath)
	_, err := obj.Attrs(ctx)
	if err == nil {
		// Already exists
		return prefixedHash, nil
	}

	// 4. Upload object
	w := obj.NewWriter(ctx)
	w.ContentType = "application/octet-stream"

	if _, err := w.Write(data); err != nil {
		_ = w.Close()
		return "", fmt.Errorf("gcs write failed: %w", err)
	}

	if err := w.Close(); err != nil {
		return "", fmt.Errorf("gcs close failed: %w", err)
	}

	return prefixedHash, nil
}

// Get retrieves data from GCS by its content hash.
func (s *GCSStore) Get(ctx context.Context, hash string) ([]byte, error) {
	// Parse "sha256:..."
	if len(hash) < 7 || hash[:7] != "sha256:" {
		return nil, fmt.Errorf("invalid hash format: %s", hash)
	}
	rawHash := hash[7:]

	objectPath := s.prefix + rawHash + ".blob"

	// Download object
	obj := s.client.Bucket(s.bucket).Object(objectPath)
	reader, err := obj.NewReader(ctx)
	if err != nil {
		return nil, fmt.Errorf("gcs get failed for %s: %w", hash, err)
	}
	defer func() { _ = reader.Close() }()

	return io.ReadAll(reader)
}

// Exists checks if an artifact exists in GCS.
func (s *GCSStore) Exists(ctx context.Context, hash string) (bool, error) {
	if len(hash) < 7 || hash[:7] != "sha256:" {
		return false, fmt.Errorf("invalid hash format: %s", hash)
	}
	rawHash := hash[7:]

	objectPath := s.prefix + rawHash + ".blob"

	obj := s.client.Bucket(s.bucket).Object(objectPath)
	_, err := obj.Attrs(ctx)
	if err != nil {
		if errors.Is(err, storage.ErrObjectNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("gcs attrs error: %w", err)
	}

	return true, nil
}

// Delete removes an artifact from GCS.
func (s *GCSStore) Delete(ctx context.Context, hash string) error {
	if len(hash) < 7 || hash[:7] != "sha256:" {
		return fmt.Errorf("invalid hash format: %s", hash)
	}
	rawHash := hash[7:]

	objectPath := s.prefix + rawHash + ".blob"

	obj := s.client.Bucket(s.bucket).Object(objectPath)
	err := obj.Delete(ctx)
	if err != nil && !errors.Is(err, storage.ErrObjectNotExist) {
		return fmt.Errorf("gcs delete failed for %s: %w", hash, err)
	}

	return nil
}

// Close closes the GCS client.
func (s *GCSStore) Close() error {
	return s.client.Close()
}
