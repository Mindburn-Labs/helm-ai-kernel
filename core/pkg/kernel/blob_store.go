// Package kernel provides content-addressed blob storage for raw records.
// Per Section 2.1 - Receipt Layering Contract
package kernel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sync"
)

// BlobAddress is a content-addressed identifier (typically SHA256 hash).
type BlobAddress string

// RawRecord represents an un-interpreted forensic record.
// Per Section 2.1 - RawRecordLayer
type RawRecord struct {
	Address    BlobAddress `json:"address"`
	Content    []byte      `json:"-"` // Not serialized directly
	ContentLen int         `json:"content_len"`
	MimeType   string      `json:"mime_type"`
	Redacted   bool        `json:"redacted"`
}

// BlobStore provides content-addressed storage for raw records.
// Per Section 2.1 - content-addressed blob storage for forensic records.
type BlobStore interface {
	// Store stores a blob and returns its content address.
	Store(ctx context.Context, content []byte, mimeType string) (BlobAddress, error)

	// StoreRedacted stores a redacted placeholder with commitment.
	StoreRedacted(ctx context.Context, contentHash string, mimeType string) (BlobAddress, error)

	// Get retrieves a blob by its content address.
	Get(ctx context.Context, address BlobAddress) (*RawRecord, error)

	// Has checks if a blob exists.
	Has(ctx context.Context, address BlobAddress) bool

	// Delete removes a blob (for GDPR compliance).
	Delete(ctx context.Context, address BlobAddress) error

	// List returns all blob addresses.
	List(ctx context.Context) ([]BlobAddress, error)
}

// InMemoryBlobStore provides an in-memory content-addressed store.
type InMemoryBlobStore struct {
	mu    sync.RWMutex
	blobs map[BlobAddress]*RawRecord
}

// NewInMemoryBlobStore creates a new in-memory blob store.
func NewInMemoryBlobStore() *InMemoryBlobStore {
	return &InMemoryBlobStore{
		blobs: make(map[BlobAddress]*RawRecord),
	}
}

// Store implements BlobStore.
func (s *InMemoryBlobStore) Store(ctx context.Context, content []byte, mimeType string) (BlobAddress, error) {
	address := computeBlobAddress(content)

	s.mu.Lock()
	defer s.mu.Unlock()

	// Content-addressed: if it exists, it's the same content
	if _, exists := s.blobs[address]; exists {
		return address, nil
	}

	s.blobs[address] = &RawRecord{
		Address:    address,
		Content:    content,
		ContentLen: len(content),
		MimeType:   mimeType,
		Redacted:   false,
	}

	return address, nil
}

// StoreRedacted implements BlobStore.
func (s *InMemoryBlobStore) StoreRedacted(ctx context.Context, contentHash string, mimeType string) (BlobAddress, error) {
	// Use the provided hash as the address for redacted content
	address := BlobAddress("redacted:" + contentHash)

	s.mu.Lock()
	defer s.mu.Unlock()

	s.blobs[address] = &RawRecord{
		Address:    address,
		Content:    nil, // No content stored
		ContentLen: 0,
		MimeType:   mimeType,
		Redacted:   true,
	}

	return address, nil
}

// Get implements BlobStore.
func (s *InMemoryBlobStore) Get(ctx context.Context, address BlobAddress) (*RawRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	record, exists := s.blobs[address]
	if !exists {
		return nil, ErrBlobNotFound
	}

	return record, nil
}

// Has implements BlobStore.
func (s *InMemoryBlobStore) Has(ctx context.Context, address BlobAddress) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, exists := s.blobs[address]
	return exists
}

// Delete implements BlobStore.
func (s *InMemoryBlobStore) Delete(ctx context.Context, address BlobAddress) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.blobs, address)
	return nil
}

// List implements BlobStore.
func (s *InMemoryBlobStore) List(ctx context.Context) ([]BlobAddress, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	addresses := make([]BlobAddress, 0, len(s.blobs))
	for addr := range s.blobs {
		addresses = append(addresses, addr)
	}
	return addresses, nil
}

// computeBlobAddress computes the content address for a blob.
func computeBlobAddress(content []byte) BlobAddress {
	h := sha256.Sum256(content)
	return BlobAddress("sha256:" + hex.EncodeToString(h[:]))
}

// Error types
var ErrBlobNotFound = errorString("blob not found")
