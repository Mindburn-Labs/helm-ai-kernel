// Package objstore provides a content-addressed object store interface
// for storing evidence packs and other binary artifacts.
package objstore

import (
	"context"
	"io"
)

// ObjectStore is the canonical interface for content-addressed blob storage.
// Implementations include local filesystem and S3-compatible (MinIO).
type ObjectStore interface {
	// Put stores data under the given content hash.
	// If an object with the same hash already exists, this is a no-op (idempotent).
	Put(ctx context.Context, hash string, data io.Reader) error

	// Get retrieves data by content hash. Returns ErrNotFound if not present.
	Get(ctx context.Context, hash string) (io.ReadCloser, error)

	// Exists checks whether an object with the given hash exists.
	Exists(ctx context.Context, hash string) (bool, error)

	// Delete removes an object by hash. Returns nil if not found.
	Delete(ctx context.Context, hash string) error

	// List returns all object hashes, optionally with a prefix filter.
	List(ctx context.Context, prefix string) ([]string, error)
}

// ErrNotFound is returned when an object is not in the store.
type ErrNotFound struct {
	Hash string
}

func (e *ErrNotFound) Error() string {
	return "object not found: " + e.Hash
}
