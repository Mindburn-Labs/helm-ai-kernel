package store

import (
	"bytes"
	"context"
	"fmt"
	"io"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/store/objstore"
)

// MinIOBlobStore wraps objstore.ObjectStore with the simpler BlobStore interface,
// converting between []byte and io.Reader/ReadCloser at the boundary.
type MinIOBlobStore struct {
	inner objstore.ObjectStore
}

// NewMinIOBlobStore constructs a MinIOBlobStore backed by the given ObjectStore.
func NewMinIOBlobStore(inner objstore.ObjectStore) *MinIOBlobStore {
	return &MinIOBlobStore{inner: inner}
}

// Put stores data under the given key. The contentType argument is accepted for
// interface compatibility but is not forwarded to the underlying ObjectStore.
func (b *MinIOBlobStore) Put(ctx context.Context, key string, data []byte, _ string) error {
	return b.inner.Put(ctx, key, bytes.NewReader(data))
}

// Get retrieves data by key, reading the full response body into a []byte slice.
func (b *MinIOBlobStore) Get(ctx context.Context, key string) ([]byte, error) {
	rc, err := b.inner.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

// Exists reports whether an object with the given key exists in the store.
func (b *MinIOBlobStore) Exists(ctx context.Context, key string) (bool, error) {
	return b.inner.Exists(ctx, key)
}

// Key convention helpers for consistent object paths across the research runtime.

// SourceSnapshotKey returns the object key for a source snapshot blob.
func SourceSnapshotKey(missionID, sourceID string) string {
	return fmt.Sprintf("research/%s/sources/%s/snapshot", missionID, sourceID)
}

// ArtifactBodyKey returns the object key for a draft article body.
func ArtifactBodyKey(missionID, draftID string) string {
	return fmt.Sprintf("research/%s/drafts/%s/body.md", missionID, draftID)
}

// EvidencePackKey returns the object key for a serialised EvidencePack.
func EvidencePackKey(missionID, packID string) string {
	return fmt.Sprintf("research/%s/evidence/%s/pack.json", missionID, packID)
}

// CitationMapKey returns the object key for a source citation map.
func CitationMapKey(missionID, sourceID string) string {
	return fmt.Sprintf("research/%s/sources/%s/citations.json", missionID, sourceID)
}
