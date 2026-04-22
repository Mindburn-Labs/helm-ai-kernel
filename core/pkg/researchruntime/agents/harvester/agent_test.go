package harvester

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime/connectors/browser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockBlobStore is an in-memory BlobStore for testing.
type mockBlobStore struct {
	data map[string][]byte
	err  error
}

func newMockBlobStore() *mockBlobStore {
	return &mockBlobStore{data: make(map[string][]byte)}
}

func (m *mockBlobStore) Put(_ context.Context, key string, data []byte, _ string) error {
	if m.err != nil {
		return m.err
	}
	m.data[key] = data
	return nil
}

func (m *mockBlobStore) Get(_ context.Context, key string) ([]byte, error) {
	v, ok := m.data[key]
	if !ok {
		return nil, errors.New("not found")
	}
	return v, nil
}

func (m *mockBlobStore) Exists(_ context.Context, key string) (bool, error) {
	_, ok := m.data[key]
	return ok, nil
}

func TestHarvesterAgent_Role(t *testing.T) {
	a := New(nil, nil)
	assert.Equal(t, researchruntime.WorkerSourceHarvester, a.Role())
}

func TestHarvesterAgent_HappyPath(t *testing.T) {
	// Spin up a test HTTP server that returns minimal HTML.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><head><title>Test Page</title></head><body><p>Hello world content here.</p></body></html>`))
	}))
	defer srv.Close()

	fetcher := browser.NewFetcher(5, 1<<20)
	blobs := newMockBlobStore()
	a := New(fetcher, blobs)

	snapshots := []researchruntime.SourceSnapshot{
		{
			SourceID:  "src-1",
			MissionID: "m1",
			URL:       srv.URL,
		},
	}
	input, _ := json.Marshal(snapshots)

	out, err := a.Execute(context.Background(), &researchruntime.TaskLease{MissionID: "m1"}, input)
	require.NoError(t, err)

	var result []researchruntime.SourceSnapshot
	require.NoError(t, json.Unmarshal(out, &result))
	require.Len(t, result, 1)

	// SnapshotHash and metadata refs should be populated.
	assert.NotEmpty(t, result[0].SnapshotHash)
	assert.Equal(t, researchruntime.ProvenanceCaptured, result[0].ProvenanceStatus)
	assert.NotNil(t, result[0].Metadata)
	assert.NotEmpty(t, result[0].Metadata["blob_ref"])
	assert.NotEmpty(t, result[0].Metadata["citation_map_ref"])

	// Blob store should contain the snapshot and citation map.
	blobKey := "research/m1/sources/src-1/snapshot"
	exists, _ := blobs.Exists(context.Background(), blobKey)
	assert.True(t, exists)
}

func TestHarvesterAgent_InvalidInputReturnsError(t *testing.T) {
	a := New(nil, nil)
	_, err := a.Execute(context.Background(), &researchruntime.TaskLease{}, []byte("not-json"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unmarshal snapshots")
}

func TestHarvesterAgent_FetchFailureContinues(t *testing.T) {
	// Use a server that immediately closes to force a fetch error.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Close the connection abruptly.
		hj, ok := w.(http.Hijacker)
		if ok {
			conn, _, _ := hj.Hijack()
			_ = conn.Close()
		}
	}))
	defer srv.Close()

	fetcher := browser.NewFetcher(1, 1<<20)
	blobs := newMockBlobStore()
	a := New(fetcher, blobs)

	snapshots := []researchruntime.SourceSnapshot{
		{SourceID: "src-bad", MissionID: "m1", URL: srv.URL},
		// A second snapshot that can't be reached either (bad URL) — both should be skipped gracefully.
		{SourceID: "src-missing", MissionID: "m1", URL: "http://127.0.0.1:1"},
	}
	input, _ := json.Marshal(snapshots)

	out, err := a.Execute(context.Background(), &researchruntime.TaskLease{MissionID: "m1"}, input)
	// Should succeed (non-fatal fetch failures).
	require.NoError(t, err)

	var result []researchruntime.SourceSnapshot
	require.NoError(t, json.Unmarshal(out, &result))
	// Snapshots are returned even if un-enriched.
	assert.Len(t, result, 2)
}

func TestHarvesterAgent_BlobStoreErrorContinues(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html><body>content</body></html>`))
	}))
	defer srv.Close()

	fetcher := browser.NewFetcher(5, 1<<20)
	blobs := &mockBlobStore{data: make(map[string][]byte), err: errors.New("storage unavailable")}
	a := New(fetcher, blobs)

	snapshots := []researchruntime.SourceSnapshot{
		{SourceID: "src-1", MissionID: "m1", URL: srv.URL},
	}
	input, _ := json.Marshal(snapshots)

	// Should not propagate blob store errors.
	out, err := a.Execute(context.Background(), &researchruntime.TaskLease{MissionID: "m1"}, input)
	require.NoError(t, err)

	var result []researchruntime.SourceSnapshot
	require.NoError(t, json.Unmarshal(out, &result))
	assert.Len(t, result, 1)
}
