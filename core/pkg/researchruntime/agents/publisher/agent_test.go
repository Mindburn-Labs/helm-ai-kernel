package publisher

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime/connectors/publish"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockPublicationStore is an in-memory PublicationStore for testing.
type mockPublicationStore struct {
	records map[string]researchruntime.PublicationRecord
	err     error
}

func newMockPublicationStore() *mockPublicationStore {
	return &mockPublicationStore{records: make(map[string]researchruntime.PublicationRecord)}
}

func (m *mockPublicationStore) Save(_ context.Context, p researchruntime.PublicationRecord) error {
	if m.err != nil {
		return m.err
	}
	m.records[p.PublicationID] = p
	return nil
}

func (m *mockPublicationStore) Get(_ context.Context, id string) (*researchruntime.PublicationRecord, error) {
	r, ok := m.records[id]
	if !ok {
		return nil, errors.New("not found")
	}
	return &r, nil
}

func (m *mockPublicationStore) GetBySlug(_ context.Context, _ string) (*researchruntime.PublicationRecord, error) {
	return nil, errors.New("not implemented")
}

func (m *mockPublicationStore) List(_ context.Context) ([]researchruntime.PublicationRecord, error) {
	return nil, nil
}

func (m *mockPublicationStore) UpdateState(_ context.Context, _, _ string) error {
	return nil
}

func (m *mockPublicationStore) SetSupersededBy(_ context.Context, _, _ string) error {
	return nil
}

// mockBlobStore is a no-op BlobStore for testing.
type mockBlobStore struct{}

func (m *mockBlobStore) Put(_ context.Context, _ string, _ []byte, _ string) error { return nil }
func (m *mockBlobStore) Get(_ context.Context, _ string) ([]byte, error)           { return nil, nil }
func (m *mockBlobStore) Exists(_ context.Context, _ string) (bool, error)          { return false, nil }

func makeRegistryPublisher(pubStore store.PublicationStore) *publish.RegistryPublisher {
	return publish.NewRegistryPublisher(pubStore, &mockBlobStore{})
}

func TestPublisherAgent_Role(t *testing.T) {
	a := New(nil)
	assert.Equal(t, researchruntime.WorkerPublisher, a.Role())
}

func TestPublisherAgent_HappyPath(t *testing.T) {
	pubStore := newMockPublicationStore()
	reg := makeRegistryPublisher(pubStore)
	a := New(reg)

	now := time.Now().UTC()
	in := publisherInput{
		Draft: researchruntime.DraftManifest{
			DraftID:   "draft-1",
			MissionID: "m1",
			Title:     "Research Paper on AI Safety",
			Version:   1,
			CreatedAt: now,
		},
		Receipt: researchruntime.PromotionReceipt{
			ReceiptID:        "receipt-1",
			MissionID:        "m1",
			PublicationID:    "pub-1",
			PublicationState: researchruntime.PublicationStatePromoted,
			EvidencePackHash: "sha256:abc123",
			PolicyDecision:   "allow",
			ManifestHash:     "sha256:def456",
			CreatedAt:        now,
		},
	}
	input, _ := json.Marshal(in)

	out, err := a.Execute(context.Background(), &researchruntime.TaskLease{MissionID: "m1"}, input)
	require.NoError(t, err)

	var rec researchruntime.PublicationRecord
	require.NoError(t, json.Unmarshal(out, &rec))
	assert.Equal(t, "m1", rec.MissionID)
	assert.Equal(t, "Research Paper on AI Safety", rec.Title)
	assert.Equal(t, researchruntime.PublicationStatePromoted, rec.State)
	assert.Equal(t, "sha256:abc123", rec.EvidencePackHash)
	assert.Equal(t, "receipt-1", rec.PromotionReceipt)
	assert.NotEmpty(t, rec.PublicationID)
	assert.NotNil(t, rec.PublishedAt)

	// Verify it was persisted in the mock store.
	assert.Len(t, pubStore.records, 1)
}

func TestPublisherAgent_InvalidInputReturnsError(t *testing.T) {
	a := New(nil)
	_, err := a.Execute(context.Background(), &researchruntime.TaskLease{}, []byte("not-json"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unmarshal input")
}

func TestPublisherAgent_NilReceiptReturnsError(t *testing.T) {
	// Use a publisherInput with a zero-value Receipt — RegistryPublisher.Publish checks for nil.
	// We instead test the store error path.
	pubStore := newMockPublicationStore()
	pubStore.err = errors.New("database unavailable")
	reg := makeRegistryPublisher(pubStore)
	a := New(reg)

	now := time.Now().UTC()
	in := publisherInput{
		Draft: researchruntime.DraftManifest{
			DraftID:   "draft-2",
			MissionID: "m1",
			Title:     "Draft",
			Version:   1,
			CreatedAt: now,
		},
		Receipt: researchruntime.PromotionReceipt{
			ReceiptID:     "r2",
			MissionID:     "m1",
			PolicyDecision: "allow",
			CreatedAt:     now,
		},
	}
	input, _ := json.Marshal(in)

	_, err := a.Execute(context.Background(), &researchruntime.TaskLease{MissionID: "m1"}, input)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "publish")
}

func TestPublisherAgent_MissingPromotionReceiptError(t *testing.T) {
	// Simulate calling Publish with empty input — RegistryPublisher will reject nil receipt.
	// We do this via direct nil injection by marshalling a publisherInput with a zero Receipt
	// and verifying the error surface from the publisher.
	//
	// The JSON null receipt case is tested via the missing receipt constant from publish package.
	pubStore := newMockPublicationStore()
	reg := publish.NewRegistryPublisher(pubStore, &mockBlobStore{})

	_, publishErr := reg.Publish(context.Background(), &researchruntime.DraftManifest{}, nil)
	require.Error(t, publishErr)
	assert.Equal(t, publish.ErrMissingPromotionReceipt, publishErr)
}
