package publish

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime/store"
)

// --- in-memory mock PublicationStore ---

type memPublicationStore struct {
	mu      sync.Mutex
	records map[string]researchruntime.PublicationRecord
}

func newMemPublicationStore() *memPublicationStore {
	return &memPublicationStore{records: make(map[string]researchruntime.PublicationRecord)}
}

func (m *memPublicationStore) Save(_ context.Context, p researchruntime.PublicationRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.records[p.PublicationID] = p
	return nil
}

func (m *memPublicationStore) Get(_ context.Context, id string) (*researchruntime.PublicationRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.records[id]
	if !ok {
		return nil, nil
	}
	return &r, nil
}

func (m *memPublicationStore) GetBySlug(_ context.Context, _ string) (*researchruntime.PublicationRecord, error) {
	return nil, nil
}

func (m *memPublicationStore) List(_ context.Context) ([]researchruntime.PublicationRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]researchruntime.PublicationRecord, 0, len(m.records))
	for _, r := range m.records {
		out = append(out, r)
	}
	return out, nil
}

func (m *memPublicationStore) UpdateState(_ context.Context, id, state string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.records[id]
	if !ok {
		return nil
	}
	r.State = researchruntime.PublicationState(state)
	m.records[id] = r
	return nil
}

func (m *memPublicationStore) SetSupersededBy(_ context.Context, oldID, newID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.records[oldID]
	if !ok {
		return nil
	}
	r.SupersededBy = newID
	m.records[oldID] = r
	return nil
}

// compile-time check that memPublicationStore satisfies the interface.
var _ store.PublicationStore = (*memPublicationStore)(nil)

// --- helpers ---

func makeDraft() *researchruntime.DraftManifest {
	return &researchruntime.DraftManifest{
		DraftID:   "draft-001",
		MissionID: "mission-abc",
		Title:     "AI Safety Weekly",
		Version:   1,
		CreatedAt: time.Now().UTC(),
	}
}

func makeReceipt() *researchruntime.PromotionReceipt {
	return &researchruntime.PromotionReceipt{
		ReceiptID:        "receipt-001",
		MissionID:        "mission-abc",
		PublicationID:    "pub-pre-001",
		PublicationState: researchruntime.PublicationStatePromoted,
		EvidencePackHash: "sha256:deadbeef",
		PolicyDecision:   "ALLOW",
		ManifestHash:     "sha256:cafebabe",
		CreatedAt:        time.Now().UTC(),
	}
}

// --- tests ---

func TestPublish_Success(t *testing.T) {
	pubs := newMemPublicationStore()
	publisher := NewRegistryPublisher(pubs, nil)

	draft := makeDraft()
	receipt := makeReceipt()

	rec, err := publisher.Publish(context.Background(), draft, receipt)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if rec == nil {
		t.Fatal("expected a PublicationRecord, got nil")
	}

	// Basic field assertions.
	if rec.MissionID != draft.MissionID {
		t.Errorf("MissionID mismatch: got %q, want %q", rec.MissionID, draft.MissionID)
	}
	if rec.Title != draft.Title {
		t.Errorf("Title mismatch: got %q, want %q", rec.Title, draft.Title)
	}
	if rec.Version != draft.Version {
		t.Errorf("Version mismatch: got %d, want %d", rec.Version, draft.Version)
	}
	if rec.EvidencePackHash != receipt.EvidencePackHash {
		t.Errorf("EvidencePackHash mismatch: got %q, want %q", rec.EvidencePackHash, receipt.EvidencePackHash)
	}
	if rec.PromotionReceipt != receipt.ReceiptID {
		t.Errorf("PromotionReceipt mismatch: got %q, want %q", rec.PromotionReceipt, receipt.ReceiptID)
	}
	if rec.State != researchruntime.PublicationStatePromoted {
		t.Errorf("State mismatch: got %q, want %q", rec.State, researchruntime.PublicationStatePromoted)
	}
	if rec.PublicationID == "" {
		t.Error("PublicationID must not be empty")
	}
	if rec.PublishedAt == nil {
		t.Error("PublishedAt must be set")
	}

	// Verify the record was actually persisted in the store.
	stored, err := pubs.Get(context.Background(), rec.PublicationID)
	if err != nil {
		t.Fatalf("store.Get error: %v", err)
	}
	if stored == nil {
		t.Fatal("record was not persisted to the store")
	}
	if stored.PublicationID != rec.PublicationID {
		t.Errorf("stored PublicationID mismatch: got %q, want %q", stored.PublicationID, rec.PublicationID)
	}
}

func TestPublish_NilReceipt(t *testing.T) {
	pubs := newMemPublicationStore()
	publisher := NewRegistryPublisher(pubs, nil)

	_, err := publisher.Publish(context.Background(), makeDraft(), nil)
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if err != ErrMissingPromotionReceipt {
		t.Errorf("unexpected error: got %v, want ErrMissingPromotionReceipt", err)
	}
}
