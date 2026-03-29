package publication

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime/connectors/publish"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime/store"
)

// ─── in-memory DraftStore ────────────────────────────────────────────────────

type memDraftStore struct {
	mu     sync.Mutex
	drafts map[string]researchruntime.DraftManifest
}

func newMemDraftStore() *memDraftStore {
	return &memDraftStore{drafts: make(map[string]researchruntime.DraftManifest)}
}

func (m *memDraftStore) Save(_ context.Context, d researchruntime.DraftManifest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.drafts[d.DraftID] = d
	return nil
}

func (m *memDraftStore) Get(_ context.Context, id string) (*researchruntime.DraftManifest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.drafts[id]
	if !ok {
		return nil, errors.New("draft not found: " + id)
	}
	return &d, nil
}

func (m *memDraftStore) ListByMission(_ context.Context, missionID string) ([]researchruntime.DraftManifest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []researchruntime.DraftManifest
	for _, d := range m.drafts {
		if d.MissionID == missionID {
			out = append(out, d)
		}
	}
	return out, nil
}

func (m *memDraftStore) UpdateState(_ context.Context, id, _ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.drafts[id]; !ok {
		return errors.New("draft not found: " + id)
	}
	return nil
}

var _ store.DraftStore = (*memDraftStore)(nil)

// ─── in-memory PublicationStore ──────────────────────────────────────────────

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

var _ store.PublicationStore = (*memPublicationStore)(nil)

// ─── in-memory FeedStore ─────────────────────────────────────────────────────

type memFeedStore struct {
	mu     sync.Mutex
	events []store.FeedEvent
}

func newMemFeedStore() *memFeedStore { return &memFeedStore{} }

func (m *memFeedStore) Append(_ context.Context, missionID, actor, action, detail string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, store.FeedEvent{
		MissionID: missionID,
		Actor:     actor,
		Action:    action,
		Detail:    detail,
		CreatedAt: time.Now().UTC(),
	})
	return nil
}

func (m *memFeedStore) Latest(_ context.Context, limit int) ([]store.FeedEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if limit <= 0 || limit > len(m.events) {
		limit = len(m.events)
	}
	return m.events[len(m.events)-limit:], nil
}

func (m *memFeedStore) ByMission(_ context.Context, missionID string) ([]store.FeedEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.FeedEvent
	for _, e := range m.events {
		if e.MissionID == missionID {
			out = append(out, e)
		}
	}
	return out, nil
}

var _ store.FeedStore = (*memFeedStore)(nil)

// ─── helpers ─────────────────────────────────────────────────────────────────

func makeDraft() researchruntime.DraftManifest {
	return researchruntime.DraftManifest{
		DraftID:   "draft-001",
		MissionID: "mission-abc",
		Title:     "AI Safety Weekly",
		Version:   1,
		CreatedAt: time.Now().UTC(),
	}
}

// makeValidReceipt builds a PromotionReceipt whose ManifestHash is consistent
// with its fields (i.e. VerifyPromotionReceipt will pass).
func makeValidReceipt(t *testing.T) *researchruntime.PromotionReceipt {
	t.Helper()
	r := researchruntime.PromotionReceipt{
		ReceiptID:        "receipt-001",
		MissionID:        "mission-abc",
		PublicationID:    "pub-pre-001",
		PublicationState: researchruntime.PublicationStatePromoted,
		EvidencePackHash: "sha256:deadbeef",
		PolicyDecision:   "ALLOW",
		CreatedAt:        time.Now().UTC(),
	}
	sealed, err := researchruntime.BuildPromotionReceipt(r)
	if err != nil {
		t.Fatalf("BuildPromotionReceipt: %v", err)
	}
	return &sealed
}

func newService(drafts store.DraftStore, pubs store.PublicationStore, feed store.FeedStore) *Service {
	publisher := publish.NewRegistryPublisher(pubs, nil)
	return New(drafts, pubs, feed, publisher)
}

// ─── tests ───────────────────────────────────────────────────────────────────

// TestPromote_Success verifies that a valid draft + receipt returns a
// PublicationRecord and appends a promotion_allowed feed event.
func TestPromote_Success(t *testing.T) {
	draftStore := newMemDraftStore()
	pubStore := newMemPublicationStore()
	feedStore := newMemFeedStore()

	draft := makeDraft()
	if err := draftStore.Save(context.Background(), draft); err != nil {
		t.Fatalf("Save draft: %v", err)
	}

	receipt := makeValidReceipt(t)
	svc := newService(draftStore, pubStore, feedStore)

	rec, err := svc.Promote(context.Background(), draft.DraftID, receipt)
	if err != nil {
		t.Fatalf("Promote: unexpected error: %v", err)
	}
	if rec == nil {
		t.Fatal("Promote: expected PublicationRecord, got nil")
	}
	if rec.MissionID != draft.MissionID {
		t.Errorf("MissionID: got %q, want %q", rec.MissionID, draft.MissionID)
	}
	if rec.Title != draft.Title {
		t.Errorf("Title: got %q, want %q", rec.Title, draft.Title)
	}
	if rec.State != researchruntime.PublicationStatePromoted {
		t.Errorf("State: got %q, want %q", rec.State, researchruntime.PublicationStatePromoted)
	}
	if rec.PublicationID == "" {
		t.Error("PublicationID must not be empty")
	}

	// Feed should contain exactly one promotion_allowed event.
	events, _ := feedStore.ByMission(context.Background(), draft.MissionID)
	if len(events) != 1 {
		t.Fatalf("expected 1 feed event, got %d", len(events))
	}
	if events[0].Action != researchruntime.EventPromotionAllowed {
		t.Errorf("feed event Action: got %q, want %q",
			events[0].Action, researchruntime.EventPromotionAllowed)
	}
}

// TestPromote_NilReceipt ensures ErrMissingPromotionReceipt is returned.
func TestPromote_NilReceipt(t *testing.T) {
	draftStore := newMemDraftStore()
	pubStore := newMemPublicationStore()
	feedStore := newMemFeedStore()

	draft := makeDraft()
	_ = draftStore.Save(context.Background(), draft)

	svc := newService(draftStore, pubStore, feedStore)

	_, err := svc.Promote(context.Background(), draft.DraftID, nil)
	if err == nil {
		t.Fatal("expected ErrMissingPromotionReceipt, got nil")
	}
	if !errors.Is(err, publish.ErrMissingPromotionReceipt) {
		t.Errorf("unexpected error: got %v, want ErrMissingPromotionReceipt", err)
	}
}

// TestPromote_InvalidReceiptHash verifies that a tampered ManifestHash is rejected.
func TestPromote_InvalidReceiptHash(t *testing.T) {
	draftStore := newMemDraftStore()
	pubStore := newMemPublicationStore()
	feedStore := newMemFeedStore()

	draft := makeDraft()
	_ = draftStore.Save(context.Background(), draft)

	receipt := makeValidReceipt(t)
	receipt.ManifestHash = "sha256:tampered" // corrupt the hash

	svc := newService(draftStore, pubStore, feedStore)

	_, err := svc.Promote(context.Background(), draft.DraftID, receipt)
	if err == nil {
		t.Fatal("expected an error for invalid receipt hash, got nil")
	}
	// The error must mention "invalid receipt".
	const want = "invalid receipt"
	if !containsString(err.Error(), want) {
		t.Errorf("error message %q does not contain %q", err.Error(), want)
	}
}

// TestSupersede marks an old publication as superseded and checks the store
// update and feed event.
func TestSupersede_MarksRecord(t *testing.T) {
	draftStore := newMemDraftStore()
	pubStore := newMemPublicationStore()
	feedStore := newMemFeedStore()

	// Seed an existing publication directly into the store.
	old := researchruntime.PublicationRecord{
		PublicationID: "pub-old-001",
		MissionID:     "mission-abc",
		State:         researchruntime.PublicationStatePublished,
		Title:         "Old Weekly",
		Version:       1,
	}
	_ = pubStore.Save(context.Background(), old)

	svc := newService(draftStore, pubStore, feedStore)

	if err := svc.Supersede(context.Background(), old.PublicationID, "pub-new-002"); err != nil {
		t.Fatalf("Supersede: %v", err)
	}

	// Confirm the store field was updated.
	stored, err := pubStore.Get(context.Background(), old.PublicationID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if stored == nil {
		t.Fatal("record not found after Supersede")
	}
	if stored.SupersededBy != "pub-new-002" {
		t.Errorf("SupersededBy: got %q, want %q", stored.SupersededBy, "pub-new-002")
	}

	// Feed should carry a publication_superseded event.
	events, _ := feedStore.ByMission(context.Background(), old.MissionID)
	if len(events) != 1 {
		t.Fatalf("expected 1 feed event, got %d", len(events))
	}
	if events[0].Action != researchruntime.EventPublicationSuperseded {
		t.Errorf("feed Action: got %q, want %q",
			events[0].Action, researchruntime.EventPublicationSuperseded)
	}
}

// TestList_ReturnsAll verifies that List returns every saved record.
func TestList_ReturnsAll(t *testing.T) {
	draftStore := newMemDraftStore()
	pubStore := newMemPublicationStore()
	feedStore := newMemFeedStore()

	// Pre-seed three records directly.
	for i, id := range []string{"pub-a", "pub-b", "pub-c"} {
		_ = pubStore.Save(context.Background(), researchruntime.PublicationRecord{
			PublicationID: id,
			MissionID:     "mission-xyz",
			State:         researchruntime.PublicationStatePublished,
			Version:       i + 1,
		})
	}

	svc := newService(draftStore, pubStore, feedStore)

	all, err := svc.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(all) != 3 {
		t.Errorf("List: got %d records, want 3", len(all))
	}
}

// containsString is a tiny helper to avoid importing strings in tests.
func containsString(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 ||
		func() bool {
			for i := 0; i+len(sub) <= len(s); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
			return false
		}())
}
