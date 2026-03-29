package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime/api"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime/store"
)

// ─── in-memory mock stores ────────────────────────────────────────────────────

type memMissionStore struct {
	mu   sync.RWMutex
	data map[string]researchruntime.MissionSpec
}

func newMemMissionStore() *memMissionStore {
	return &memMissionStore{data: make(map[string]researchruntime.MissionSpec)}
}

func (s *memMissionStore) Create(_ context.Context, m researchruntime.MissionSpec) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[m.MissionID] = m
	return nil
}

func (s *memMissionStore) Get(_ context.Context, id string) (*researchruntime.MissionSpec, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	m, ok := s.data[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	return &m, nil
}

func (s *memMissionStore) UpdateState(_ context.Context, id string, state string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.data[id]
	if !ok {
		return store.ErrNotFound
	}
	_ = state
	s.data[id] = m
	return nil
}

func (s *memMissionStore) List(_ context.Context, _ store.MissionFilter) ([]researchruntime.MissionSpec, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]researchruntime.MissionSpec, 0, len(s.data))
	for _, m := range s.data {
		out = append(out, m)
	}
	return out, nil
}

// ── task store ────────────────────────────────────────────────────────────────

type memTaskStore struct{}

func (s *memTaskStore) Create(_ context.Context, _ researchruntime.TaskLease) error { return nil }
func (s *memTaskStore) Get(_ context.Context, _ string) (*researchruntime.TaskLease, error) {
	return nil, store.ErrNotFound
}
func (s *memTaskStore) UpdateState(_ context.Context, _, _ string) error { return nil }
func (s *memTaskStore) ListByMission(_ context.Context, _ string) ([]researchruntime.TaskLease, error) {
	return []researchruntime.TaskLease{}, nil
}
func (s *memTaskStore) AcquireLease(_ context.Context, _, _ string, _ time.Time) error { return nil }
func (s *memTaskStore) ReleaseLease(_ context.Context, _ string) error                 { return nil }

// ── source store ──────────────────────────────────────────────────────────────

type memSourceStore struct{}

func (s *memSourceStore) Save(_ context.Context, _ researchruntime.SourceSnapshot) error { return nil }
func (s *memSourceStore) Get(_ context.Context, _ string) (*researchruntime.SourceSnapshot, error) {
	return nil, store.ErrNotFound
}
func (s *memSourceStore) ListByMission(_ context.Context, _ string) ([]researchruntime.SourceSnapshot, error) {
	return []researchruntime.SourceSnapshot{}, nil
}
func (s *memSourceStore) UpdateState(_ context.Context, _, _ string) error { return nil }

// ── draft store ───────────────────────────────────────────────────────────────

type memDraftStore struct{}

func (s *memDraftStore) Save(_ context.Context, _ researchruntime.DraftManifest) error { return nil }
func (s *memDraftStore) Get(_ context.Context, _ string) (*researchruntime.DraftManifest, error) {
	return nil, store.ErrNotFound
}
func (s *memDraftStore) ListByMission(_ context.Context, _ string) ([]researchruntime.DraftManifest, error) {
	return []researchruntime.DraftManifest{}, nil
}
func (s *memDraftStore) UpdateState(_ context.Context, _, _ string) error { return nil }

// ── publication store ─────────────────────────────────────────────────────────

type memPublicationStore struct {
	mu   sync.RWMutex
	data map[string]researchruntime.PublicationRecord
}

func newMemPublicationStore() *memPublicationStore {
	return &memPublicationStore{data: make(map[string]researchruntime.PublicationRecord)}
}

func (s *memPublicationStore) Save(_ context.Context, p researchruntime.PublicationRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[p.PublicationID] = p
	return nil
}

func (s *memPublicationStore) Get(_ context.Context, id string) (*researchruntime.PublicationRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.data[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	return &p, nil
}

func (s *memPublicationStore) GetBySlug(_ context.Context, _ string) (*researchruntime.PublicationRecord, error) {
	return nil, store.ErrNotFound
}

func (s *memPublicationStore) List(_ context.Context) ([]researchruntime.PublicationRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]researchruntime.PublicationRecord, 0, len(s.data))
	for _, p := range s.data {
		out = append(out, p)
	}
	return out, nil
}

func (s *memPublicationStore) UpdateState(_ context.Context, _, _ string) error { return nil }
func (s *memPublicationStore) SetSupersededBy(_ context.Context, _, _ string) error { return nil }

// ── feed store ────────────────────────────────────────────────────────────────

type memFeedStore struct {
	mu     sync.RWMutex
	events []store.FeedEvent
}

func (s *memFeedStore) Append(_ context.Context, missionID, actor, action, detail string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, store.FeedEvent{
		ID:        "evt-0",
		MissionID: missionID,
		Actor:     actor,
		Action:    action,
		Detail:    detail,
		CreatedAt: time.Now(),
	})
	return nil
}

func (s *memFeedStore) Latest(_ context.Context, limit int) ([]store.FeedEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.events) == 0 {
		return []store.FeedEvent{}, nil
	}
	start := len(s.events) - limit
	if start < 0 {
		start = 0
	}
	out := make([]store.FeedEvent, len(s.events[start:]))
	copy(out, s.events[start:])
	return out, nil
}

func (s *memFeedStore) ByMission(_ context.Context, _ string) ([]store.FeedEvent, error) {
	return []store.FeedEvent{}, nil
}

// ── override store ────────────────────────────────────────────────────────────

type memOverrideStore struct {
	mu   sync.RWMutex
	data map[string]store.Override
}

func newMemOverrideStore() *memOverrideStore {
	return &memOverrideStore{data: make(map[string]store.Override)}
}

func (s *memOverrideStore) Save(_ context.Context, o store.Override) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[o.ID] = o
	return nil
}

func (s *memOverrideStore) Get(_ context.Context, id string) (*store.Override, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	o, ok := s.data[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	return &o, nil
}

func (s *memOverrideStore) ListPending(_ context.Context) ([]store.Override, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]store.Override, 0, len(s.data))
	for _, o := range s.data {
		if o.Decision == "" {
			out = append(out, o)
		}
	}
	return out, nil
}

func (s *memOverrideStore) Resolve(_ context.Context, id, decision, operatorID, notes string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.data[id]
	if !ok {
		return store.ErrNotFound
	}
	o.Decision = decision
	o.OperatorID = operatorID
	o.Notes = notes
	s.data[id] = o
	return nil
}

// ─── test helpers ─────────────────────────────────────────────────────────────

func newTestRouter() (*api.Router, *memMissionStore, *memFeedStore, *memOverrideStore) {
	missions := newMemMissionStore()
	feed := &memFeedStore{}
	overrides := newMemOverrideStore()

	r := api.NewRouter(api.Config{
		Missions:     missions,
		Tasks:        &memTaskStore{},
		Sources:      &memSourceStore{},
		Drafts:       &memDraftStore{},
		Publications: newMemPublicationStore(),
		Feed:         feed,
		Overrides:    overrides,
		Conductor:    nil,
		Publication:  nil,
	})
	return r, missions, feed, overrides
}

func serve(r *api.Router, method, path string, body any) *httptest.ResponseRecorder {
	mux := http.NewServeMux()
	r.Register(mux)

	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

// ─── tests ────────────────────────────────────────────────────────────────────

func TestCreateMission_201(t *testing.T) {
	r, _, _, _ := newTestRouter()

	rr := serve(r, http.MethodPost, "/api/research/missions", map[string]string{
		"title":     "Test Mission",
		"objective": "Learn everything",
		"type":      "research_paper",
	})

	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d — body: %s", rr.Code, rr.Body.String())
	}

	var spec map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&spec); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if spec["mission_id"] == "" || spec["mission_id"] == nil {
		t.Error("response missing mission_id")
	}
	if spec["title"] != "Test Mission" {
		t.Errorf("expected title 'Test Mission', got %v", spec["title"])
	}
}

func TestCreateMission_MissingTitle_400(t *testing.T) {
	r, _, _, _ := newTestRouter()

	rr := serve(r, http.MethodPost, "/api/research/missions", map[string]string{
		"objective": "Learn everything",
	})

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestListMissions_200(t *testing.T) {
	r, missions, _, _ := newTestRouter()

	// Pre-populate a mission so the list is non-empty.
	_ = missions.Create(context.Background(), researchruntime.MissionSpec{
		MissionID: "m-1",
		Title:     "Existing Mission",
		CreatedAt: time.Now(),
	})

	rr := serve(r, http.MethodGet, "/api/research/missions", nil)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", rr.Code, rr.Body.String())
	}

	var list []map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&list); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if len(list) != 1 {
		t.Errorf("expected 1 mission, got %d", len(list))
	}
}

func TestGetMission_200(t *testing.T) {
	r, missions, _, _ := newTestRouter()

	_ = missions.Create(context.Background(), researchruntime.MissionSpec{
		MissionID: "m-abc",
		Title:     "Detail Mission",
		CreatedAt: time.Now(),
	})

	rr := serve(r, http.MethodGet, "/api/research/missions/m-abc", nil)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", rr.Code, rr.Body.String())
	}

	var m map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&m); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if m["mission_id"] != "m-abc" {
		t.Errorf("expected mission_id 'm-abc', got %v", m["mission_id"])
	}
}

func TestGetMission_NotFound_404(t *testing.T) {
	r, _, _, _ := newTestRouter()

	rr := serve(r, http.MethodGet, "/api/research/missions/does-not-exist", nil)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rr.Code)
	}
}

func TestGetFeed_200(t *testing.T) {
	r, _, feed, _ := newTestRouter()

	// Add a feed event.
	_ = feed.Append(context.Background(), "m-1", "test", "action", "detail")

	rr := serve(r, http.MethodGet, "/api/research/feed", nil)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", rr.Code, rr.Body.String())
	}

	var events []map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&events); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if len(events) != 1 {
		t.Errorf("expected 1 event, got %d", len(events))
	}
}

func TestListOverrides_200(t *testing.T) {
	r, _, _, overrides := newTestRouter()

	// Add a pending override.
	_ = overrides.Save(context.Background(), store.Override{
		ID:        "ov-1",
		MissionID: "m-1",
		CreatedAt: time.Now(),
	})

	rr := serve(r, http.MethodGet, "/api/research/overrides", nil)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", rr.Code, rr.Body.String())
	}

	var list []map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&list); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if len(list) != 1 {
		t.Errorf("expected 1 override, got %d", len(list))
	}
}

func TestCancelMission_200(t *testing.T) {
	r, missions, _, _ := newTestRouter()

	_ = missions.Create(context.Background(), researchruntime.MissionSpec{
		MissionID: "m-cancel",
		Title:     "To Cancel",
		CreatedAt: time.Now(),
	})

	rr := serve(r, http.MethodPost, "/api/research/missions/m-cancel/cancel", nil)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode: %v", err)
	}
	if resp["status"] != "canceled" {
		t.Errorf("expected status 'canceled', got %q", resp["status"])
	}
}
