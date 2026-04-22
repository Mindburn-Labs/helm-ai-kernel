package conductor_test

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime/agents"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime/conductor"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime/store"
)

// ── in-memory mock stores ────────────────────────────────────────────────────

type mockMissionStore struct {
	mu     sync.Mutex
	states map[string]string
}

func newMockMissionStore() *mockMissionStore {
	return &mockMissionStore{states: make(map[string]string)}
}
func (m *mockMissionStore) Create(_ context.Context, ms researchruntime.MissionSpec) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.states[ms.MissionID] = "pending"
	return nil
}
func (m *mockMissionStore) Get(_ context.Context, id string) (*researchruntime.MissionSpec, error) {
	return &researchruntime.MissionSpec{MissionID: id}, nil
}
func (m *mockMissionStore) UpdateState(_ context.Context, id, state string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.states[id] = state
	return nil
}
func (m *mockMissionStore) List(_ context.Context, _ store.MissionFilter) ([]researchruntime.MissionSpec, error) {
	return nil, nil
}
func (m *mockMissionStore) stateOf(id string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.states[id]
}

// ────────────────────────────────────────────────────────────────────────────

type mockTaskStore struct {
	mu     sync.Mutex
	tasks  map[string]researchruntime.TaskLease // keyed by LeaseID
	states map[string]string
}

func newMockTaskStore() *mockTaskStore {
	return &mockTaskStore{
		tasks:  make(map[string]researchruntime.TaskLease),
		states: make(map[string]string),
	}
}
func (m *mockTaskStore) Create(_ context.Context, t researchruntime.TaskLease) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tasks[t.LeaseID] = t
	m.states[t.LeaseID] = "pending"
	return nil
}
func (m *mockTaskStore) Get(_ context.Context, id string) (*researchruntime.TaskLease, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tasks[id]
	if !ok {
		return nil, errors.New("not found")
	}
	return &t, nil
}
func (m *mockTaskStore) UpdateState(_ context.Context, id, state string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.states[id] = state
	return nil
}
func (m *mockTaskStore) ListByMission(_ context.Context, missionID string) ([]researchruntime.TaskLease, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []researchruntime.TaskLease
	for _, t := range m.tasks {
		if t.MissionID == missionID {
			out = append(out, t)
		}
	}
	return out, nil
}
func (m *mockTaskStore) AcquireLease(_ context.Context, id, _ string, _ time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.states[id] = "leased"
	return nil
}
func (m *mockTaskStore) ReleaseLease(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.states[id] = "released"
	return nil
}
func (m *mockTaskStore) stateOf(leaseID string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.states[leaseID]
}

// ────────────────────────────────────────────────────────────────────────────

type mockFeedStore struct {
	mu     sync.Mutex
	events []store.FeedEvent
}

func (m *mockFeedStore) Append(_ context.Context, missionID, actor, action, detail string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, store.FeedEvent{
		MissionID: missionID,
		Actor:     actor,
		Action:    action,
		Detail:    detail,
		CreatedAt: time.Now(),
	})
	return nil
}
func (m *mockFeedStore) Latest(_ context.Context, limit int) ([]store.FeedEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if limit <= 0 || limit >= len(m.events) {
		return append([]store.FeedEvent{}, m.events...), nil
	}
	return append([]store.FeedEvent{}, m.events[len(m.events)-limit:]...), nil
}
func (m *mockFeedStore) ByMission(_ context.Context, missionID string) ([]store.FeedEvent, error) {
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
func (m *mockFeedStore) hasAction(action string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range m.events {
		if e.Action == action {
			return true
		}
	}
	return false
}

// ────────────────────────────────────────────────────────────────────────────

type mockBlobStore struct {
	mu   sync.Mutex
	data map[string][]byte
}

func newMockBlobStore() *mockBlobStore {
	return &mockBlobStore{data: make(map[string][]byte)}
}
func (m *mockBlobStore) Put(_ context.Context, key string, data []byte, _ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]byte, len(data))
	copy(cp, data)
	m.data[key] = cp
	return nil
}
func (m *mockBlobStore) Get(_ context.Context, key string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.data[key]
	if !ok {
		return nil, errors.New("blob not found: " + key)
	}
	return v, nil
}
func (m *mockBlobStore) Exists(_ context.Context, key string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.data[key]
	return ok, nil
}

// ── mock agent ───────────────────────────────────────────────────────────────

type mockAgent struct {
	role   researchruntime.WorkerRole
	output []byte
	err    error
	calls  int
	mu     sync.Mutex
}

func (a *mockAgent) Role() researchruntime.WorkerRole { return a.role }
func (a *mockAgent) Execute(_ context.Context, _ *researchruntime.TaskLease, _ []byte) ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls++
	return a.output, a.err
}
func (a *mockAgent) callCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.calls
}

// Compile-time interface checks.
var _ agents.Agent = (*mockAgent)(nil)

// ── helpers ──────────────────────────────────────────────────────────────────

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("mustMarshal: %v", err)
	}
	return b
}

// seedMission creates a standard two-node graph (planner → synthesizer),
// stores the WorkGraph blob, and inserts two TaskLease records into the task store.
func seedMission(
	t *testing.T,
	missionID string,
	blobs *mockBlobStore,
	tasks *mockTaskStore,
) (plannerLeaseID, synthLeaseID string) {
	t.Helper()

	graph := researchruntime.WorkGraph{
		MissionID: missionID,
		Version:   "1",
		Nodes: []researchruntime.WorkNode{
			{ID: "node-plan", Role: researchruntime.WorkerPlanner, Title: "Plan", Purpose: "build graph", Required: true},
			{ID: "node-synth", Role: researchruntime.WorkerSynthesizer, Title: "Synth", Purpose: "synthesize", DependsOn: []string{"node-plan"}, Required: true},
		},
		Edges: []researchruntime.WorkEdge{
			{From: "node-plan", To: "node-synth", Kind: "depends"},
		},
	}
	if err := blobs.Put(context.Background(), conductor.WorkGraphKey(missionID), mustMarshal(t, graph), "application/json"); err != nil {
		t.Fatalf("seed blob: %v", err)
	}

	plannerLeaseID = "lease-plan-001"
	synthLeaseID = "lease-synth-001"

	if err := tasks.Create(context.Background(), researchruntime.TaskLease{
		LeaseID:   plannerLeaseID,
		MissionID: missionID,
		NodeID:    "node-plan",
		Role:      researchruntime.WorkerPlanner,
		DeadlineAt: time.Now().Add(5 * time.Minute),
	}); err != nil {
		t.Fatalf("create planner task: %v", err)
	}
	if err := tasks.Create(context.Background(), researchruntime.TaskLease{
		LeaseID:   synthLeaseID,
		MissionID: missionID,
		NodeID:    "node-synth",
		Role:      researchruntime.WorkerSynthesizer,
		DeadlineAt: time.Now().Add(10 * time.Minute),
	}); err != nil {
		t.Fatalf("create synth task: %v", err)
	}
	return
}

// ── tests ────────────────────────────────────────────────────────────────────

// TestConductor_RunMission verifies the happy path: two tasks (planner →
// synthesizer) both reach "completed" state and the feed contains the
// expected lifecycle events.
func TestConductor_RunMission(t *testing.T) {
	const missionID = "mission-test-001"

	missions := newMockMissionStore()
	taskStore := newMockTaskStore()
	feed := &mockFeedStore{}
	blobs := newMockBlobStore()

	plannerOut := mustMarshal(t, map[string]string{"plan": "do research"})
	synthOut := mustMarshal(t, map[string]string{"synthesis": "here is the report"})

	plannerAgent := &mockAgent{role: researchruntime.WorkerPlanner, output: plannerOut}
	synthAgent := &mockAgent{role: researchruntime.WorkerSynthesizer, output: synthOut}

	plannerLeaseID, synthLeaseID := seedMission(t, missionID, blobs, taskStore)

	cfg := conductor.Config{
		Missions: missions,
		Tasks:    taskStore,
		Feed:     feed,
		Blobs:    blobs,
		Agents: map[researchruntime.WorkerRole]agents.Agent{
			researchruntime.WorkerPlanner:     plannerAgent,
			researchruntime.WorkerSynthesizer: synthAgent,
		},
		Retry: &conductor.RetryPolicy{MaxAttempts: 1, BaseDelay: 0},
	}

	svc := conductor.New(cfg)
	if err := svc.Run(context.Background(), missionID); err != nil {
		t.Fatalf("Run() unexpected error: %v", err)
	}

	// Both tasks should be completed.
	if got := taskStore.stateOf(plannerLeaseID); got != "completed" {
		t.Errorf("planner task state = %q, want %q", got, "completed")
	}
	if got := taskStore.stateOf(synthLeaseID); got != "completed" {
		t.Errorf("synthesizer task state = %q, want %q", got, "completed")
	}

	// Mission should be published.
	if got := missions.stateOf(missionID); got != "published" {
		t.Errorf("mission state = %q, want %q", got, "published")
	}

	// Each agent should have been called exactly once.
	if n := plannerAgent.callCount(); n != 1 {
		t.Errorf("planner agent calls = %d, want 1", n)
	}
	if n := synthAgent.callCount(); n != 1 {
		t.Errorf("synthesizer agent calls = %d, want 1", n)
	}

	// Feed must contain lifecycle events.
	for _, action := range []string{"mission_started", "task_started", "task_completed", "mission_completed"} {
		if !feed.hasAction(action) {
			t.Errorf("feed missing action %q", action)
		}
	}

	// Planner output blob must have been written.
	plannerBlobKey := conductor.TaskOutputKey(missionID, plannerLeaseID)
	if exists, _ := blobs.Exists(context.Background(), plannerBlobKey); !exists {
		t.Errorf("expected blob at %s to exist", plannerBlobKey)
	}
}

// TestConductor_TaskFailure verifies that when an agent returns an error, the
// conductor marks the task and mission as failed and propagates the error.
func TestConductor_TaskFailure(t *testing.T) {
	const missionID = "mission-fail-001"

	missions := newMockMissionStore()
	taskStore := newMockTaskStore()
	feed := &mockFeedStore{}
	blobs := newMockBlobStore()

	boom := errors.New("agent exploded")
	failingAgent := &mockAgent{role: researchruntime.WorkerPlanner, err: boom}

	seedMission(t, missionID, blobs, taskStore)

	cfg := conductor.Config{
		Missions: missions,
		Tasks:    taskStore,
		Feed:     feed,
		Blobs:    blobs,
		Agents: map[researchruntime.WorkerRole]agents.Agent{
			researchruntime.WorkerPlanner:     failingAgent,
			researchruntime.WorkerSynthesizer: &mockAgent{role: researchruntime.WorkerSynthesizer},
		},
		Retry: &conductor.RetryPolicy{MaxAttempts: 1, BaseDelay: 0},
	}

	svc := conductor.New(cfg)
	err := svc.Run(context.Background(), missionID)
	if err == nil {
		t.Fatal("Run() expected error, got nil")
	}
	if !errors.Is(err, boom) {
		t.Errorf("Run() error = %v, want wrapping %v", err, boom)
	}

	if got := missions.stateOf(missionID); got != "failed" {
		t.Errorf("mission state = %q, want %q", got, "failed")
	}
	if !feed.hasAction("mission_failed") {
		t.Error("feed missing mission_failed event")
	}
}

// TestConductor_RetryOnTransientFailure verifies that a task that fails on the
// first attempt but succeeds on the second is ultimately completed.
func TestConductor_RetryOnTransientFailure(t *testing.T) {
	const missionID = "mission-retry-001"

	missions := newMockMissionStore()
	taskStore := newMockTaskStore()
	feed := &mockFeedStore{}
	blobs := newMockBlobStore()

	attempt := 0
	transientAgent := &flakyAgent{failN: 1, role: researchruntime.WorkerPlanner, out: []byte(`{"ok":true}`)}
	_ = attempt

	seedMission(t, missionID, blobs, taskStore)

	cfg := conductor.Config{
		Missions: missions,
		Tasks:    taskStore,
		Feed:     feed,
		Blobs:    blobs,
		Agents: map[researchruntime.WorkerRole]agents.Agent{
			researchruntime.WorkerPlanner:     transientAgent,
			researchruntime.WorkerSynthesizer: &mockAgent{role: researchruntime.WorkerSynthesizer, output: []byte(`{}`)},
		},
		Retry: &conductor.RetryPolicy{MaxAttempts: 3, BaseDelay: 0},
	}

	svc := conductor.New(cfg)
	if err := svc.Run(context.Background(), missionID); err != nil {
		t.Fatalf("Run() unexpected error after retry: %v", err)
	}
	if transientAgent.callCount() < 2 {
		t.Errorf("expected at least 2 calls (fail then succeed), got %d", transientAgent.callCount())
	}
	if got := missions.stateOf(missionID); got != "published" {
		t.Errorf("mission state = %q, want %q", got, "published")
	}
}

// TestConductor_MissingAgent verifies that a missing agent for a required role
// causes an immediate failure.
func TestConductor_MissingAgent(t *testing.T) {
	const missionID = "mission-noagent-001"

	missions := newMockMissionStore()
	taskStore := newMockTaskStore()
	feed := &mockFeedStore{}
	blobs := newMockBlobStore()

	seedMission(t, missionID, blobs, taskStore)

	cfg := conductor.Config{
		Missions: missions,
		Tasks:    taskStore,
		Feed:     feed,
		Blobs:    blobs,
		Agents:   map[researchruntime.WorkerRole]agents.Agent{}, // intentionally empty
		Retry:    &conductor.RetryPolicy{MaxAttempts: 1, BaseDelay: 0},
	}

	svc := conductor.New(cfg)
	if err := svc.Run(context.Background(), missionID); err == nil {
		t.Fatal("Run() expected error for missing agent, got nil")
	}
	if got := missions.stateOf(missionID); got != "failed" {
		t.Errorf("mission state = %q, want %q", got, "failed")
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

// flakyAgent fails the first failN calls, then succeeds.
type flakyAgent struct {
	mu     sync.Mutex
	role   researchruntime.WorkerRole
	calls  int
	failN  int
	out    []byte
}

func (f *flakyAgent) Role() researchruntime.WorkerRole { return f.role }
func (f *flakyAgent) Execute(_ context.Context, _ *researchruntime.TaskLease, _ []byte) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.calls <= f.failN {
		return nil, errors.New("transient failure")
	}
	return f.out, nil
}
func (f *flakyAgent) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}
