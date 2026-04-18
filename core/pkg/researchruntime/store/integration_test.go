//go:build integration

// Package store integration tests.
//
// Run with:
//
//	TEST_DB_URL=postgres://... go test -tags=integration ./pkg/researchruntime/store/... -count=1
//
// If TEST_DB_URL is not set the tests skip, so unit-only CI stays green.
// Migrations under ./migrations/ are applied idempotently at test start.
// Each subtest uses unique IDs (t.Name + nanosecond suffix) so parallel runs
// and reruns against a persistent test DB do not collide.
package store_test

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime/store"
)

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	url := os.Getenv("TEST_DB_URL")
	if url == "" {
		t.Skip("TEST_DB_URL not set; skipping integration test")
	}
	db, err := sql.Open("postgres", url)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		t.Fatalf("ping: %v", err)
	}
	for _, m := range []string{
		"migrations/001_research_missions.sql",
		"migrations/002_research_tasks.sql",
		"migrations/003_research_sources.sql",
		"migrations/004_research_artifacts.sql",
	} {
		body, err := os.ReadFile(filepath.Clean(m))
		if err != nil {
			t.Fatalf("read migration %s: %v", m, err)
		}
		if _, err := db.Exec(string(body)); err != nil {
			t.Fatalf("apply migration %s: %v", m, err)
		}
	}
	return db
}

func uniqueID(t *testing.T, prefix string) string {
	t.Helper()
	name := strings.ReplaceAll(t.Name(), "/", "-")
	return fmt.Sprintf("%s-%s-%d", prefix, name, time.Now().UnixNano())
}

func seedMission(t *testing.T, ctx context.Context, db *sql.DB) string {
	t.Helper()
	ms := store.NewPostgresMissionStore(db)
	id := uniqueID(t, "mission")
	if err := ms.Create(ctx, researchruntime.MissionSpec{
		MissionID: id,
		Title:     "seed mission",
		Thesis:    "fixture for foreign-key parents",
		Class:     researchruntime.MissionClassDailyBrief,
		Trigger:   researchruntime.MissionTrigger{Type: researchruntime.MissionTriggerManual},
	}); err != nil {
		t.Fatalf("seedMission: %v", err)
	}
	return id
}

func TestMissionStore_Integration(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	defer db.Close()

	s := store.NewPostgresMissionStore(db)
	id := uniqueID(t, "mission")

	spec := researchruntime.MissionSpec{
		MissionID:       id,
		Title:           "integration test mission",
		Thesis:          "validate postgres store end-to-end",
		Class:           researchruntime.MissionClassDailyBrief,
		QuerySeeds:      []string{"helm research runtime"},
		MaxBudgetTokens: 1000,
		MaxBudgetCents:  500,
		Trigger: researchruntime.MissionTrigger{
			Type:     researchruntime.MissionTriggerSchedule,
			Schedule: "0 9 * * *",
		},
	}

	if err := s.Create(ctx, spec); err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, err := s.Get(ctx, id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Title != spec.Title {
		t.Errorf("Title: got %q want %q", got.Title, spec.Title)
	}
	if got.Class != spec.Class {
		t.Errorf("Class: got %q want %q", got.Class, spec.Class)
	}
	if got.MaxBudgetTokens != spec.MaxBudgetTokens {
		t.Errorf("MaxBudgetTokens: got %d want %d", got.MaxBudgetTokens, spec.MaxBudgetTokens)
	}
	if got.Trigger.Schedule != spec.Trigger.Schedule {
		t.Errorf("Trigger.Schedule: got %q want %q", got.Trigger.Schedule, spec.Trigger.Schedule)
	}

	if err := s.UpdateState(ctx, id, "running"); err != nil {
		t.Fatalf("UpdateState: %v", err)
	}

	list, err := s.List(ctx, store.MissionFilter{Limit: 100})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	found := false
	for _, m := range list {
		if m.MissionID == id {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Create+List: mission %q not in list", id)
	}

	if _, err := s.Get(ctx, "nonexistent-"+uniqueID(t, "id")); err == nil {
		t.Errorf("Get(missing) returned nil error; want ErrNotFound")
	}
}

func TestTaskStore_Integration(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	defer db.Close()

	missionID := seedMission(t, ctx, db)
	s := store.NewPostgresTaskStore(db)
	id := uniqueID(t, "task")

	lease := researchruntime.TaskLease{
		LeaseID:    id,
		MissionID:  missionID,
		NodeID:     "node-planner-1",
		Role:       researchruntime.WorkerPlanner,
		DeadlineAt: time.Now().Add(5 * time.Minute).UTC(),
		RetryCount: 0,
	}
	if err := s.Create(ctx, lease); err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, err := s.Get(ctx, id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Role != researchruntime.WorkerPlanner {
		t.Errorf("Role: got %q want planner", got.Role)
	}

	if err := s.UpdateState(ctx, id, "running"); err != nil {
		t.Fatalf("UpdateState: %v", err)
	}

	until := time.Now().Add(1 * time.Minute).UTC()
	if err := s.AcquireLease(ctx, id, "worker-1", until); err != nil {
		t.Fatalf("AcquireLease: %v", err)
	}
	if err := s.ReleaseLease(ctx, id); err != nil {
		t.Fatalf("ReleaseLease: %v", err)
	}

	list, err := s.ListByMission(ctx, missionID)
	if err != nil {
		t.Fatalf("ListByMission: %v", err)
	}
	found := false
	for _, l := range list {
		if l.LeaseID == id {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("ListByMission: task %q missing", id)
	}
}

func TestSourceStore_Integration(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	defer db.Close()

	missionID := seedMission(t, ctx, db)
	s := store.NewPostgresSourceStore(db)
	id := uniqueID(t, "source")

	snap := researchruntime.SourceSnapshot{
		SourceID:         id,
		MissionID:        missionID,
		URL:              "https://example.com/paper.pdf",
		CanonicalURL:     "https://example.com/paper",
		Title:            "Example paper",
		ContentHash:      "sha256:deadbeef",
		SnapshotHash:     "sha256:cafebabe",
		FreshnessScore:   0.9,
		Primary:          true,
		CapturedAt:       time.Now().UTC(),
		ProvenanceStatus: researchruntime.ProvenanceCaptured,
	}
	if err := s.Save(ctx, snap); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := s.Get(ctx, id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.URL != snap.URL {
		t.Errorf("URL: got %q want %q", got.URL, snap.URL)
	}
	if !got.Primary {
		t.Errorf("Primary: got %v want true", got.Primary)
	}

	if err := s.UpdateState(ctx, id, string(researchruntime.ProvenanceVerified)); err != nil {
		t.Fatalf("UpdateState: %v", err)
	}

	list, err := s.ListByMission(ctx, missionID)
	if err != nil {
		t.Fatalf("ListByMission: %v", err)
	}
	if len(list) == 0 {
		t.Errorf("ListByMission: got 0 sources for mission %q", missionID)
	}
}

func TestDraftStore_Integration(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	defer db.Close()

	missionID := seedMission(t, ctx, db)
	s := store.NewPostgresDraftStore(db)
	id := uniqueID(t, "draft")

	draft := researchruntime.DraftManifest{
		DraftID:   id,
		MissionID: missionID,
		Title:     "first draft",
		Version:   1,
		ArtifactHashes: map[string]any{
			"body":     "sha256:aaa",
			"outline":  "sha256:bbb",
			"evidence": "sha256:ccc",
		},
		CreatedAt: time.Now().UTC(),
	}
	if err := s.Save(ctx, draft); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := s.Get(ctx, id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.MissionID != missionID {
		t.Errorf("MissionID: got %q want %q", got.MissionID, missionID)
	}

	if err := s.UpdateState(ctx, id, "verifying"); err != nil {
		t.Fatalf("UpdateState: %v", err)
	}

	list, err := s.ListByMission(ctx, missionID)
	if err != nil {
		t.Fatalf("ListByMission: %v", err)
	}
	if len(list) == 0 {
		t.Errorf("ListByMission: got 0 drafts for mission %q", missionID)
	}
}

func TestPublicationStore_Integration(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	defer db.Close()

	missionID := seedMission(t, ctx, db)
	s := store.NewPostgresPublicationStore(db)
	idA := uniqueID(t, "pub-a")
	idB := uniqueID(t, "pub-b")
	slugA := "pub-" + uniqueID(t, "slug")

	recA := researchruntime.PublicationRecord{
		PublicationID:    idA,
		MissionID:        missionID,
		Class:            researchruntime.PublicationClassInternalNote,
		State:            researchruntime.PublicationStateDraft,
		Title:            "initial pub",
		Slug:             slugA,
		EvidencePackHash: "sha256:evidence-a",
		Version:          1,
	}
	if err := s.Save(ctx, recA); err != nil {
		t.Fatalf("Save A: %v", err)
	}

	got, err := s.Get(ctx, idA)
	if err != nil {
		t.Fatalf("Get A: %v", err)
	}
	if got.Slug != slugA {
		t.Errorf("Slug: got %q want %q", got.Slug, slugA)
	}

	bySlug, err := s.GetBySlug(ctx, slugA)
	if err != nil {
		t.Fatalf("GetBySlug: %v", err)
	}
	if bySlug.PublicationID != idA {
		t.Errorf("GetBySlug: got %q want %q", bySlug.PublicationID, idA)
	}

	if err := s.UpdateState(ctx, idA, string(researchruntime.PublicationStatePromoted)); err != nil {
		t.Fatalf("UpdateState: %v", err)
	}

	recB := researchruntime.PublicationRecord{
		PublicationID:    idB,
		MissionID:        missionID,
		Class:            researchruntime.PublicationClassInternalNote,
		State:            researchruntime.PublicationStateDraft,
		Title:            "revision",
		Slug:             "pub-" + uniqueID(t, "slugB"),
		EvidencePackHash: "sha256:evidence-b",
		Version:          2,
	}
	if err := s.Save(ctx, recB); err != nil {
		t.Fatalf("Save B: %v", err)
	}
	if err := s.SetSupersededBy(ctx, idA, idB); err != nil {
		t.Fatalf("SetSupersededBy: %v", err)
	}

	list, err := s.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	seenA, seenB := false, false
	for _, r := range list {
		if r.PublicationID == idA {
			seenA = true
		}
		if r.PublicationID == idB {
			seenB = true
		}
	}
	if !seenA || !seenB {
		t.Errorf("List: missing records A=%v B=%v", seenA, seenB)
	}
}

func TestFeedStore_Integration(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	defer db.Close()

	missionID := seedMission(t, ctx, db)
	s := store.NewPostgresFeedStore(db)

	if err := s.Append(ctx, missionID, "conductor", "mission.created", "seeded"); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if err := s.Append(ctx, missionID, "planner", "graph.built", "7 nodes"); err != nil {
		t.Fatalf("Append 2: %v", err)
	}

	latest, err := s.Latest(ctx, 10)
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}
	if len(latest) == 0 {
		t.Errorf("Latest: got 0 events")
	}

	byMission, err := s.ByMission(ctx, missionID)
	if err != nil {
		t.Fatalf("ByMission: %v", err)
	}
	if len(byMission) < 2 {
		t.Errorf("ByMission: got %d events want >=2", len(byMission))
	}
}

func TestOverrideStore_Integration(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	defer db.Close()

	missionID := seedMission(t, ctx, db)
	s := store.NewPostgresOverrideStore(db)
	id := uniqueID(t, "override")

	ov := store.Override{
		ID:          id,
		MissionID:   missionID,
		ArtifactID:  "draft-1",
		ReasonCodes: []string{"low_editor_score", "single_primary_source"},
		OperatorID:  "",
		Decision:    "pending",
		Notes:       "needs human review",
		CreatedAt:   time.Now().UTC(),
	}
	if err := s.Save(ctx, ov); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := s.Get(ctx, id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.MissionID != missionID {
		t.Errorf("MissionID: got %q want %q", got.MissionID, missionID)
	}
	if len(got.ReasonCodes) != 2 {
		t.Errorf("ReasonCodes: got %d want 2", len(got.ReasonCodes))
	}

	pending, err := s.ListPending(ctx)
	if err != nil {
		t.Fatalf("ListPending: %v", err)
	}
	foundPending := false
	for _, o := range pending {
		if o.ID == id {
			foundPending = true
			break
		}
	}
	if !foundPending {
		t.Errorf("ListPending: override %q not found", id)
	}

	if err := s.Resolve(ctx, id, "approved", "operator-1", "looks good"); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	resolved, err := s.Get(ctx, id)
	if err != nil {
		t.Fatalf("Get after Resolve: %v", err)
	}
	if resolved.Decision != "approved" {
		t.Errorf("Decision: got %q want approved", resolved.Decision)
	}
}
