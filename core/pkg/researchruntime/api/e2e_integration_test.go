//go:build integration

// End-to-end smoke test for the researchruntime HTTP API.
//
// Covers the 12 endpoints that only depend on the store layer. The two
// endpoints that require wired services are deferred:
//   - POST /api/research/publications/{id}/publish  (needs publication.Service)
//   - GET  /api/research/feed/stream                (SSE — exercised separately)
// See docs/ai/adr-researchruntime-cmd-helm-mount.md for the 3-commit plan
// that lands the full conductor/publication wiring.
//
// Run with:
//
//	TEST_DB_URL=postgres://... go test -tags=integration ./pkg/researchruntime/api/... -count=1
package api_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime"
	researchapi "github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime/api"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime/store"
)

func openDB(t *testing.T) *sql.DB {
	t.Helper()
	url := os.Getenv("TEST_DB_URL")
	if url == "" {
		t.Skip("TEST_DB_URL not set; skipping E2E smoke")
	}
	db, err := sql.Open("postgres", url)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		t.Fatalf("ping: %v", err)
	}
	for _, m := range []string{
		"../store/migrations/001_research_missions.sql",
		"../store/migrations/002_research_tasks.sql",
		"../store/migrations/003_research_sources.sql",
		"../store/migrations/004_research_artifacts.sql",
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

func newTestMux(t *testing.T, db *sql.DB) *http.ServeMux {
	t.Helper()
	cfg := researchapi.Config{
		Missions:     store.NewPostgresMissionStore(db),
		Tasks:        store.NewPostgresTaskStore(db),
		Sources:      store.NewPostgresSourceStore(db),
		Drafts:       store.NewPostgresDraftStore(db),
		Publications: store.NewPostgresPublicationStore(db),
		Feed:         store.NewPostgresFeedStore(db),
		Overrides:    store.NewPostgresOverrideStore(db),
		// Conductor + Publication intentionally nil — this E2E avoids
		// endpoints that depend on those services.
	}
	mux := http.NewServeMux()
	researchapi.NewRouter(cfg).Register(mux)
	return mux
}

func unique(t *testing.T, prefix string) string {
	t.Helper()
	name := strings.ReplaceAll(t.Name(), "/", "-")
	return fmt.Sprintf("%s-%s-%d", prefix, name, time.Now().UnixNano())
}

func do(t *testing.T, mux *http.ServeMux, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf *bytes.Buffer
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal %s %s: %v", method, path, err)
		}
		buf = bytes.NewBuffer(b)
	} else {
		buf = &bytes.Buffer{}
	}
	req := httptest.NewRequest(method, path, buf)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestResearchAPI_E2E_Smoke(t *testing.T) {
	ctx := context.Background()
	db := openDB(t)
	defer db.Close()
	mux := newTestMux(t, db)

	missionID := unique(t, "mission")
	slug := unique(t, "slug")

	t.Run("create mission", func(t *testing.T) {
		rec := do(t, mux, http.MethodPost, "/api/research/missions", map[string]any{
			"mission_id": missionID,
			"title":      "E2E smoke mission",
			"thesis":     "verify API surface end-to-end",
			"class":      "daily_brief",
			"trigger": map[string]any{
				"type": "manual",
			},
		})
		if rec.Code < 200 || rec.Code >= 300 {
			t.Fatalf("createMission: status %d body %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("list missions", func(t *testing.T) {
		rec := do(t, mux, http.MethodGet, "/api/research/missions", nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("listMissions: status %d body %s", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), missionID) {
			t.Errorf("listMissions: missionID %q not in body", missionID)
		}
	})

	t.Run("get mission", func(t *testing.T) {
		rec := do(t, mux, http.MethodGet, "/api/research/missions/"+missionID, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("getMission: status %d body %s", rec.Code, rec.Body.String())
		}
	})

	taskID := unique(t, "task")
	if err := store.NewPostgresTaskStore(db).Create(ctx, researchruntime.TaskLease{
		LeaseID: taskID, MissionID: missionID,
		NodeID: "planner-1", Role: researchruntime.WorkerPlanner,
		DeadlineAt: time.Now().Add(time.Minute).UTC(),
	}); err != nil {
		t.Fatalf("seed task: %v", err)
	}
	sourceID := unique(t, "source")
	if err := store.NewPostgresSourceStore(db).Save(ctx, researchruntime.SourceSnapshot{
		SourceID: sourceID, MissionID: missionID,
		URL:              "https://example.com/",
		ContentHash:      "sha256:seed",
		ProvenanceStatus: researchruntime.ProvenanceCaptured,
	}); err != nil {
		t.Fatalf("seed source: %v", err)
	}
	draftID := unique(t, "draft")
	if err := store.NewPostgresDraftStore(db).Save(ctx, researchruntime.DraftManifest{
		DraftID:   draftID,
		MissionID: missionID,
		Title:     "smoke draft",
		Version:   1,
	}); err != nil {
		t.Fatalf("seed draft: %v", err)
	}
	if err := store.NewPostgresFeedStore(db).Append(ctx, missionID, "conductor", "mission.created", "seeded"); err != nil {
		t.Fatalf("seed feed: %v", err)
	}

	t.Run("list tasks", func(t *testing.T) {
		rec := do(t, mux, http.MethodGet, "/api/research/missions/"+missionID+"/tasks", nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("listTasks: %d %s", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), taskID) {
			t.Errorf("listTasks: taskID %q missing", taskID)
		}
	})
	t.Run("list sources", func(t *testing.T) {
		rec := do(t, mux, http.MethodGet, "/api/research/missions/"+missionID+"/sources", nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("listSources: %d %s", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), sourceID) {
			t.Errorf("listSources: sourceID %q missing", sourceID)
		}
	})
	t.Run("list drafts", func(t *testing.T) {
		rec := do(t, mux, http.MethodGet, "/api/research/missions/"+missionID+"/drafts", nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("listDrafts: %d %s", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), draftID) {
			t.Errorf("listDrafts: draftID %q missing", draftID)
		}
	})

	pubID := unique(t, "pub")
	if err := store.NewPostgresPublicationStore(db).Save(ctx, researchruntime.PublicationRecord{
		PublicationID: pubID, MissionID: missionID,
		Class: researchruntime.PublicationClassInternalNote,
		State: researchruntime.PublicationStateDraft,
		Title: "smoke pub",
		Slug:  slug,
	}); err != nil {
		t.Fatalf("seed publication: %v", err)
	}
	t.Run("list publications", func(t *testing.T) {
		rec := do(t, mux, http.MethodGet, "/api/research/publications", nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("listPublications: %d %s", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), pubID) {
			t.Errorf("listPublications: pubID %q missing", pubID)
		}
	})
	t.Run("get publication", func(t *testing.T) {
		rec := do(t, mux, http.MethodGet, "/api/research/publications/"+pubID, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("getPublication: %d %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("feed", func(t *testing.T) {
		rec := do(t, mux, http.MethodGet, "/api/research/feed", nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("feed: %d %s", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "mission.created") {
			t.Errorf("feed: expected seeded event, got %s", rec.Body.String())
		}
	})

	overrideID := unique(t, "override")
	if err := store.NewPostgresOverrideStore(db).Save(ctx, store.Override{
		ID:          overrideID,
		MissionID:   missionID,
		ArtifactID:  draftID,
		ReasonCodes: []string{"low_editor_score"},
		Decision:    "pending",
		CreatedAt:   time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seed override: %v", err)
	}
	t.Run("list overrides", func(t *testing.T) {
		rec := do(t, mux, http.MethodGet, "/api/research/overrides", nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("listOverrides: %d %s", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), overrideID) {
			t.Errorf("listOverrides: overrideID %q missing", overrideID)
		}
	})
	t.Run("resolve override", func(t *testing.T) {
		rec := do(t, mux, http.MethodPost, "/api/research/overrides/"+overrideID+"/resolve", map[string]any{
			"decision":    "approved",
			"operator_id": "smoke-operator",
			"notes":       "e2e",
		})
		if rec.Code < 200 || rec.Code >= 300 {
			t.Fatalf("resolveOverride: %d %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("cancel mission", func(t *testing.T) {
		rec := do(t, mux, http.MethodPost, "/api/research/missions/"+missionID+"/cancel", nil)
		if rec.Code < 200 || rec.Code >= 300 {
			t.Fatalf("cancelMission: %d %s", rec.Code, rec.Body.String())
		}
	})
}
