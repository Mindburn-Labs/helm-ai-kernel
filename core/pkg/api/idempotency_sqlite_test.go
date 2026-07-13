package api

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func TestSQLiteIdempotencyStoreReplaysAcrossStoreInstances(t *testing.T) {
	db, err := sql.Open("sqlite", t.TempDir()+"/idempotency.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	firstStore := NewSQLiteIdempotencyStore(db, time.Hour)
	if err := firstStore.Init(context.Background()); err != nil {
		t.Fatalf("init first store: %v", err)
	}

	var calls atomic.Int32
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"decision_id":"dec-1"}`))
	})

	first := IdempotencyMiddleware(firstStore)(handler)
	firstRequest := httptest.NewRequest(http.MethodPost, "/api/v1/evaluate", bytes.NewReader([]byte(`{"action":"read"}`)))
	firstRequest.Header.Set("Idempotency-Key", "evaluate-1")
	firstRequest.Header.Set("X-Helm-Tenant-ID", "tenant-a")
	firstRequest.Header.Set("X-Helm-Principal-ID", "principal-a")
	firstRequest.Header.Set("X-Helm-Session-ID", "session-a")
	firstResponse := httptest.NewRecorder()
	first.ServeHTTP(firstResponse, firstRequest)
	if firstResponse.Code != http.StatusCreated || calls.Load() != 1 {
		t.Fatalf("first request = status %d calls %d body=%s", firstResponse.Code, calls.Load(), firstResponse.Body.String())
	}

	secondStore := NewSQLiteIdempotencyStore(db, time.Hour)
	if err := secondStore.Init(context.Background()); err != nil {
		t.Fatalf("init second store: %v", err)
	}
	second := IdempotencyMiddleware(secondStore)(handler)
	secondRequest := httptest.NewRequest(http.MethodPost, "/api/v1/evaluate", bytes.NewReader([]byte(`{"action":"read"}`)))
	secondRequest.Header.Set("Idempotency-Key", "evaluate-1")
	secondRequest.Header.Set("X-Helm-Tenant-ID", "tenant-a")
	secondRequest.Header.Set("X-Helm-Principal-ID", "principal-a")
	secondRequest.Header.Set("X-Helm-Session-ID", "session-a")
	secondResponse := httptest.NewRecorder()
	second.ServeHTTP(secondResponse, secondRequest)
	if secondResponse.Code != http.StatusCreated || calls.Load() != 1 {
		t.Fatalf("durable replay = status %d calls %d body=%s", secondResponse.Code, calls.Load(), secondResponse.Body.String())
	}
	if secondResponse.Header().Get("X-Helm-Idempotency-Replayed") != "true" {
		t.Fatalf("replay header = %q", secondResponse.Header().Get("X-Helm-Idempotency-Replayed"))
	}
}

func TestIdempotencyMiddlewareScopesRawKeyByAuthenticatedBinding(t *testing.T) {
	store := NewIdempotencyStore(time.Hour)
	var calls atomic.Int32
	handler := IdempotencyMiddleware(store)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusCreated)
	}))

	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/evaluate", bytes.NewReader([]byte(`{"action":"read"}`)))
		req.Header.Set("Idempotency-Key", "shared-client-key")
		req.Header.Set("X-Helm-Tenant-ID", tenant)
		req.Header.Set("X-Helm-Principal-ID", "principal")
		req.Header.Set("X-Helm-Session-ID", "session")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		if response.Code != http.StatusCreated {
			t.Fatalf("tenant %s status = %d", tenant, response.Code)
		}
	}
	if calls.Load() != 2 {
		t.Fatalf("scoped idempotency calls = %d, want 2", calls.Load())
	}
}

func TestIdempotencyMiddlewareFailsClosedWhenResponseCannotPersist(t *testing.T) {
	store := &failingIdempotencyStore{}
	handler := IdempotencyMiddleware(store)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"decision_id":"must-not-leak"}`))
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/evaluate", bytes.NewReader([]byte(`{"action":"read"}`)))
	req.Header.Set("Idempotency-Key", "persist-failure")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("persistence failure status = %d body=%s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "must-not-leak") {
		t.Fatalf("response leaked uncached governed result: %s", response.Body.String())
	}
}

type failingIdempotencyStore struct{}

func (*failingIdempotencyStore) Check(string) (*cachedResponse, bool) { return nil, false }

func (*failingIdempotencyStore) Set(string, string, int, http.Header, []byte) error {
	return errors.New("database unavailable")
}
