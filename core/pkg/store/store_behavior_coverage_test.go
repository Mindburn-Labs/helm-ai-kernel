package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"

	_ "github.com/lib/pq"
	_ "modernc.org/sqlite"
)

func TestAuditStoreNewIsEmpty(t *testing.T) {
	s := NewAuditStore()
	if s.Size() != 0 || s.GetSequence() != 0 || s.GetChainHead() != "genesis" {
		t.Fatal("new audit store should be empty with genesis head")
	}
}

func TestAuditStoreAppendMultipleTypes(t *testing.T) {
	s := NewAuditStore()
	types := []EntryType{EntryTypeViolation, EntryTypeEvidence, EntryTypeSecurityEvent}
	for _, et := range types {
		if _, err := s.Append(et, "subj", "act", nil, nil); err != nil {
			t.Fatalf("append %s: %v", et, err)
		}
	}
	if s.Size() != 3 {
		t.Fatalf("expected 3, got %d", s.Size())
	}
}

func TestAuditStoreGetByHashNotFound(t *testing.T) {
	s := NewAuditStore()
	_, err := s.GetByHash("sha256:nonexistent")
	if !errors.Is(err, ErrEntryNotFound) {
		t.Fatal("expected ErrEntryNotFound for missing hash")
	}
}

func TestAuditStorePayloadHashComputed(t *testing.T) {
	s := NewAuditStore()
	e, _ := s.Append(EntryTypeAudit, "s", "a", map[string]string{"k": "v"}, nil)
	if e.PayloadHash == "" || e.PayloadHash[:7] != "sha256:" {
		t.Fatalf("expected sha256 payload hash, got %q", e.PayloadHash)
	}
}

func TestAuditStoreMetadataPreserved(t *testing.T) {
	s := NewAuditStore()
	meta := map[string]string{"env": "test", "region": "us-east-1"}
	e, _ := s.Append(EntryTypeAudit, "s", "a", nil, meta)
	if e.Metadata["env"] != "test" || e.Metadata["region"] != "us-east-1" {
		t.Fatal("metadata not preserved")
	}
}

func TestAuditStoreQueryMaxResults(t *testing.T) {
	s := NewAuditStore()
	for i := 0; i < 10; i++ {
		s.Append(EntryTypeAudit, "s", "a", nil, nil)
	}
	results := s.Query(QueryFilter{MaxResults: 3})
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}
}

func TestAuditStoreVerifyChainEmpty(t *testing.T) {
	s := NewAuditStore()
	if err := s.VerifyChain(); err != nil {
		t.Fatalf("empty chain should verify: %v", err)
	}
}

func TestAuditStoreExportBundleNoMatch(t *testing.T) {
	s := NewAuditStore()
	s.Append(EntryTypeAudit, "s", "a", nil, nil)
	_, err := s.ExportBundle(QueryFilter{Subject: "no-match"})
	if err == nil {
		t.Fatal("expected error for empty bundle")
	}
}

func TestVerifyBundleEmpty(t *testing.T) {
	err := VerifyBundle(&AuditEvidenceBundle{Entries: []*AuditEntry{}})
	if err == nil {
		t.Fatal("expected error for empty bundle")
	}
}

func TestAuditStoreMultipleHandlers(t *testing.T) {
	s := NewAuditStore()
	count := 0
	s.AddHandler(func(_ *AuditEntry) { count++ })
	s.AddHandler(func(_ *AuditEntry) { count++ })
	s.Append(EntryTypeAudit, "s", "a", nil, nil)
	if count != 2 {
		t.Fatalf("expected 2 handler calls, got %d", count)
	}
}

// --- SQLite Receipt Store tests ---

func newTestSQLiteStore(t *testing.T) (*SQLiteReceiptStore, func()) {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewSQLiteReceiptStore(db)
	if err != nil {
		t.Fatal(err)
	}
	return store, func() { _ = db.Close() }
}

func TestSQLiteReceiptStoreAndGet(t *testing.T) {
	store, cleanup := newTestSQLiteStore(t)
	defer cleanup()
	r := &contracts.Receipt{ReceiptID: "r1", DecisionID: "d1", EffectID: "e1", Status: "OK", Timestamp: time.Now()}
	if err := store.Store(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	got, err := store.Get(context.Background(), "d1")
	if err != nil || got.ReceiptID != "r1" {
		t.Fatalf("expected r1, got err=%v, receipt=%+v", err, got)
	}
}

func TestSQLiteReceiptGetByReceiptID(t *testing.T) {
	store, cleanup := newTestSQLiteStore(t)
	defer cleanup()
	r := &contracts.Receipt{ReceiptID: "r2", DecisionID: "d2", EffectID: "e2", Status: "OK", Timestamp: time.Now()}
	store.Store(context.Background(), r)
	got, err := store.GetByReceiptID(context.Background(), "r2")
	if err != nil || got.DecisionID != "d2" {
		t.Fatal("GetByReceiptID failed")
	}
}

func TestSQLiteReceiptList(t *testing.T) {
	store, cleanup := newTestSQLiteStore(t)
	defer cleanup()
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		store.Store(ctx, &contracts.Receipt{
			ReceiptID: fmt.Sprintf("r%d", i), DecisionID: fmt.Sprintf("d%d", i),
			EffectID: "e", Status: "OK", Timestamp: time.Now(),
		})
	}
	list, err := store.List(ctx, 3)
	if err != nil || len(list) != 3 {
		t.Fatalf("expected 3 receipts, got %d, err=%v", len(list), err)
	}
}

func TestSQLiteReceiptRoundTripsChainFieldsAndAgentFilter(t *testing.T) {
	store, cleanup := newTestSQLiteStore(t)
	defer cleanup()
	ctx := context.Background()
	receipts := []*contracts.Receipt{
		{
			ReceiptID:    "r-agent-1",
			DecisionID:   "d-agent-1",
			EffectID:     "e",
			Status:       "OK",
			Timestamp:    time.Now().Add(-time.Second),
			ExecutorID:   "agent.demo.exec",
			SessionID:    "agent.demo.exec",
			PrevHash:     "prev-0",
			LamportClock: 1,
			ArgsHash:     "args-1",
			BlobHash:     "blob-1",
		},
		{
			ReceiptID:    "r-agent-2",
			DecisionID:   "d-agent-2",
			EffectID:     "e",
			Status:       "OK",
			Timestamp:    time.Now(),
			ExecutorID:   "agent.demo.exec",
			SessionID:    "agent.demo.exec",
			PrevHash:     "prev-1",
			LamportClock: 2,
			ArgsHash:     "args-2",
			BlobHash:     "blob-2",
		},
		{
			ReceiptID:    "r-other",
			DecisionID:   "d-other",
			EffectID:     "e",
			Status:       "OK",
			Timestamp:    time.Now(),
			ExecutorID:   "agent.other",
			SessionID:    "agent.other",
			LamportClock: 3,
		},
	}
	for _, receipt := range receipts {
		if err := store.Store(ctx, receipt); err != nil {
			t.Fatal(err)
		}
	}

	got, err := store.GetByReceiptID(ctx, "r-agent-2")
	if err != nil {
		t.Fatal(err)
	}
	if got.PrevHash != "prev-1" || got.LamportClock != 2 || got.ArgsHash != "args-2" || got.BlobHash != "blob-2" {
		t.Fatalf("chain fields did not round-trip: %+v", got)
	}

	filtered, err := store.ListByAgent(ctx, "agent.demo.exec", 1, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(filtered) != 1 || filtered[0].ReceiptID != "r-agent-2" {
		t.Fatalf("unexpected agent filter result: %+v", filtered)
	}

	allSince, err := store.ListSince(ctx, 1, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(allSince) != 2 || allSince[0].ReceiptID != "r-agent-2" || allSince[1].ReceiptID != "r-other" {
		t.Fatalf("unexpected cursor result: %+v", allSince)
	}
}

func TestSQLiteReceiptRejectsDuplicateExecutorLamport(t *testing.T) {
	store, cleanup := newTestSQLiteStore(t)
	defer cleanup()
	ctx := context.Background()
	first := &contracts.Receipt{
		ReceiptID:    "r-dup-1",
		DecisionID:   "d-dup-1",
		EffectID:     "e",
		Status:       "OK",
		Timestamp:    time.Now(),
		ExecutorID:   "agent.dup",
		SessionID:    "agent.dup",
		LamportClock: 9,
	}
	second := &contracts.Receipt{
		ReceiptID:    "r-dup-2",
		DecisionID:   "d-dup-2",
		EffectID:     "e",
		Status:       "OK",
		Timestamp:    time.Now().Add(time.Second),
		ExecutorID:   "agent.dup",
		SessionID:    "agent.dup",
		LamportClock: 9,
	}
	if err := store.Store(ctx, first); err != nil {
		t.Fatal(err)
	}
	if err := store.Store(ctx, second); err == nil {
		t.Fatal("expected duplicate executor/lamport receipt to fail")
	}
}

func TestSQLiteReceiptAppendCausalAssignsChainInsideStore(t *testing.T) {
	store, cleanup := newTestSQLiteStore(t)
	defer cleanup()
	ctx := context.Background()
	first := func(_ *contracts.Receipt, lamport uint64, prevHash string) (*contracts.Receipt, error) {
		return &contracts.Receipt{
			ReceiptID:    "r-causal-1",
			DecisionID:   "d-causal-1",
			EffectID:     "e",
			Status:       "OK",
			Timestamp:    time.Unix(1700000000, 0).UTC(),
			ExecutorID:   "agent.causal",
			SessionID:    "agent.causal",
			PrevHash:     prevHash,
			LamportClock: lamport,
			Signature:    "sig-1",
		}, nil
	}
	if err := store.AppendCausal(ctx, "agent.causal", first); err != nil {
		t.Fatal(err)
	}

	var seenPrevious *contracts.Receipt
	second := func(previous *contracts.Receipt, lamport uint64, prevHash string) (*contracts.Receipt, error) {
		seenPrevious = previous
		return &contracts.Receipt{
			ReceiptID:    "r-causal-2",
			DecisionID:   "d-causal-2",
			EffectID:     "e",
			Status:       "OK",
			Timestamp:    time.Unix(1700000001, 0).UTC(),
			ExecutorID:   "agent.causal",
			SessionID:    "agent.causal",
			PrevHash:     prevHash,
			LamportClock: lamport,
			Signature:    "sig-2",
		}, nil
	}
	if err := store.AppendCausal(ctx, "agent.causal", second); err != nil {
		t.Fatal(err)
	}
	if seenPrevious == nil || seenPrevious.ReceiptID != "r-causal-1" {
		t.Fatalf("builder did not receive previous receipt: %+v", seenPrevious)
	}
	got, err := store.GetByReceiptID(ctx, "r-causal-2")
	if err != nil {
		t.Fatal(err)
	}
	expectedPrevHash, err := contracts.ReceiptChainHash(seenPrevious)
	if err != nil {
		t.Fatal(err)
	}
	if got.LamportClock != 2 || got.PrevHash != expectedPrevHash {
		t.Fatalf("causal fields = lamport %d prev %q, want 2 %q", got.LamportClock, got.PrevHash, expectedPrevHash)
	}
}

func TestPostgresReceiptAppendCausalParallelOutperformsSQLite(t *testing.T) {
	postgresURL := os.Getenv("HELM_TEST_POSTGRES_URL")
	if postgresURL == "" {
		t.Skip("set HELM_TEST_POSTGRES_URL to run Postgres receipt throughput gate")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	const sessions = 64
	const appendsPerSession = 50

	sqliteDB, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "receipts.db"))
	if err != nil {
		t.Fatal(err)
	}
	sqliteStore, err := NewSQLiteReceiptStore(sqliteDB)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sqliteDB.Close() }()

	schema := fmt.Sprintf("helm_receipts_%d", time.Now().UnixNano())
	pgURL := postgresURLWithSearchPath(t, postgresURL, schema)
	postgresDB, err := sql.Open("postgres", pgURL)
	if err != nil {
		t.Fatal(err)
	}
	postgresDB.SetMaxOpenConns(sessions)
	postgresDB.SetMaxIdleConns(sessions)
	postgresDB.SetConnMaxLifetime(time.Minute)
	defer func() { _ = postgresDB.Close() }()
	if _, err := postgresDB.ExecContext(ctx, `CREATE SCHEMA IF NOT EXISTS `+schema); err != nil {
		t.Fatalf("create test schema: %v", err)
	}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		_, _ = postgresDB.ExecContext(cleanupCtx, `DROP SCHEMA IF EXISTS `+schema+` CASCADE`)
	}()
	postgresStore := NewPostgresReceiptStore(postgresDB)
	if err := postgresStore.Init(ctx); err != nil {
		t.Fatalf("init postgres store: %v", err)
	}

	sqliteDuration := runReceiptAppendCausalLoad(t, ctx, sqliteStore, "sqlite", sessions, appendsPerSession)
	postgresDuration := runReceiptAppendCausalLoad(t, ctx, postgresStore, "postgres", sessions, appendsPerSession)
	t.Logf("parallel causal append: sqlite=%s postgres=%s sessions=%d appends_per_session=%d", sqliteDuration, postgresDuration, sessions, appendsPerSession)
	if postgresDuration >= sqliteDuration {
		t.Fatalf("parallel Postgres receipt append did not outperform SQLite: postgres=%s sqlite=%s", postgresDuration, sqliteDuration)
	}
}

func postgresURLWithSearchPath(t *testing.T, rawURL, schema string) string {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" {
		t.Fatalf("HELM_TEST_POSTGRES_URL must be a URL-style Postgres DSN for schema isolation: %v", err)
	}
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func runReceiptAppendCausalLoad(t *testing.T, ctx context.Context, store ReceiptStore, prefix string, sessions, appendsPerSession int) time.Duration {
	t.Helper()
	start := time.Now()
	var wg sync.WaitGroup
	errCh := make(chan error, sessions)
	for sessionIndex := 0; sessionIndex < sessions; sessionIndex++ {
		sessionIndex := sessionIndex
		wg.Add(1)
		go func() {
			defer wg.Done()
			sessionID := fmt.Sprintf("%s-session-%02d", prefix, sessionIndex)
			for appendIndex := 0; appendIndex < appendsPerSession; appendIndex++ {
				appendIndex := appendIndex
				if err := store.AppendCausal(ctx, sessionID, func(_ *contracts.Receipt, lamport uint64, prevHash string) (*contracts.Receipt, error) {
					return &contracts.Receipt{
						ReceiptID:    fmt.Sprintf("%s-receipt-%02d-%03d", prefix, sessionIndex, appendIndex),
						DecisionID:   fmt.Sprintf("%s-decision-%02d-%03d", prefix, sessionIndex, appendIndex),
						EffectID:     "receipt-throughput",
						Status:       "OK",
						Timestamp:    time.Unix(1700000000+int64(appendIndex), 0).UTC(),
						ExecutorID:   sessionID,
						SessionID:    sessionID,
						PrevHash:     prevHash,
						LamportClock: lamport,
						Signature:    "sig",
					}, nil
				}); err != nil {
					errCh <- fmt.Errorf("%s append %d: %w", sessionID, appendIndex, err)
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatal(err)
		}
	}
	return time.Since(start)
}

func TestSQLiteReceiptRejectsUnmarshalableMetadata(t *testing.T) {
	store, cleanup := newTestSQLiteStore(t)
	defer cleanup()
	err := store.Store(context.Background(), &contracts.Receipt{
		ReceiptID:  "r-bad-meta",
		DecisionID: "d-bad-meta",
		EffectID:   "e",
		Status:     "OK",
		Timestamp:  time.Now(),
		Metadata:   map[string]any{"bad": func() {}},
	})
	if err == nil {
		t.Fatal("expected metadata marshal failure")
	}
}

func TestSQLiteReceiptNotFound(t *testing.T) {
	store, cleanup := newTestSQLiteStore(t)
	defer cleanup()
	_, err := store.GetByReceiptID(context.Background(), "missing")
	if err == nil {
		t.Fatal("expected error for missing receipt")
	}
}

func TestSQLiteReceiptGetLastForSessionGenesis(t *testing.T) {
	store, cleanup := newTestSQLiteStore(t)
	defer cleanup()
	got, err := store.GetLastForSession(context.Background(), "no-session")
	if err != nil || got != nil {
		t.Fatalf("expected nil genesis, got err=%v, receipt=%+v", err, got)
	}
}

// --- Airgap Store tests ---

func TestAirgapStorePutGet(t *testing.T) {
	dir := filepath.Join(os.TempDir(), fmt.Sprintf("airgap-test-%d", time.Now().UnixNano()))
	defer os.RemoveAll(dir)
	s, err := NewAirgapStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	s.Put(ctx, "k1", []byte("hello"))
	got, err := s.Get(ctx, "k1")
	if err != nil || string(got) != "hello" {
		t.Fatalf("expected hello, got %s, err=%v", got, err)
	}
}
