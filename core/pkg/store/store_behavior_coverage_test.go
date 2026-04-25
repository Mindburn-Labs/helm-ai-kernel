package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"

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
			ExecutorID:   "agent.titan.exec",
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
			ExecutorID:   "agent.titan.exec",
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

	filtered, err := store.ListByAgent(ctx, "agent.titan.exec", 1, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(filtered) != 1 || filtered[0].ReceiptID != "r-agent-2" {
		t.Fatalf("unexpected agent filter result: %+v", filtered)
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
