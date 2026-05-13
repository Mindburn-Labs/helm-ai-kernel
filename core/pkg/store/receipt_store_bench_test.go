package store

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"

	_ "modernc.org/sqlite"
)

func benchSQLiteStore(tb testing.TB) (*SQLiteReceiptStore, func()) {
	tb.Helper()
	db, err := sql.Open("sqlite", filepath.Join(tb.TempDir(), "bench-receipts.db"))
	if err != nil {
		tb.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	// WAL mode for concurrent benchmark realism
	_, _ = db.Exec("PRAGMA busy_timeout=5000")
	_, _ = db.Exec("PRAGMA journal_mode=WAL")
	_, _ = db.Exec("PRAGMA synchronous=NORMAL")

	store, err := NewSQLiteReceiptStore(db)
	if err != nil {
		tb.Fatal(err)
	}
	return store, func() { _ = db.Close() }
}

func benchReceipt(i int) *contracts.Receipt {
	return &contracts.Receipt{
		ReceiptID:    fmt.Sprintf("rcpt-bench-%d", i),
		DecisionID:   fmt.Sprintf("dec-bench-%d", i),
		EffectID:     fmt.Sprintf("eff-bench-%d", i),
		Status:       "EXECUTED",
		BlobHash:     "sha256:input-hash",
		OutputHash:   "sha256:output-hash",
		Timestamp:    time.Now(),
		ExecutorID:   "bench-session",
		Signature:    "sig-fixture",
		PrevHash:     "sha256:prev",
		LamportClock: uint64(i),
	}
}

// BenchmarkSQLiteReceiptStore_Append measures the cost of receipt persistence.
// This is the I/O-bound component of the HELM hot path.
func BenchmarkSQLiteReceiptStore_Append(b *testing.B) {
	store, cleanup := benchSQLiteStore(b)
	defer cleanup()
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		r := benchReceipt(i)
		if err := store.Store(ctx, r); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSQLiteReceiptStore_AppendParallel measures concurrent receipt persistence.
func BenchmarkSQLiteReceiptStore_AppendParallel(b *testing.B) {
	store, cleanup := benchSQLiteStore(b)
	defer cleanup()
	var seq atomic.Uint64

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		ctx := context.Background()
		for pb.Next() {
			i := seq.Add(1)
			r := benchReceipt(int(i))
			r.ReceiptID = fmt.Sprintf("rcpt-par-%d", i)
			r.DecisionID = fmt.Sprintf("dec-par-%d", i)
			if err := store.Store(ctx, r); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkSQLiteReceiptStore_GetByID measures receipt retrieval by ID.
func BenchmarkSQLiteReceiptStore_GetByID(b *testing.B) {
	store, cleanup := benchSQLiteStore(b)
	defer cleanup()
	ctx := context.Background()

	// Pre-populate
	for i := 0; i < 1000; i++ {
		_ = store.Store(ctx, benchReceipt(i))
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		id := fmt.Sprintf("rcpt-bench-%d", i%1000)
		_, _ = store.GetByReceiptID(ctx, id)
	}
}
