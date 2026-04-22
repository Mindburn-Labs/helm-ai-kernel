package store

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"

	_ "modernc.org/sqlite"
)

func benchSQLiteStore(tb testing.TB) (*SQLiteReceiptStore, func()) {
	tb.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		tb.Fatal(err)
	}
	// WAL mode for concurrent benchmark realism
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
		Signature:    "sig-placeholder",
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

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		ctx := context.Background()
		i := 0
		for pb.Next() {
			r := benchReceipt(b.N + i)
			r.ReceiptID = fmt.Sprintf("rcpt-par-%d-%d", time.Now().UnixNano(), i)
			if err := store.Store(ctx, r); err != nil {
				b.Fatal(err)
			}
			i++
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
