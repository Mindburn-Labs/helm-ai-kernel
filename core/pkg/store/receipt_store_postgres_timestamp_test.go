package store

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

func TestPostgresReceiptTimestampStaysStableAcrossCacheAndReload(t *testing.T) {
	ctx := context.Background()
	db, mock, cleanup := newStoreCoverageSQLMock(t)
	defer cleanup()
	receiptStore := NewPostgresReceiptStore(db)
	const sessionID = "postgres-session"
	timestamp := time.Date(2026, 8, 1, 12, 0, 0, 123456789, time.UTC)
	wantTimestamp := timestamp.Truncate(time.Microsecond)

	var first *contracts.Receipt
	mock.ExpectBegin()
	mock.ExpectExec("SELECT pg_advisory_xact_lock").WithArgs(sessionID).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("FROM receipts WHERE causal_session_id").WithArgs(sessionID).WillReturnRows(sqlmock.NewRows(storePostgresReceiptColumns()))
	mock.ExpectExec("INSERT INTO receipts").WithArgs(storeAnySQLArgs(30)...).WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()
	if err := receiptStore.AppendCausal(ctx, sessionID, func(_ *contracts.Receipt, lamport uint64, prevHash string) (*contracts.Receipt, error) {
		first = storeCoverageReceipt("postgres-first", "postgres-decision-first", sessionID, lamport, timestamp)
		first.PrevHash = prevHash
		return first, nil
	}); err != nil {
		t.Fatalf("append first receipt: %v", err)
	}
	if !first.Timestamp.Equal(wantTimestamp) {
		t.Fatalf("cached receipt timestamp = %s, want PostgreSQL precision %s", first.Timestamp, wantTimestamp)
	}
	firstHash, err := contracts.ReceiptChainHash(first)
	if err != nil {
		t.Fatal(err)
	}

	// Simulate a process restart: PostgreSQL returns the microsecond timestamp
	// that it persisted, not the original nanosecond value from the producer.
	reloaded := *first
	if reloadedHash, err := contracts.ReceiptChainHash(&reloaded); err != nil || reloadedHash != firstHash {
		t.Fatalf("reloaded predecessor hash = %q err=%v, want %q", reloadedHash, err, firstHash)
	}
	metadata, err := json.Marshal(first.Metadata)
	if err != nil {
		t.Fatal(err)
	}
	receiptStore.lastBySession = map[string]*contracts.Receipt{}

	mock.ExpectBegin()
	mock.ExpectExec("SELECT pg_advisory_xact_lock").WithArgs(sessionID).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("FROM receipts WHERE causal_session_id").WithArgs(sessionID).WillReturnRows(storePostgresReceiptRows(&reloaded, metadata))
	mock.ExpectExec("INSERT INTO receipts").WithArgs(storeAnySQLArgs(30)...).WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()
	if err := receiptStore.AppendCausal(ctx, sessionID, func(previous *contracts.Receipt, lamport uint64, prevHash string) (*contracts.Receipt, error) {
		if previous == nil || !previous.Timestamp.Equal(wantTimestamp) || lamport != 2 || prevHash != firstHash {
			t.Fatalf("reloaded causal predecessor changed: previous=%+v lamport=%d prev_hash=%q", previous, lamport, prevHash)
		}
		second := storeCoverageReceipt("postgres-second", "postgres-decision-second", sessionID, lamport, timestamp.Add(time.Second))
		second.PrevHash = prevHash
		return second, nil
	}); err != nil {
		t.Fatalf("append reloaded successor: %v", err)
	}
}
