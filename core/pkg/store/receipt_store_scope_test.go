package store

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

func TestSQLiteReceiptAppendCausalScopedIsolatesSameExternalSession(t *testing.T) {
	receiptStore, cleanup := newTestSQLiteStore(t)
	defer cleanup()

	signer, err := helmcrypto.NewEd25519Signer("tenant-scoped-receipts")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	const externalSessionID = "caller-session"

	issue := func(tenantID, suffix string, timestamp time.Time) *contracts.Receipt {
		t.Helper()
		var issued *contracts.Receipt
		err := receiptStore.AppendCausalScoped(ctx, tenantID, externalSessionID, func(_ *contracts.Receipt, lamport uint64, prevHash string) (*contracts.Receipt, error) {
			receipt := &contracts.Receipt{
				ReceiptID:        "receipt-" + suffix,
				DecisionID:       "decision-" + suffix,
				EffectID:         "effect-" + suffix,
				Status:           "SUCCESS",
				Timestamp:        timestamp,
				OutputHash:       "output-" + suffix,
				ArgsHash:         "args-" + suffix,
				SignatureVersion: contracts.ReceiptSignatureV5,
				SessionID:        externalSessionID,
				PrevHash:         prevHash,
				LamportClock:     lamport,
				Verdict:          string(contracts.VerdictAllow),
			}
			if err := signer.SignReceipt(receipt); err != nil {
				return nil, err
			}
			issued = receipt
			return receipt, nil
		})
		if err != nil {
			t.Fatalf("append %s/%s: %v", tenantID, suffix, err)
		}
		return issued
	}

	base := time.Unix(1700000000, 123456789).UTC()
	firstA := issue("tenant-a", "a-1", base)
	firstB := issue("tenant-b", "b-1", base.Add(time.Second))
	secondA := issue("tenant-a", "a-2", base.Add(2*time.Second))
	secondB := issue("tenant-b", "b-2", base.Add(3*time.Second))

	if firstA.SessionID != externalSessionID || firstB.SessionID != externalSessionID {
		t.Fatalf("external session changed: a=%q b=%q", firstA.SessionID, firstB.SessionID)
	}
	if firstA.LamportClock != 1 || firstB.LamportClock != 1 || firstA.PrevHash != "" || firstB.PrevHash != "" {
		t.Fatalf("independent tenant genesis receipts are not roots: a=%+v b=%+v", firstA, firstB)
	}
	firstAHash, err := contracts.ReceiptChainHash(firstA)
	if err != nil {
		t.Fatal(err)
	}
	firstBHash, err := contracts.ReceiptChainHash(firstB)
	if err != nil {
		t.Fatal(err)
	}
	if secondA.LamportClock != 2 || secondA.PrevHash != firstAHash || secondB.LamportClock != 2 || secondB.PrevHash != firstBHash {
		t.Fatalf("tenant chains crossed or lost order: second_a=%+v second_b=%+v", secondA, secondB)
	}
	for _, receipt := range []*contracts.Receipt{firstA, firstB, secondA, secondB} {
		if valid, err := signer.VerifyReceipt(receipt); err != nil || !valid {
			t.Fatalf("scoped receipt signature invalid: valid=%v err=%v receipt=%+v", valid, err, receipt)
		}
	}

	for receiptID, wantKey := range map[string]string{
		firstA.ReceiptID: causalReceiptScopeKey("tenant-a", externalSessionID),
		firstB.ReceiptID: causalReceiptScopeKey("tenant-b", externalSessionID),
	} {
		var got string
		if err := receiptStore.db.QueryRowContext(ctx, `SELECT causal_session_id FROM receipts WHERE receipt_id = ?`, receiptID).Scan(&got); err != nil {
			t.Fatalf("read causal key for %s: %v", receiptID, err)
		}
		if got != wantKey || got == externalSessionID {
			t.Fatalf("causal key for %s = %q, want tenant-qualified %q", receiptID, got, wantKey)
		}
	}
}

func TestSQLiteListByTenantCursorRetainsTiedSessionLamports(t *testing.T) {
	receiptStore, cleanup := newTestSQLiteStore(t)
	defer cleanup()

	ctx := context.Background()
	timestamp := time.Date(2026, 5, 5, 0, 0, 0, 123456789, time.UTC)
	appendReceipt := func(sessionID, receiptID string) *contracts.Receipt {
		t.Helper()
		var issued *contracts.Receipt
		err := receiptStore.AppendCausalScoped(ctx, "tenant-a", sessionID, func(_ *contracts.Receipt, lamport uint64, prevHash string) (*contracts.Receipt, error) {
			issued = &contracts.Receipt{
				ReceiptID:        receiptID,
				DecisionID:       "decision-" + receiptID,
				EffectID:         "effect-" + receiptID,
				Status:           "SUCCESS",
				Timestamp:        timestamp,
				OutputHash:       "output-" + receiptID,
				ArgsHash:         "args-" + receiptID,
				SignatureVersion: contracts.ReceiptSignatureV5,
				SessionID:        sessionID,
				PrevHash:         prevHash,
				LamportClock:     lamport,
				Verdict:          string(contracts.VerdictAllow),
			}
			return issued, nil
		})
		if err != nil {
			t.Fatalf("append %s: %v", receiptID, err)
		}
		return issued
	}

	firstIssued := appendReceipt("session-a", "receipt-a")
	secondIssued := appendReceipt("session-b", "receipt-b")
	if firstIssued.LamportClock != 1 || secondIssued.LamportClock != 1 {
		t.Fatalf("independent tenant sessions must both start at Lamport 1: first=%d second=%d", firstIssued.LamportClock, secondIssued.LamportClock)
	}

	firstPage, err := receiptStore.ListByTenantCursor(ctx, "tenant-a", TenantReceiptCursor{}, 1)
	if err != nil || len(firstPage) != 1 {
		t.Fatalf("first tenant cursor page = %+v err=%v", firstPage, err)
	}
	cursor := TenantReceiptCursor{
		LamportClock: firstPage[0].LamportClock,
		Timestamp:    firstPage[0].Timestamp,
		ReceiptID:    firstPage[0].ReceiptID,
	}
	secondPage, err := receiptStore.ListByTenantCursor(ctx, "tenant-a", cursor, 1)
	if err != nil || len(secondPage) != 1 {
		t.Fatalf("second tenant cursor page = %+v err=%v", secondPage, err)
	}
	if firstPage[0].ReceiptID == secondPage[0].ReceiptID {
		t.Fatalf("tenant cursor repeated receipt %q", firstPage[0].ReceiptID)
	}
	got := map[string]bool{firstPage[0].ReceiptID: true, secondPage[0].ReceiptID: true}
	if len(got) != 2 || !got["receipt-a"] || !got["receipt-b"] {
		t.Fatalf("tenant cursor lost a tied-Lamport receipt: %+v", got)
	}
}

func TestPostgresReceiptAppendCausalScopedUsesTenantLookupKey(t *testing.T) {
	ctx := context.Background()
	db, mock, cleanup := newStoreCoverageSQLMock(t)
	defer cleanup()
	receiptStore := NewPostgresReceiptStore(db)
	const tenantID = "tenant-a"
	const externalSessionID = "caller-session"
	lookupKey := causalReceiptScopeKey(tenantID, externalSessionID)

	mock.ExpectBegin()
	mock.ExpectExec("SELECT pg_advisory_xact_lock").WithArgs(lookupKey).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("FROM receipts WHERE causal_session_id").WithArgs(lookupKey).WillReturnRows(sqlmock.NewRows(storePostgresReceiptColumns()))
	mock.ExpectExec("INSERT INTO receipts").WithArgs(storeAnySQLArgs(30)...).WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()
	var issued *contracts.Receipt
	if err := receiptStore.AppendCausalScoped(ctx, tenantID, externalSessionID, func(_ *contracts.Receipt, lamport uint64, prevHash string) (*contracts.Receipt, error) {
		issued = storeCoverageReceipt("scoped-postgres", "scoped-postgres-decision", externalSessionID, lamport, time.Unix(1700000000, 123456789).UTC())
		issued.PrevHash = prevHash
		return issued, nil
	}); err != nil {
		t.Fatalf("append scoped receipt: %v", err)
	}
	if issued.SessionID != externalSessionID || receiptStore.cachedLastReceipt(lookupKey) == nil || receiptStore.cachedLastReceipt(externalSessionID) != nil {
		t.Fatalf("Postgres scoped append did not separate lookup from signed session: receipt=%+v", issued)
	}
}

func TestPostgresListByTenantCursorUsesFullKeyset(t *testing.T) {
	ctx := context.Background()
	db, mock, cleanup := newStoreCoverageSQLMock(t)
	defer cleanup()
	receiptStore := NewPostgresReceiptStore(db)
	timestamp := time.Date(2026, 5, 5, 0, 0, 0, 123456789, time.UTC)
	prefix := causalReceiptTenantScopePrefix("tenant-a")
	receipt := storeCoverageReceipt("receipt-b", "decision-b", "session-b", 1, timestamp)

	mock.ExpectQuery(`lamport_clock > \$4[\s\S]*timestamp > \$5[\s\S]*receipt_id > \$6[\s\S]*ORDER BY lamport_clock ASC, timestamp ASC, receipt_id ASC`).
		WithArgs(contracts.ReceiptSignatureV5, len(prefix), prefix, uint64(1), timestamp.Truncate(time.Microsecond), "receipt-a", 1).
		WillReturnRows(storePostgresReceiptRows(receipt, nil))
	got, err := receiptStore.ListByTenantCursor(ctx, "tenant-a", TenantReceiptCursor{
		LamportClock: 1,
		Timestamp:    timestamp,
		ReceiptID:    "receipt-a",
	}, 1)
	if err != nil || len(got) != 1 || got[0].ReceiptID != "receipt-b" {
		t.Fatalf("Postgres tenant keyset page = %+v err=%v", got, err)
	}
}
