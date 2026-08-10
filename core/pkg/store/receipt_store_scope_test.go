package store

import (
	"context"
	"database/sql"
	"strings"
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
				DecisionHash:     "decision-hash-" + suffix,
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
	if err := receiptStore.PreflightCausalAppendScoped(ctx, "tenant-a", externalSessionID); err != nil {
		t.Fatalf("preflight tenant-a: %v", err)
	}
	if err := receiptStore.PreflightCausalAppendScoped(ctx, "tenant-b", externalSessionID); err != nil {
		t.Fatalf("preflight tenant-b: %v", err)
	}
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

func TestSQLiteTenantCursorContinuesWithLateSessionGenesis(t *testing.T) {
	receiptStore, cleanup := newTestSQLiteStore(t)
	defer cleanup()

	ctx := context.Background()
	timestamp := time.Date(2026, 5, 5, 0, 0, 0, 123456789, time.UTC)
	appendReceipt := func(sessionID, receiptID string, issuedAt time.Time) *contracts.Receipt {
		t.Helper()
		var issued *contracts.Receipt
		err := receiptStore.AppendCausalScoped(ctx, "tenant-a", sessionID, func(_ *contracts.Receipt, lamport uint64, prevHash string) (*contracts.Receipt, error) {
			issued = &contracts.Receipt{
				ReceiptID:        receiptID,
				DecisionID:       "decision-" + receiptID,
				EffectID:         "effect-" + receiptID,
				Status:           "SUCCESS",
				Timestamp:        issuedAt,
				OutputHash:       "output-" + receiptID,
				DecisionHash:     "decision-hash-" + receiptID,
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

	firstIssued := appendReceipt("session-a", "receipt-a", timestamp)
	secondIssued := appendReceipt("session-a", "receipt-b", timestamp.Add(time.Second))
	if firstIssued.LamportClock != 1 || secondIssued.LamportClock != 2 {
		t.Fatalf("first session Lamports = %d, %d; want 1, 2", firstIssued.LamportClock, secondIssued.LamportClock)
	}

	firstPage, err := receiptStore.ListByTenantCursor(ctx, "tenant-a", TenantReceiptCursor{}, 2)
	if err != nil || len(firstPage) != 2 {
		t.Fatalf("first tenant cursor page = %+v err=%v", firstPage, err)
	}
	if firstPage[0].ReceiptID != firstIssued.ReceiptID || firstPage[1].ReceiptID != secondIssued.ReceiptID {
		t.Fatalf("first tenant cursor page = %+v, want append order %q then %q", firstPage, firstIssued.ReceiptID, secondIssued.ReceiptID)
	}
	cursor := TenantReceiptCursor{
		LamportClock: secondIssued.LamportClock,
		Timestamp:    secondIssued.Timestamp,
		ReceiptID:    secondIssued.ReceiptID,
	}

	// This is a new signed session root after the cursor. Its older timestamp
	// and reset Lamport clock must not put it behind the cursor for either a
	// paginated list or the tail loop, which both call ListByTenantCursor.
	lateGenesis := appendReceipt("session-b", "receipt-c", timestamp.Add(-time.Hour))
	if lateGenesis.LamportClock != 1 {
		t.Fatalf("late session genesis Lamport = %d, want 1", lateGenesis.LamportClock)
	}
	continued, err := receiptStore.ListByTenantCursor(ctx, "tenant-a", cursor, 1)
	if err != nil || len(continued) != 1 || continued[0].ReceiptID != lateGenesis.ReceiptID {
		t.Fatalf("tenant cursor omitted late session genesis: receipts=%+v err=%v", continued, err)
	}
}

func TestSQLiteTenantCursorRejectsStaleOrCrossTenantReceipt(t *testing.T) {
	receiptStore, cleanup := newTestSQLiteStore(t)
	defer cleanup()

	ctx := context.Background()
	issuedAt := time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC)
	issue := func(tenantID, receiptID string) *contracts.Receipt {
		t.Helper()
		var issued *contracts.Receipt
		err := receiptStore.AppendCausalScoped(ctx, tenantID, "cursor-session", func(_ *contracts.Receipt, lamport uint64, prevHash string) (*contracts.Receipt, error) {
			issued = &contracts.Receipt{
				ReceiptID:        receiptID,
				DecisionID:       "decision-" + receiptID,
				EffectID:         "effect-" + receiptID,
				Status:           "SUCCESS",
				Timestamp:        issuedAt,
				OutputHash:       "output-" + receiptID,
				DecisionHash:     "decision-hash-" + receiptID,
				ArgsHash:         "args-" + receiptID,
				SignatureVersion: contracts.ReceiptSignatureV5,
				SessionID:        "cursor-session",
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
	foreign := issue("tenant-b", "receipt-tenant-b")
	for _, cursorID := range []string{"receipt-deleted-or-stale", foreign.ReceiptID} {
		_, err := receiptStore.ListByTenantCursor(ctx, "tenant-a", TenantReceiptCursor{ReceiptID: cursorID, Timestamp: issuedAt}, 10)
		if err == nil || !strings.Contains(err.Error(), "invalid for authenticated tenant") {
			t.Fatalf("cursor %q error = %v, want authenticated-scope validation", cursorID, err)
		}
	}
}

func TestSQLiteTenantPrefixQueriesSupportUnicodeTenantID(t *testing.T) {
	receiptStore, cleanup := newTestSQLiteStore(t)
	defer cleanup()

	ctx := context.Background()
	const tenantID = "организация-猫"
	const sessionID = "unicode-session"
	issuedAt := time.Date(2026, 5, 5, 0, 0, 0, 0, time.UTC)
	var issued *contracts.Receipt
	if err := receiptStore.AppendCausalScoped(ctx, tenantID, sessionID, func(_ *contracts.Receipt, lamport uint64, prevHash string) (*contracts.Receipt, error) {
		issued = &contracts.Receipt{
			ReceiptID:        "receipt-unicode",
			DecisionID:       "decision-unicode",
			EffectID:         "effect-unicode",
			Status:           "SUCCESS",
			Timestamp:        issuedAt,
			OutputHash:       "output-unicode",
			DecisionHash:     "decision-hash-unicode",
			ArgsHash:         "args-unicode",
			SignatureVersion: contracts.ReceiptSignatureV5,
			SessionID:        sessionID,
			PrevHash:         prevHash,
			LamportClock:     lamport,
			Verdict:          string(contracts.VerdictAllow),
		}
		return issued, nil
	}); err != nil {
		t.Fatalf("append unicode tenant receipt: %v", err)
	}

	got, err := receiptStore.GetByReceiptIDForTenant(ctx, tenantID, issued.ReceiptID)
	if err != nil || got == nil || got.ReceiptID != issued.ReceiptID {
		t.Fatalf("get unicode tenant receipt = %+v err=%v", got, err)
	}
	miss, err := receiptStore.GetByDecisionIDForTenant(ctx, "other-tenant", issued.DecisionID)
	if err != nil || miss != nil {
		t.Fatalf("cross-tenant idempotency miss = %+v err=%v, want nil receipt and nil error", miss, err)
	}
	listed, err := receiptStore.ListByTenant(ctx, tenantID, 0, 10)
	if err != nil || len(listed) != 1 || listed[0].ReceiptID != issued.ReceiptID {
		t.Fatalf("list unicode tenant receipts = %+v err=%v", listed, err)
	}
	cursorListed, err := receiptStore.ListByTenantCursor(ctx, tenantID, TenantReceiptCursor{}, 10)
	if err != nil || len(cursorListed) != 1 || cursorListed[0].ReceiptID != issued.ReceiptID {
		t.Fatalf("list unicode tenant cursor receipts = %+v err=%v", cursorListed, err)
	}
}

func TestSQLiteReceiptMigrationBackfillsAppendSequence(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	// This is the subset of the prior schema used by the migration and its
	// indexes. It intentionally has no append_sequence column.
	if _, err := db.Exec(`CREATE TABLE receipts (
		receipt_id TEXT PRIMARY KEY,
		decision_id TEXT,
		executor_id TEXT,
		timestamp DATETIME,
		metadata JSON,
		signature_version TEXT DEFAULT '',
		decision_hash TEXT DEFAULT '',
		causal_session_id TEXT DEFAULT '',
		session_id TEXT DEFAULT '',
		lamport_clock INTEGER DEFAULT 0
	)`); err != nil {
		t.Fatalf("create legacy receipts: %v", err)
	}
	for _, receiptID := range []string{"receipt-old-a", "receipt-old-b"} {
		if _, err := db.Exec(`INSERT INTO receipts (receipt_id, decision_id, executor_id, timestamp) VALUES (?, ?, ?, ?)`, receiptID, "decision-"+receiptID, "executor", time.Now().UTC()); err != nil {
			t.Fatalf("insert legacy receipt %s: %v", receiptID, err)
		}
	}

	if _, err := NewSQLiteReceiptStore(db); err != nil {
		t.Fatalf("migrate legacy sqlite receipt store: %v", err)
	}
	for sequence, receiptID := range []string{"receipt-old-a", "receipt-old-b"} {
		var got int64
		if err := db.QueryRow(`SELECT append_sequence FROM receipts WHERE receipt_id = ?`, receiptID).Scan(&got); err != nil {
			t.Fatalf("read append sequence for %s: %v", receiptID, err)
		}
		if want := int64(sequence + 1); got != want {
			t.Fatalf("append sequence for %s = %d, want %d", receiptID, got, want)
		}
	}
	if _, err := db.Exec(`INSERT INTO receipts (receipt_id, decision_id, executor_id, timestamp) VALUES (?, ?, ?, ?)`, "receipt-new", "decision-new", "executor", time.Now().UTC()); err != nil {
		t.Fatalf("insert post-migration receipt: %v", err)
	}
	var newSequence int64
	if err := db.QueryRow(`SELECT append_sequence FROM receipts WHERE receipt_id = ?`, "receipt-new").Scan(&newSequence); err != nil {
		t.Fatalf("read post-migration append sequence: %v", err)
	}
	if newSequence != 3 {
		t.Fatalf("post-migration append sequence = %d, want 3", newSequence)
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
	mock.ExpectQuery("FROM receipts WHERE causal_session_id").WithArgs(lookupKey).WillReturnRows(sqlmock.NewRows(storePostgresReceiptColumnsWithChainHash()))
	mock.ExpectRollback()
	if err := receiptStore.PreflightCausalAppendScoped(ctx, tenantID, externalSessionID); err != nil {
		t.Fatalf("preflight scoped receipt: %v", err)
	}

	mock.ExpectBegin()
	mock.ExpectExec("SELECT pg_advisory_xact_lock").WithArgs(lookupKey).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("FROM receipts WHERE causal_session_id").WithArgs(lookupKey).WillReturnRows(sqlmock.NewRows(storePostgresReceiptColumnsWithChainHash()))
	mock.ExpectExec("INSERT INTO receipts").WithArgs(storeAnySQLArgs(storePostgresReceiptInsertArgCount)...).WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()
	var issued *contracts.Receipt
	if err := receiptStore.AppendCausalScoped(ctx, tenantID, externalSessionID, func(_ *contracts.Receipt, lamport uint64, prevHash string) (*contracts.Receipt, error) {
		issued = storeCoverageReceipt("scoped-postgres", "scoped-postgres-decision", externalSessionID, lamport, time.Unix(1700000000, 123456789).UTC())
		issued.PrevHash = prevHash
		return issued, nil
	}); err != nil {
		t.Fatalf("append scoped receipt: %v", err)
	}
	if issued.SessionID != externalSessionID {
		t.Fatalf("Postgres scoped append did not preserve the signed session: receipt=%+v", issued)
	}
}

func TestPostgresGetByDecisionIDForTenantMissIsNil(t *testing.T) {
	ctx := context.Background()
	db, mock, cleanup := newStoreCoverageSQLMock(t)
	defer cleanup()
	receiptStore := NewPostgresReceiptStore(db)
	const tenantID = "tenant-a"
	prefix := causalReceiptTenantScopePrefix(tenantID)

	mock.ExpectQuery(`FROM receipts[\s\S]*decision_id = \$1[\s\S]*left\(causal_session_id, char_length\(\$3\)\) = \$3`).
		WithArgs("missing-decision", contracts.ReceiptSignatureV5, prefix).
		WillReturnRows(sqlmock.NewRows(storePostgresReceiptColumns()))
	got, err := receiptStore.GetByDecisionIDForTenant(ctx, tenantID, "missing-decision")
	if err != nil || got != nil {
		t.Fatalf("tenant idempotency miss = %+v err=%v, want nil receipt and nil error", got, err)
	}
}

func TestPostgresReceiptAppendCausalScopedReloadsDurablePredecessorAcrossStoreInstances(t *testing.T) {
	ctx := context.Background()
	db, mock, cleanup := newStoreCoverageSQLMock(t)
	defer cleanup()
	firstStore := NewPostgresReceiptStore(db)
	secondStore := NewPostgresReceiptStore(db)
	const tenantID = "tenant-a"
	const externalSessionID = "shared-session"
	lookupKey := causalReceiptScopeKey(tenantID, externalSessionID)
	timestamp := time.Unix(1700000000, 123456789).UTC()
	seed := storeCoverageReceipt("durable-seed", "durable-seed-decision", externalSessionID, 1, timestamp)

	mock.ExpectBegin()
	mock.ExpectExec("SELECT pg_advisory_xact_lock").WithArgs(lookupKey).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("FROM receipts WHERE causal_session_id").WithArgs(lookupKey).WillReturnRows(storePostgresReceiptRowsWithChainHash(t, seed, nil, ""))
	mock.ExpectExec("INSERT INTO receipts").WithArgs(storeAnySQLArgs(storePostgresReceiptInsertArgCount)...).WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()
	var first *contracts.Receipt
	if err := firstStore.AppendCausalScoped(ctx, tenantID, externalSessionID, func(previous *contracts.Receipt, lamport uint64, prevHash string) (*contracts.Receipt, error) {
		if previous == nil || previous.ReceiptID != seed.ReceiptID || lamport != 2 || prevHash == "" {
			t.Fatalf("first store did not allocate from durable predecessor: previous=%+v lamport=%d prev_hash=%q", previous, lamport, prevHash)
		}
		first = storeCoverageReceipt("durable-first", "durable-first-decision", externalSessionID, lamport, timestamp.Add(time.Second))
		first.PrevHash = prevHash
		return first, nil
	}); err != nil {
		t.Fatalf("first store append: %v", err)
	}

	mock.ExpectBegin()
	mock.ExpectExec("SELECT pg_advisory_xact_lock").WithArgs(lookupKey).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("FROM receipts WHERE causal_session_id").WithArgs(lookupKey).WillReturnRows(storePostgresReceiptRowsWithChainHash(t, first, nil, ""))
	mock.ExpectExec("INSERT INTO receipts").WithArgs(storeAnySQLArgs(storePostgresReceiptInsertArgCount)...).WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()
	if err := secondStore.AppendCausalScoped(ctx, tenantID, externalSessionID, func(previous *contracts.Receipt, lamport uint64, prevHash string) (*contracts.Receipt, error) {
		if previous == nil || previous.ReceiptID != first.ReceiptID || lamport != 3 || prevHash == "" {
			t.Fatalf("second store did not reload first store's durable predecessor: previous=%+v lamport=%d prev_hash=%q", previous, lamport, prevHash)
		}
		next := storeCoverageReceipt("durable-second", "durable-second-decision", externalSessionID, lamport, timestamp.Add(2*time.Second))
		next.PrevHash = prevHash
		return next, nil
	}); err != nil {
		t.Fatalf("second store append: %v", err)
	}
}

func TestPostgresListLatestByTenantUsesLatestFirstOrder(t *testing.T) {
	ctx := context.Background()
	db, mock, cleanup := newStoreCoverageSQLMock(t)
	defer cleanup()
	receiptStore := NewPostgresReceiptStore(db)
	const tenantID = "tenant-a"
	prefix := causalReceiptTenantScopePrefix(tenantID)
	receipt := storeCoverageReceipt("receipt-latest", "decision-latest", "session-latest", 1, time.Date(2026, 5, 5, 0, 0, 2, 0, time.UTC))

	mock.ExpectQuery(`left\(causal_session_id, char_length\(\$2\)\) = \$2[\s\S]*ORDER BY timestamp DESC, append_sequence DESC LIMIT \$3`).
		WithArgs(contracts.ReceiptSignatureV5, prefix, 2).
		WillReturnRows(storePostgresReceiptRows(receipt, nil))
	got, err := receiptStore.ListLatestByTenant(ctx, tenantID, 2)
	if err != nil || len(got) != 1 || got[0].ReceiptID != receipt.ReceiptID {
		t.Fatalf("Postgres latest tenant receipts = %+v err=%v", got, err)
	}
}

func TestPostgresListByTenantCursorUsesAppendSequence(t *testing.T) {
	ctx := context.Background()
	db, mock, cleanup := newStoreCoverageSQLMock(t)
	defer cleanup()
	receiptStore := NewPostgresReceiptStore(db)
	timestamp := time.Date(2026, 5, 5, 0, 0, 0, 123456789, time.UTC)
	const tenantID = "организация-猫"
	prefix := causalReceiptTenantScopePrefix(tenantID)
	receipt := storeCoverageReceipt("receipt-b", "decision-b", "session-b", 1, timestamp)

	mock.ExpectQuery(`SELECT append_sequence FROM receipts[\s\S]*receipt_id = \$1[\s\S]*left\(causal_session_id, char_length\(\$3\)\) = \$3`).
		WithArgs("receipt-a", contracts.ReceiptSignatureV5, prefix).
		WillReturnRows(sqlmock.NewRows([]string{"append_sequence"}).AddRow(17))
	mock.ExpectQuery(`left\(causal_session_id, char_length\(\$2\)\) = \$2[\s\S]*append_sequence > \$3[\s\S]*ORDER BY append_sequence ASC LIMIT \$4`).
		WithArgs(contracts.ReceiptSignatureV5, prefix, int64(17), 1).
		WillReturnRows(storePostgresReceiptRows(receipt, nil))
	got, err := receiptStore.ListByTenantCursor(ctx, tenantID, TenantReceiptCursor{
		LamportClock: 1,
		Timestamp:    timestamp,
		ReceiptID:    "receipt-a",
	}, 1)
	if err != nil || len(got) != 1 || got[0].ReceiptID != "receipt-b" {
		t.Fatalf("Postgres tenant keyset page = %+v err=%v", got, err)
	}
}

func TestPostgresListByTenantCursorRejectsUnresolvableReceipt(t *testing.T) {
	ctx := context.Background()
	db, mock, cleanup := newStoreCoverageSQLMock(t)
	defer cleanup()
	receiptStore := NewPostgresReceiptStore(db)
	const tenantID = "tenant-a"
	prefix := causalReceiptTenantScopePrefix(tenantID)

	mock.ExpectQuery(`SELECT append_sequence FROM receipts[\s\S]*receipt_id = \$1[\s\S]*left\(causal_session_id, char_length\(\$3\)\) = \$3`).
		WithArgs("foreign-or-deleted-receipt", contracts.ReceiptSignatureV5, prefix).
		WillReturnRows(sqlmock.NewRows([]string{"append_sequence"}))
	_, err := receiptStore.ListByTenantCursor(ctx, tenantID, TenantReceiptCursor{
		Timestamp: time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC),
		ReceiptID: "foreign-or-deleted-receipt",
	}, 1)
	if err == nil || !strings.Contains(err.Error(), "invalid for authenticated tenant") {
		t.Fatalf("unresolvable tenant cursor error = %v", err)
	}
}
