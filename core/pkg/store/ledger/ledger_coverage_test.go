package ledger

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestFileLedgerCoverage(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1000, 0)
	ledger, err := NewFileLedgerWithClock(filepath.Join(t.TempDir(), "ledger.json"), func() time.Time { return now })
	if err != nil {
		t.Fatalf("NewFileLedgerWithClock: %v", err)
	}

	obl := Obligation{ID: "obl-1", IdempotencyKey: "key-1", Intent: "intent"}
	if err := ledger.Create(ctx, obl); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := ledger.Create(ctx, obl); err == nil || !strings.Contains(err.Error(), "obligation exists") {
		t.Fatalf("expected duplicate error, got %v", err)
	}

	got, err := ledger.Get(ctx, obl.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.State != StatePending || !got.CreatedAt.Equal(now) || !got.UpdatedAt.Equal(now) {
		t.Fatalf("unexpected created obligation: %#v", got)
	}
	if _, err := ledger.Get(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected not found, got %v", err)
	}

	leased, err := ledger.AcquireLease(ctx, obl.ID, "worker-1", time.Minute)
	if err != nil {
		t.Fatalf("AcquireLease: %v", err)
	}
	if leased.LeasedBy != "worker-1" || !leased.LeasedUntil.Equal(now.Add(time.Minute)) {
		t.Fatalf("unexpected lease: %#v", leased)
	}
	if _, err := ledger.AcquireLease(ctx, obl.ID, "worker-2", time.Minute); err == nil || !strings.Contains(err.Error(), "locked by another worker") {
		t.Fatalf("expected lock error, got %v", err)
	}
	if _, err := ledger.AcquireLease(ctx, "missing", "worker-1", time.Minute); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected acquire missing, got %v", err)
	}

	pending, err := ledger.ListPending(ctx)
	if err != nil {
		t.Fatalf("ListPending: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("expected one pending obligation, got %#v", pending)
	}

	if err := ledger.UpdateState(ctx, obl.ID, StateCompleted, nil); err != nil {
		t.Fatalf("UpdateState: %v", err)
	}
	if err := ledger.UpdateState(ctx, "missing", StateFailed, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected update missing, got %v", err)
	}

	pending, err = ledger.ListPending(ctx)
	if err != nil {
		t.Fatalf("ListPending: %v", err)
	}
	if len(pending) != 0 {
		t.Fatalf("expected no pending obligations, got %#v", pending)
	}
	all, err := ledger.ListAll(ctx)
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("expected one obligation, got %#v", all)
	}

	reloaded, err := NewFileLedger(ledger.path)
	if err != nil {
		t.Fatalf("NewFileLedger: %v", err)
	}
	if _, err := reloaded.Get(ctx, obl.ID); err != nil {
		t.Fatalf("reloaded Get: %v", err)
	}
}

func TestFileLedgerLoadAndSaveErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := NewFileLedger(dir); err == nil {
		t.Fatal("expected read directory error")
	}

	badJSON := filepath.Join(t.TempDir(), "ledger.json")
	if err := os.WriteFile(badJSON, []byte("{"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := NewFileLedger(badJSON); err == nil {
		t.Fatal("expected unmarshal error")
	}

	failing := &FileLedger{
		path:  t.TempDir(),
		data:  map[string]Obligation{},
		clock: time.Now,
	}
	if err := failing.Create(context.Background(), Obligation{ID: "fails"}); err == nil {
		t.Fatal("expected save error")
	}

	restore := replaceFileLedgerHooks()
	defer restore()

	fileLedgerMarshalIndent = func(any, string, string) ([]byte, error) {
		return nil, errors.New("marshal failed")
	}
	if err := (&FileLedger{data: map[string]Obligation{}}).save(); err == nil {
		t.Fatal("expected marshal error")
	}
	restore()

	fileLedgerWriteFile = func(string, []byte, os.FileMode) error {
		return errors.New("write failed")
	}
	saveFailingLease := &FileLedger{
		path: filepath.Join(t.TempDir(), "ledger.json"),
		data: map[string]Obligation{
			"lease": {ID: "lease", State: StatePending},
		},
		clock: time.Now,
	}
	if _, err := saveFailingLease.AcquireLease(context.Background(), "lease", "worker", time.Minute); err == nil {
		t.Fatal("expected acquire lease save error")
	}
}

func replaceFileLedgerHooks() func() {
	originalMarshalIndent := fileLedgerMarshalIndent
	originalWriteFile := fileLedgerWriteFile
	return func() {
		fileLedgerMarshalIndent = originalMarshalIndent
		fileLedgerWriteFile = originalWriteFile
	}
}

func TestSQLLedgerCoverage(t *testing.T) {
	ctx := context.Background()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	ledger := NewSQLLedger(db)
	now := time.Unix(100, 0)
	obl := Obligation{ID: "sql-1", IdempotencyKey: "key", Intent: "intent", State: StatePending, CreatedAt: now, UpdatedAt: now}

	mock.ExpectExec("CREATE TABLE IF NOT EXISTS obligations").WillReturnResult(sqlmock.NewResult(0, 0))
	if err := ledger.Init(ctx); err != nil {
		t.Fatalf("Init: %v", err)
	}
	mock.ExpectExec("CREATE TABLE IF NOT EXISTS obligations").WillReturnError(errors.New("init failed"))
	if err := ledger.Init(ctx); err == nil {
		t.Fatal("expected init error")
	}

	mock.ExpectExec("INSERT INTO obligations").WillReturnResult(sqlmock.NewResult(1, 1))
	if err := ledger.Create(ctx, obl); err != nil {
		t.Fatalf("Create: %v", err)
	}
	mock.ExpectExec("INSERT INTO obligations").WillReturnError(errors.New("create failed"))
	if err := ledger.Create(ctx, obl); err == nil {
		t.Fatal("expected create error")
	}

	mock.ExpectQuery("SELECT id, idempotency_key, intent, state, created_at, updated_at FROM obligations").
		WithArgs(obl.ID).
		WillReturnRows(sqlRows().AddRow(obl.ID, obl.IdempotencyKey, obl.Intent, obl.State, now, now))
	got, err := ledger.Get(ctx, obl.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ID != obl.ID {
		t.Fatalf("unexpected obligation: %#v", got)
	}

	mock.ExpectQuery("SELECT id, idempotency_key, intent, state, created_at, updated_at FROM obligations").
		WithArgs("missing").
		WillReturnError(sql.ErrNoRows)
	if _, err := ledger.Get(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected not found, got %v", err)
	}

	mock.ExpectQuery("SELECT id, idempotency_key, intent, state, created_at, updated_at FROM obligations").
		WithArgs("bad-scan").
		WillReturnRows(sqlRows().AddRow("bad-scan", "key", "intent", StatePending, "bad-time", now))
	if _, err := ledger.Get(ctx, "bad-scan"); err == nil {
		t.Fatal("expected scan error")
	}

	mock.ExpectExec("UPDATE obligations").WillReturnError(errors.New("lease exec failed"))
	if _, err := ledger.AcquireLease(ctx, obl.ID, "worker", time.Minute); err == nil {
		t.Fatal("expected lease exec error")
	}
	mock.ExpectExec("UPDATE obligations").WillReturnResult(sqlmock.NewErrorResult(errors.New("rows failed")))
	if _, err := ledger.AcquireLease(ctx, obl.ID, "worker", time.Minute); err == nil || !strings.Contains(err.Error(), "failed to check rows affected") {
		t.Fatalf("expected rows affected error, got %v", err)
	}
	mock.ExpectExec("UPDATE obligations").WillReturnResult(sqlmock.NewResult(0, 0))
	if _, err := ledger.AcquireLease(ctx, obl.ID, "worker", time.Minute); err == nil || !strings.Contains(err.Error(), "locked by another worker") {
		t.Fatalf("expected locked error, got %v", err)
	}
	mock.ExpectExec("UPDATE obligations").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("SELECT id, idempotency_key, intent, state, created_at, updated_at FROM obligations").
		WithArgs(obl.ID).
		WillReturnRows(sqlRows().AddRow(obl.ID, obl.IdempotencyKey, obl.Intent, obl.State, now, now))
	if _, err := ledger.AcquireLease(ctx, obl.ID, "worker", time.Minute); err != nil {
		t.Fatalf("AcquireLease success: %v", err)
	}

	mock.ExpectExec("UPDATE obligations").WillReturnResult(sqlmock.NewResult(0, 1))
	if err := ledger.UpdateState(ctx, obl.ID, StateCompleted, nil); err != nil {
		t.Fatalf("UpdateState: %v", err)
	}
	mock.ExpectExec("UPDATE obligations").WillReturnError(errors.New("update failed"))
	if err := ledger.UpdateState(ctx, obl.ID, StateFailed, nil); err == nil {
		t.Fatal("expected update error")
	}

	mock.ExpectQuery("SELECT id, idempotency_key, intent, state, created_at, updated_at FROM obligations WHERE state = 'PENDING'").
		WillReturnRows(sqlRows().AddRow(obl.ID, obl.IdempotencyKey, obl.Intent, StatePending, now, now))
	pending, err := ledger.ListPending(ctx)
	if err != nil {
		t.Fatalf("ListPending: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("expected pending row, got %#v", pending)
	}
	mock.ExpectQuery("SELECT id, idempotency_key, intent, state, created_at, updated_at FROM obligations WHERE state = 'PENDING'").
		WillReturnError(errors.New("query failed"))
	if _, err := ledger.ListPending(ctx); err == nil {
		t.Fatal("expected ListPending query error")
	}
	mock.ExpectQuery("SELECT id, idempotency_key, intent, state, created_at, updated_at FROM obligations WHERE state = 'PENDING'").
		WillReturnRows(sqlRows().AddRow("bad", "key", "intent", StatePending, "bad-time", now))
	if _, err := ledger.ListPending(ctx); err == nil {
		t.Fatal("expected ListPending scan error")
	}
	rowErr := sqlRows().AddRow(obl.ID, obl.IdempotencyKey, obl.Intent, StatePending, now, now)
	rowErr.RowError(0, errors.New("row failed"))
	mock.ExpectQuery("SELECT id, idempotency_key, intent, state, created_at, updated_at FROM obligations WHERE state = 'PENDING'").
		WillReturnRows(rowErr)
	if _, err := ledger.ListPending(ctx); err == nil {
		t.Fatal("expected ListPending row error")
	}

	mock.ExpectQuery("SELECT id, idempotency_key, intent, state, created_at, updated_at FROM obligations").
		WillReturnRows(sqlRows().AddRow(obl.ID, obl.IdempotencyKey, obl.Intent, StatePending, now, now))
	all, err := ledger.ListAll(ctx)
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("expected all row, got %#v", all)
	}
	mock.ExpectQuery("SELECT id, idempotency_key, intent, state, created_at, updated_at FROM obligations").
		WillReturnError(errors.New("query failed"))
	if _, err := ledger.ListAll(ctx); err == nil {
		t.Fatal("expected ListAll query error")
	}
	mock.ExpectQuery("SELECT id, idempotency_key, intent, state, created_at, updated_at FROM obligations").
		WillReturnRows(sqlRows().AddRow("bad", "key", "intent", StatePending, "bad-time", now))
	if _, err := ledger.ListAll(ctx); err == nil {
		t.Fatal("expected ListAll scan error")
	}
	rowErr = sqlRows().AddRow(obl.ID, obl.IdempotencyKey, obl.Intent, StatePending, now, now)
	rowErr.RowError(0, errors.New("row failed"))
	mock.ExpectQuery("SELECT id, idempotency_key, intent, state, created_at, updated_at FROM obligations").
		WillReturnRows(rowErr)
	if _, err := ledger.ListAll(ctx); err == nil {
		t.Fatal("expected ListAll row error")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresLedgerCoverage(t *testing.T) {
	ctx := context.Background()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	ledger := NewPostgresLedger(db)
	now := time.Unix(200, 0)
	obl := Obligation{ID: "pg-1", IdempotencyKey: "key", Intent: "intent", State: StatePending, CreatedAt: now, UpdatedAt: now, TenantID: "tenant"}

	mock.ExpectExec("CREATE TABLE IF NOT EXISTS obligations").WillReturnResult(sqlmock.NewResult(0, 0))
	if err := ledger.Init(ctx); err != nil {
		t.Fatalf("Init: %v", err)
	}
	mock.ExpectExec("CREATE TABLE IF NOT EXISTS obligations").WillReturnError(errors.New("init failed"))
	if err := ledger.Init(ctx); err == nil {
		t.Fatal("expected init error")
	}

	mock.ExpectQuery("SELECT hash FROM obligations").WillReturnError(errors.New("hash query failed"))
	if err := ledger.Create(ctx, obl); err == nil {
		t.Fatal("expected hash query error")
	}
	mock.ExpectQuery("SELECT hash FROM obligations").WillReturnError(sql.ErrNoRows)
	mock.ExpectExec("INSERT INTO obligations").WillReturnResult(sqlmock.NewResult(1, 1))
	if err := ledger.Create(ctx, obl); err != nil {
		t.Fatalf("Create genesis: %v", err)
	}
	mock.ExpectQuery("SELECT hash FROM obligations").WillReturnRows(sqlmock.NewRows([]string{"hash"}).AddRow("previous"))
	mock.ExpectExec("INSERT INTO obligations").WillReturnError(errors.New("insert failed"))
	if err := ledger.Create(ctx, obl); err == nil {
		t.Fatal("expected insert error")
	}

	mock.ExpectQuery("SELECT id, idempotency_key, intent, state, created_at, updated_at, hash").
		WithArgs(obl.ID).
		WillReturnRows(pgRows().AddRow(obl.ID, obl.IdempotencyKey, obl.Intent, StatePending, now, now, "hash", "previous", `{"attempt":1}`, "tenant"))
	got, err := ledger.Get(ctx, obl.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Metadata["attempt"].(float64) != 1 {
		t.Fatalf("metadata not decoded: %#v", got.Metadata)
	}
	mock.ExpectQuery("SELECT id, idempotency_key, intent, state, created_at, updated_at, hash").
		WithArgs("missing").
		WillReturnError(sql.ErrNoRows)
	if _, err := ledger.Get(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected not found, got %v", err)
	}
	mock.ExpectQuery("SELECT id, idempotency_key, intent, state, created_at, updated_at, hash").
		WithArgs("bad-scan").
		WillReturnRows(pgRows().AddRow("bad-scan", "key", "intent", StatePending, "bad-time", now, "hash", "previous", "", "tenant"))
	if _, err := ledger.Get(ctx, "bad-scan"); err == nil {
		t.Fatal("expected scan error")
	}
	mock.ExpectQuery("SELECT id, idempotency_key, intent, state, created_at, updated_at, hash").
		WithArgs("bad-meta").
		WillReturnRows(pgRows().AddRow("bad-meta", "key", "intent", StatePending, now, now, "hash", "previous", "{", "tenant"))
	if _, err := ledger.Get(ctx, "bad-meta"); err == nil || !strings.Contains(err.Error(), "corrupt metadata") {
		t.Fatalf("expected corrupt metadata, got %v", err)
	}

	mock.ExpectExec("UPDATE obligations").WillReturnError(errors.New("lease exec failed"))
	if _, err := ledger.AcquireLease(ctx, obl.ID, "worker", time.Minute); err == nil {
		t.Fatal("expected lease exec error")
	}
	mock.ExpectExec("UPDATE obligations").WillReturnResult(sqlmock.NewErrorResult(errors.New("rows failed")))
	if _, err := ledger.AcquireLease(ctx, obl.ID, "worker", time.Minute); err == nil || !strings.Contains(err.Error(), "failed to check rows affected") {
		t.Fatalf("expected rows error, got %v", err)
	}
	mock.ExpectExec("UPDATE obligations").WillReturnResult(sqlmock.NewResult(0, 0))
	if _, err := ledger.AcquireLease(ctx, obl.ID, "worker", time.Minute); err == nil || !strings.Contains(err.Error(), "locked by another worker") {
		t.Fatalf("expected locked error, got %v", err)
	}
	mock.ExpectExec("UPDATE obligations").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("SELECT id, idempotency_key, intent, state, created_at, updated_at, hash").
		WithArgs(obl.ID).
		WillReturnRows(pgRows().AddRow(obl.ID, obl.IdempotencyKey, obl.Intent, StatePending, now, now, "hash", "previous", "", "tenant"))
	if _, err := ledger.AcquireLease(ctx, obl.ID, "worker", time.Minute); err != nil {
		t.Fatalf("AcquireLease: %v", err)
	}

	if err := ledger.UpdateState(ctx, obl.ID, StateFailed, map[string]any{"bad": func() {}}); err == nil || !strings.Contains(err.Error(), "failed to marshal metadata") {
		t.Fatalf("expected marshal error, got %v", err)
	}
	mock.ExpectExec("UPDATE obligations SET state").WillReturnResult(sqlmock.NewResult(0, 1))
	if err := ledger.UpdateState(ctx, obl.ID, StateCompleted, map[string]any{"ok": true}); err != nil {
		t.Fatalf("UpdateState: %v", err)
	}
	mock.ExpectExec("UPDATE obligations SET state").WillReturnError(errors.New("update failed"))
	if err := ledger.UpdateState(ctx, obl.ID, StateCompleted, nil); err == nil {
		t.Fatal("expected update error")
	}

	mock.ExpectQuery("SELECT id, idempotency_key, intent, state, created_at, updated_at, hash").WillReturnRows(
		pgRows().AddRow(obl.ID, obl.IdempotencyKey, obl.Intent, StatePending, now, now, "hash", "previous", `{"ok":true}`, "tenant"),
	)
	pending, err := ledger.ListPending(ctx)
	if err != nil {
		t.Fatalf("ListPending: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("expected pending row, got %#v", pending)
	}
	mock.ExpectQuery("SELECT id, idempotency_key, intent, state, created_at, updated_at, hash").WillReturnError(errors.New("query failed"))
	if _, err := ledger.ListPending(ctx); err == nil {
		t.Fatal("expected ListPending query error")
	}
	mock.ExpectQuery("SELECT id, idempotency_key, intent, state, created_at, updated_at, hash").WillReturnRows(
		pgRows().AddRow("bad", "key", "intent", StatePending, "bad-time", now, "hash", "previous", "", "tenant"),
	)
	if _, err := ledger.ListPending(ctx); err == nil {
		t.Fatal("expected ListPending scan error")
	}
	rowErr := pgRows().AddRow(obl.ID, obl.IdempotencyKey, obl.Intent, StatePending, now, now, "hash", "previous", "", "tenant")
	rowErr.RowError(0, errors.New("row failed"))
	mock.ExpectQuery("SELECT id, idempotency_key, intent, state, created_at, updated_at, hash").WillReturnRows(rowErr)
	if _, err := ledger.ListPending(ctx); err == nil {
		t.Fatal("expected ListPending row error")
	}

	mock.ExpectQuery("SELECT id, idempotency_key, intent, state, created_at, updated_at, hash").WillReturnRows(
		pgRows().AddRow(obl.ID, obl.IdempotencyKey, obl.Intent, StatePending, now, now, "hash", "previous", `{"ok":true}`, "tenant"),
	)
	all, err := ledger.ListAll(ctx)
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("expected all row, got %#v", all)
	}
	mock.ExpectQuery("SELECT id, idempotency_key, intent, state, created_at, updated_at, hash").WillReturnError(errors.New("query failed"))
	if _, err := ledger.ListAll(ctx); err == nil {
		t.Fatal("expected ListAll query error")
	}
	mock.ExpectQuery("SELECT id, idempotency_key, intent, state, created_at, updated_at, hash").WillReturnRows(
		pgRows().AddRow("bad", "key", "intent", StatePending, "bad-time", now, "hash", "previous", "", "tenant"),
	)
	if _, err := ledger.ListAll(ctx); err == nil {
		t.Fatal("expected ListAll scan error")
	}
	rowErr = pgRows().AddRow(obl.ID, obl.IdempotencyKey, obl.Intent, StatePending, now, now, "hash", "previous", "", "tenant")
	rowErr.RowError(0, errors.New("row failed"))
	mock.ExpectQuery("SELECT id, idempotency_key, intent, state, created_at, updated_at, hash").WillReturnRows(rowErr)
	if _, err := ledger.ListAll(ctx); err == nil {
		t.Fatal("expected ListAll row error")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresAcquireNextPendingCoverage(t *testing.T) {
	ctx := context.Background()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()
	ledger := NewPostgresLedger(db)

	mock.ExpectBegin().WillReturnError(errors.New("begin failed"))
	if _, err := ledger.AcquireNextPending(ctx, "worker", time.Minute); err == nil {
		t.Fatal("expected begin error")
	}

	mock.ExpectBegin()
	mock.ExpectQuery("SELECT id").WillReturnError(errors.New("select failed"))
	mock.ExpectRollback()
	if _, err := ledger.AcquireNextPending(ctx, "worker", time.Minute); err == nil {
		t.Fatal("expected select error")
	}

	mock.ExpectBegin()
	mock.ExpectQuery("SELECT id").WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("pg-1"))
	mock.ExpectExec("UPDATE obligations").WillReturnError(errors.New("update failed"))
	mock.ExpectRollback()
	if _, err := ledger.AcquireNextPending(ctx, "worker", time.Minute); err == nil {
		t.Fatal("expected update error")
	}

	mock.ExpectBegin()
	mock.ExpectQuery("SELECT id").WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("pg-1"))
	mock.ExpectExec("UPDATE obligations").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit().WillReturnError(errors.New("commit failed"))
	if _, err := ledger.AcquireNextPending(ctx, "worker", time.Minute); err == nil {
		t.Fatal("expected commit error")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func sqlRows() *sqlmock.Rows {
	return sqlmock.NewRows([]string{"id", "idempotency_key", "intent", "state", "created_at", "updated_at"})
}

func pgRows() *sqlmock.Rows {
	return sqlmock.NewRows([]string{"id", "idempotency_key", "intent", "state", "created_at", "updated_at", "hash", "previous_hash", "metadata", "tenant_id"})
}
