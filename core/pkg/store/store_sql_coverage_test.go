package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

type storeCoverageVerifier struct {
	valid bool
	err   error
}

func (v storeCoverageVerifier) Verify([]byte, []byte) bool {
	return v.valid
}

func (v storeCoverageVerifier) VerifyDecision(*contracts.DecisionRecord) (bool, error) {
	return v.valid, v.err
}

func (v storeCoverageVerifier) VerifyIntent(*contracts.AuthorizedExecutionIntent) (bool, error) {
	return v.valid, v.err
}

func (v storeCoverageVerifier) VerifyReceipt(*contracts.Receipt) (bool, error) {
	return v.valid, v.err
}

type storeRoundTripFunc func(*http.Request) (*http.Response, error)

func (f storeRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestCoverageOpenAIEmbedderBranches(t *testing.T) {
	ctx := context.Background()
	if _, err := NewOpenAIEmbedder("").Embed(ctx, "text"); err == nil {
		t.Fatal("expected missing key error")
	}

	success := NewOpenAIEmbedder("key")
	success.client = &http.Client{Transport: storeRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodPost || req.URL.Host != "api.openai.com" || req.Header.Get("Authorization") != "Bearer key" {
			t.Fatalf("unexpected request: %s %s auth=%q", req.Method, req.URL.String(), req.Header.Get("Authorization"))
		}
		body, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatalf("read request body: %v", err)
		}
		if !strings.Contains(string(body), "text-embedding-3-small") || !strings.Contains(string(body), "hello") {
			t.Fatalf("unexpected request body: %s", string(body))
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"data":[{"embedding":[1.25,2.5]}]}`)),
			Header:     make(http.Header),
		}, nil
	})}
	got, err := success.Embed(ctx, "hello")
	if err != nil || len(got) != 2 || got[0] != 1.25 {
		t.Fatalf("unexpected embedding %v err=%v", got, err)
	}

	for name, transport := range map[string]storeRoundTripFunc{
		"transport error": func(*http.Request) (*http.Response, error) {
			return nil, errors.New("transport failed")
		},
		"status error": func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusTooManyRequests, Body: io.NopCloser(strings.NewReader(`{}`))}, nil
		},
		"decode error": func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{`))}, nil
		},
		"empty data": func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"data":[]}`))}, nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			embedder := NewOpenAIEmbedder("key")
			embedder.client = &http.Client{Transport: transport}
			if _, err := embedder.Embed(ctx, "hello"); err == nil {
				t.Fatal("expected embed error")
			}
		})
	}
}

func TestCoveragePGVectorStoreBranches(t *testing.T) {
	ctx := context.Background()
	db, mock, cleanup := newStoreCoverageSQLMock(t)
	defer cleanup()

	store := NewPGVectorStore(db)
	mock.ExpectExec("INSERT INTO embeddings").
		WithArgs("id-1", "[1,2.5]", "hello", []byte(`{"a":"b"}`)).
		WillReturnResult(sqlmock.NewResult(1, 1))
	if err := store.Store(ctx, "id-1", "hello", Embedding{1, 2.5}, map[string]string{"a": "b"}); err != nil {
		t.Fatalf("Store: %v", err)
	}
	mock.ExpectExec("INSERT INTO embeddings").WillReturnError(errors.New("insert failed"))
	if err := store.Store(ctx, "id-2", "hello", Embedding{3}, nil); err == nil {
		t.Fatal("expected store error")
	}

	mock.ExpectQuery("SELECT id, text, metadata").
		WithArgs("[1,2.5]", 2).
		WillReturnRows(sqlmock.NewRows([]string{"id", "text", "metadata", "score"}).
			AddRow("id-1", "hello", []byte(`{"a":"b"}`), 0.75).
			AddRow("id-2", "world", []byte(`{`), 0.25))
	results, err := store.Search(ctx, Embedding{1, 2.5}, 2)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(results) != 2 || results[0].Metadata["a"] != "b" || results[1].Metadata != nil {
		t.Fatalf("unexpected search results: %+v", results)
	}

	mock.ExpectQuery("SELECT id, text, metadata").WillReturnError(errors.New("query failed"))
	if _, err := store.Search(ctx, Embedding{1}, 1); err == nil {
		t.Fatal("expected query error")
	}
	mock.ExpectQuery("SELECT id, text, metadata").
		WillReturnRows(sqlmock.NewRows([]string{"id", "text", "metadata", "score"}).
			AddRow("id-bad", "bad", []byte(`{}`), "not-a-score"))
	if _, err := store.Search(ctx, Embedding{1}, 1); err == nil {
		t.Fatal("expected scan error")
	}
	mock.ExpectQuery("SELECT id, text, metadata").
		WillReturnRows(sqlmock.NewRows([]string{"id", "text", "metadata", "score"}).
			AddRow("id-row-error", "bad", []byte(`{}`), 0.1).
			RowError(0, errors.New("row failed")))
	if _, err := store.Search(ctx, Embedding{1}, 1); err == nil {
		t.Fatal("expected rows error")
	}
}

func TestCoveragePostgresEffectOutboxStoreBranches(t *testing.T) {
	ctx := context.Background()
	effect := &contracts.Effect{EffectID: "effect-1", EffectType: contracts.EffectTypeGeneric, Params: map[string]any{"ok": true}}
	intent := &contracts.AuthorizedExecutionIntent{ID: "intent-1", DecisionID: "decision-1", AllowedTool: "tool"}

	db, mock, cleanup := newStoreCoverageSQLMock(t)
	defer cleanup()

	errVerifier := NewPostgresEffectOutboxStore(db, storeCoverageVerifier{err: errors.New("verify failed")})
	if err := errVerifier.Schedule(ctx, effect, intent); err == nil || !strings.Contains(err.Error(), "error verifying intent") {
		t.Fatalf("expected verifier error, got %v", err)
	}
	invalidVerifier := NewPostgresEffectOutboxStore(db, storeCoverageVerifier{valid: false})
	if err := invalidVerifier.Schedule(ctx, effect, intent); err == nil || !strings.Contains(err.Error(), "invalid intent signature") {
		t.Fatalf("expected invalid signature error, got %v", err)
	}

	outbox := NewPostgresEffectOutboxStore(db, storeCoverageVerifier{valid: true})
	if err := outbox.Schedule(ctx, &contracts.Effect{Params: map[string]any{"bad": func() {}}}, intent); err == nil {
		t.Fatal("expected effect marshal error")
	}
	mock.ExpectExec("INSERT INTO effect_outbox").WillReturnResult(sqlmock.NewResult(1, 1))
	if err := outbox.Schedule(ctx, effect, intent); err != nil {
		t.Fatalf("Schedule: %v", err)
	}
	mock.ExpectExec("INSERT INTO effect_outbox").WillReturnError(errors.New("insert failed"))
	if err := outbox.Schedule(ctx, effect, intent); err == nil || !strings.Contains(err.Error(), "failed to schedule effect") {
		t.Fatalf("expected schedule insert error, got %v", err)
	}

	effectJSON, err := json.Marshal(effect)
	if err != nil {
		t.Fatal(err)
	}
	intentJSON, err := json.Marshal(intent)
	if err != nil {
		t.Fatal(err)
	}
	scheduled := time.Unix(1700000000, 0).UTC()
	mock.ExpectQuery("SELECT id, effect_json, decision_json").
		WillReturnRows(sqlmock.NewRows([]string{"id", "effect_json", "decision_json", "scheduled_at", "status"}).
			AddRow("intent-1", effectJSON, intentJSON, scheduled, "PENDING"))
	pending, err := outbox.GetPending(ctx)
	if err != nil {
		t.Fatalf("GetPending: %v", err)
	}
	if len(pending) != 1 || pending[0].ID != "intent-1" || pending[0].Status != "PENDING" {
		t.Fatalf("unexpected pending records: %+v", pending)
	}

	mock.ExpectQuery("SELECT id, effect_json, decision_json").WillReturnError(errors.New("select failed"))
	if _, err := outbox.GetPending(ctx); err == nil {
		t.Fatal("expected query error")
	}
	for name, row := range map[string]*sqlmock.Rows{
		"scan error": sqlmock.NewRows([]string{"id", "effect_json", "decision_json", "scheduled_at", "status"}).
			AddRow("bad", effectJSON, intentJSON, "not-time", "PENDING"),
		"bad effect": sqlmock.NewRows([]string{"id", "effect_json", "decision_json", "scheduled_at", "status"}).
			AddRow("bad-effect", []byte(`{`), intentJSON, scheduled, "PENDING"),
		"bad intent": sqlmock.NewRows([]string{"id", "effect_json", "decision_json", "scheduled_at", "status"}).
			AddRow("bad-intent", effectJSON, []byte(`{`), scheduled, "PENDING"),
		"row error": sqlmock.NewRows([]string{"id", "effect_json", "decision_json", "scheduled_at", "status"}).
			AddRow("row-error", effectJSON, intentJSON, scheduled, "PENDING").
			RowError(0, errors.New("row failed")),
	} {
		t.Run(name, func(t *testing.T) {
			mock.ExpectQuery("SELECT id, effect_json, decision_json").WillReturnRows(row)
			if _, err := outbox.GetPending(ctx); err == nil {
				t.Fatal("expected pending error")
			}
		})
	}

	mock.ExpectExec("UPDATE effect_outbox").WithArgs("intent-1").WillReturnResult(sqlmock.NewResult(0, 1))
	if err := outbox.MarkDone(ctx, "intent-1"); err != nil {
		t.Fatalf("MarkDone: %v", err)
	}
	mock.ExpectExec("UPDATE effect_outbox").WithArgs("intent-2").WillReturnError(errors.New("update failed"))
	if err := outbox.MarkDone(ctx, "intent-2"); err == nil {
		t.Fatal("expected mark done error")
	}
}

func TestCoveragePostgresReceiptStoreQueries(t *testing.T) {
	ctx := context.Background()
	db, mock, cleanup := newStoreCoverageSQLMock(t)
	defer cleanup()
	store := NewPostgresReceiptStore(db)
	now := time.Unix(1700000000, 0).UTC()
	receipt := storeCoverageReceipt("receipt-1", "decision-1", "agent-1", 7, now)

	mock.ExpectExec("CREATE TABLE IF NOT EXISTS receipts").WillReturnResult(sqlmock.NewResult(0, 0))
	if err := store.Init(ctx); err != nil {
		t.Fatalf("Init: %v", err)
	}
	mock.ExpectExec("CREATE TABLE IF NOT EXISTS receipts").WillReturnError(errors.New("init failed"))
	if err := store.Init(ctx); err == nil {
		t.Fatal("expected init error")
	}

	mock.ExpectExec("INSERT INTO receipts").WithArgs(storeAnySQLArgs(19)...).WillReturnResult(sqlmock.NewResult(1, 1))
	if err := store.Store(ctx, receipt); err != nil {
		t.Fatalf("Store: %v", err)
	}
	if err := store.Store(ctx, &contracts.Receipt{Metadata: map[string]any{"bad": func() {}}}); err == nil {
		t.Fatal("expected metadata marshal error")
	}
	mock.ExpectExec("INSERT INTO receipts").WillReturnError(errors.New("insert failed"))
	if err := store.Store(ctx, receipt); err == nil || !strings.Contains(err.Error(), "failed to insert receipt") {
		t.Fatalf("expected insert error, got %v", err)
	}

	mock.ExpectQuery("FROM receipts WHERE decision_id").WithArgs("decision-1").WillReturnRows(storePostgresReceiptRows(receipt, []byte(`{"k":"v"}`)))
	got, err := store.Get(ctx, "decision-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ReceiptID != receipt.ReceiptID || got.Metadata["k"] != "v" {
		t.Fatalf("unexpected receipt: %+v", got)
	}
	mock.ExpectQuery("FROM receipts WHERE decision_id").WithArgs("missing").WillReturnError(sql.ErrNoRows)
	if _, err := store.Get(ctx, "missing"); err == nil || !strings.Contains(err.Error(), "receipt not found") {
		t.Fatalf("expected receipt not found, got %v", err)
	}
	mock.ExpectQuery("FROM receipts WHERE receipt_id").WithArgs("bad-meta").WillReturnRows(storePostgresReceiptRows(receipt, []byte(`{`)))
	if _, err := store.GetByReceiptID(ctx, "bad-meta"); err == nil || !strings.Contains(err.Error(), "decode receipt metadata") {
		t.Fatalf("expected metadata decode error, got %v", err)
	}

	mock.ExpectQuery("FROM receipts ORDER BY timestamp DESC").WithArgs(2).
		WillReturnRows(storePostgresReceiptRows(receipt, []byte(`null`)).
			AddRow("receipt-2", "decision-2", "effect", "", "OK", "blob", "output", now.Add(time.Second), "agent-2", []byte(`{"x":1}`), nil, nil, "", int64(8), "args", "", int64(0), nil))
	list, err := store.List(ctx, 2)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 2 || list[1].Metadata["x"].(float64) != 1 {
		t.Fatalf("unexpected list: %+v", list)
	}
	mock.ExpectQuery("FROM receipts ORDER BY timestamp DESC").WillReturnError(errors.New("list failed"))
	if _, err := store.List(ctx, 1); err == nil {
		t.Fatal("expected list query error")
	}
	mock.ExpectQuery("FROM receipts ORDER BY timestamp DESC").
		WillReturnRows(sqlmock.NewRows(storePostgresReceiptColumns()).
			AddRow("receipt-bad", "decision-bad", "effect", "", "OK", "blob", "output", "not-time", "agent", []byte(`null`), nil, nil, "", int64(1), "args", "", int64(0), nil))
	if _, err := store.List(ctx, 1); err == nil {
		t.Fatal("expected list scan error")
	}

	mock.ExpectQuery("FROM receipts WHERE executor_id").WithArgs("agent-1", uint64(1), 10).WillReturnRows(storePostgresReceiptRows(receipt, nil))
	if got, err := store.ListByAgent(ctx, "agent-1", 1, 10); err != nil || len(got) != 1 {
		t.Fatalf("ListByAgent got %d err=%v", len(got), err)
	}
	mock.ExpectQuery("FROM receipts WHERE executor_id").WillReturnError(errors.New("agent query failed"))
	if _, err := store.ListByAgent(ctx, "agent-1", 1, 10); err == nil {
		t.Fatal("expected ListByAgent query error")
	}
	mock.ExpectQuery("FROM receipts WHERE lamport_clock").WithArgs(uint64(1), 10).WillReturnRows(storePostgresReceiptRows(receipt, nil))
	if got, err := store.ListSince(ctx, 1, 10); err != nil || len(got) != 1 {
		t.Fatalf("ListSince got %d err=%v", len(got), err)
	}
	mock.ExpectQuery("FROM receipts WHERE lamport_clock").WillReturnError(errors.New("since query failed"))
	if _, err := store.ListSince(ctx, 1, 10); err == nil {
		t.Fatal("expected ListSince query error")
	}

	mock.ExpectQuery("FROM receipts WHERE executor_id").WithArgs("agent-row-error", uint64(0), 1).
		WillReturnRows(storePostgresReceiptRows(receipt, nil).RowError(0, errors.New("agent row failed")))
	if _, err := store.ListByAgent(ctx, "agent-row-error", 0, 1); err == nil {
		t.Fatal("expected ListByAgent rows error")
	}
	mock.ExpectQuery("FROM receipts WHERE lamport_clock").WithArgs(uint64(0), 1).
		WillReturnRows(storePostgresReceiptRows(receipt, nil).RowError(0, errors.New("since row failed")))
	if _, err := store.ListSince(ctx, 0, 1); err == nil {
		t.Fatal("expected ListSince rows error")
	}

	mock.ExpectQuery("FROM receipts WHERE executor_id").WithArgs("agent-1").WillReturnRows(storePostgresReceiptRows(receipt, nil))
	last, err := store.GetLastForSession(ctx, "agent-1")
	if err != nil || last == nil || last.ReceiptID != receipt.ReceiptID {
		t.Fatalf("GetLastForSession got %+v err=%v", last, err)
	}
	mock.ExpectQuery("FROM receipts WHERE executor_id").WithArgs("missing").WillReturnRows(sqlmock.NewRows(storePostgresReceiptColumns()))
	last, err = store.GetLastForSession(ctx, "missing")
	if err != nil || last != nil {
		t.Fatalf("expected missing last receipt to be nil, got %+v err=%v", last, err)
	}
}

func TestCoverageAirgapStoreErrorBranches(t *testing.T) {
	temp := t.TempDir()
	storageFile := filepath.Join(temp, "storage-file")
	if err := os.WriteFile(storageFile, []byte("not a directory"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewAirgapStore(filepath.Join(storageFile, "child")); err == nil {
		t.Fatal("expected storage dir create error")
	}

	badJSONDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(badJSONDir, "airgap_cache.json"), []byte(`{`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewAirgapStore(badJSONDir); err == nil {
		t.Fatal("expected load error for invalid cache")
	}

	removedDir := t.TempDir()
	store, err := NewAirgapStore(removedDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(removedDir); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(context.Background(), "key", []byte("value")); err == nil {
		t.Fatal("expected save error after storage dir removal")
	}
}

func TestCoverageSQLiteReceiptMigrationAndParsingBranches(t *testing.T) {
	if !parseTime("").IsZero() {
		t.Fatal("empty parseTime should be zero")
	}
	now := time.Unix(1700000000, 123).UTC()
	if got := parseTime(now.Format(time.RFC3339Nano)); !got.Equal(now) {
		t.Fatalf("RFC3339Nano parse = %s, want %s", got, now)
	}
	truncated := now.Truncate(time.Second)
	if got := parseTime(truncated.Format(time.RFC3339)); !got.Equal(truncated) {
		t.Fatalf("RFC3339 parse = %s, want %s", got, truncated)
	}
	if !parseTime("not-a-time").IsZero() {
		t.Fatal("bad parseTime should be zero")
	}

	receipt, err := receiptFromSQLiteFields(
		"receipt", "decision", "effect",
		sql.NullString{String: "external", Valid: true},
		"OK", "blob", "output", now.Format(time.RFC3339Nano),
		sql.NullString{String: "agent", Valid: true},
		sql.NullString{String: `{"a":1}`, Valid: true},
		sql.NullString{String: "sig", Valid: true},
		sql.NullString{String: "root", Valid: true},
		sql.NullString{String: "prev", Valid: true},
		9,
		sql.NullString{String: "args", Valid: true},
		sql.NullString{String: "logid", Valid: true},
		11,
		sql.NullString{String: `{"backend":"translog","deferred":true}`, Valid: true},
	)
	if err != nil {
		t.Fatalf("receiptFromSQLiteFields: %v", err)
	}
	if receipt.Metadata["a"].(float64) != 1 || receipt.ExternalReferenceID != "external" || receipt.ArgsHash != "args" {
		t.Fatalf("unexpected SQLite receipt: %+v", receipt)
	}
	if receipt.LogID != "logid" || receipt.LeafIndex != 11 || receipt.Transparency == nil || !receipt.Transparency.Deferred {
		t.Fatalf("transparency fields not decoded: %+v", receipt)
	}
	if _, err := receiptFromSQLiteFields("r", "d", "e", sql.NullString{}, "OK", "", "", "", sql.NullString{}, sql.NullString{String: `{`, Valid: true}, sql.NullString{}, sql.NullString{}, sql.NullString{}, 0, sql.NullString{}, sql.NullString{}, 0, sql.NullString{}); err == nil {
		t.Fatal("expected SQLite metadata decode error")
	}

	db, mock, cleanup := newStoreCoverageSQLMock(t)
	defer cleanup()
	mock.ExpectExec("PRAGMA journal_mode").WillReturnError(errors.New("wal failed"))
	if _, err := NewSQLiteReceiptStore(db); err == nil {
		t.Fatal("expected WAL setup error")
	}

	dbBusy, mockBusy, cleanupBusy := newStoreCoverageSQLMock(t)
	defer cleanupBusy()
	mockBusy.ExpectExec("PRAGMA journal_mode").WillReturnResult(sqlmock.NewResult(0, 0))
	mockBusy.ExpectExec("PRAGMA synchronous").WillReturnResult(sqlmock.NewResult(0, 0))
	mockBusy.ExpectExec("PRAGMA busy_timeout").WillReturnError(errors.New("busy failed"))
	if _, err := NewSQLiteReceiptStore(dbBusy); err == nil {
		t.Fatal("expected busy timeout setup error")
	}

	dbMigrate, mockMigrate, cleanupMigrate := newStoreCoverageSQLMock(t)
	defer cleanupMigrate()
	sqliteStore := &SQLiteReceiptStore{db: dbMigrate}
	mockMigrate.ExpectExec("CREATE TABLE IF NOT EXISTS receipts").WillReturnError(errors.New("create failed"))
	if err := sqliteStore.migrate(); err == nil {
		t.Fatal("expected migrate create error")
	}

	dbEnsure, mockEnsure, cleanupEnsure := newStoreCoverageSQLMock(t)
	defer cleanupEnsure()
	sqliteStore = &SQLiteReceiptStore{db: dbEnsure}
	mockEnsure.ExpectQuery("PRAGMA table_info").WillReturnRows(sqlmock.NewRows([]string{"cid", "name", "type", "notnull", "dflt_value", "pk"}).AddRow(0, "args_hash", "TEXT", 1, "", 0))
	if err := sqliteStore.ensureColumn("args_hash", "TEXT"); err != nil {
		t.Fatalf("ensure existing column: %v", err)
	}
	mockEnsure.ExpectQuery("PRAGMA table_info").WillReturnError(errors.New("pragma failed"))
	if err := sqliteStore.ensureColumn("missing", "TEXT"); err == nil {
		t.Fatal("expected ensure query error")
	}
	mockEnsure.ExpectQuery("PRAGMA table_info").
		WillReturnRows(sqlmock.NewRows([]string{"cid", "name", "type", "notnull", "dflt_value", "pk"}).
			AddRow("bad-cid", "name", "TEXT", 0, "", 0))
	if err := sqliteStore.ensureColumn("missing", "TEXT"); err == nil {
		t.Fatal("expected ensure scan error")
	}
	mockEnsure.ExpectQuery("PRAGMA table_info").WillReturnRows(sqlmock.NewRows([]string{"cid", "name", "type", "notnull", "dflt_value", "pk"}))
	mockEnsure.ExpectExec("ALTER TABLE receipts ADD COLUMN missing TEXT").WillReturnError(errors.New("alter failed"))
	if err := sqliteStore.ensureColumn("missing", "TEXT"); err == nil {
		t.Fatal("expected ensure alter error")
	}
}

func TestCoveragePostgresReceiptStoreAppendCausal(t *testing.T) {
	ctx := context.Background()
	db, mock, cleanup := newStoreCoverageSQLMock(t)
	defer cleanup()
	store := NewPostgresReceiptStore(db)
	now := time.Unix(1700000000, 0).UTC()

	if err := store.AppendCausal(ctx, "agent", nil); err == nil {
		t.Fatal("expected nil builder error")
	}
	if err := store.AppendCausal(ctx, "", func(*contracts.Receipt, uint64, string) (*contracts.Receipt, error) { return nil, nil }); err == nil {
		t.Fatal("expected missing session error")
	}

	mock.ExpectBegin()
	mock.ExpectExec("SELECT pg_advisory_xact_lock").WithArgs("agent").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("FROM receipts WHERE executor_id").WithArgs("agent").WillReturnRows(sqlmock.NewRows(storePostgresReceiptColumns()))
	mock.ExpectExec("INSERT INTO receipts").WithArgs(storeAnySQLArgs(19)...).WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()
	if err := store.AppendCausal(ctx, "agent", func(previous *contracts.Receipt, lamport uint64, prevHash string) (*contracts.Receipt, error) {
		if previous != nil || lamport != 1 || prevHash != "" {
			t.Fatalf("unexpected genesis inputs previous=%+v lamport=%d prev=%q", previous, lamport, prevHash)
		}
		return storeCoverageReceipt("receipt-genesis", "decision-genesis", "agent", lamport, now), nil
	}); err != nil {
		t.Fatalf("AppendCausal genesis: %v", err)
	}

	mock.ExpectExec("INSERT INTO receipts").WithArgs(storeAnySQLArgs(19)...).WillReturnResult(sqlmock.NewResult(1, 1))
	if err := store.AppendCausal(ctx, "agent", func(previous *contracts.Receipt, lamport uint64, prevHash string) (*contracts.Receipt, error) {
		if previous == nil || previous.ReceiptID != "receipt-genesis" || lamport != 2 || prevHash == "" {
			t.Fatalf("unexpected chained inputs previous=%+v lamport=%d prev=%q", previous, lamport, prevHash)
		}
		next := storeCoverageReceipt("receipt-next", "decision-next", "agent", lamport, now.Add(time.Second))
		next.PrevHash = prevHash
		return next, nil
	}); err != nil {
		t.Fatalf("AppendCausal chained: %v", err)
	}

	store.lastBySession = map[string]*contracts.Receipt{}
	mock.ExpectBegin()
	mock.ExpectExec("SELECT pg_advisory_xact_lock").WithArgs("agent").WillReturnError(errors.New("lock failed"))
	mock.ExpectRollback()
	if err := store.AppendCausal(ctx, "agent", func(*contracts.Receipt, uint64, string) (*contracts.Receipt, error) { return nil, nil }); err == nil {
		t.Fatal("expected lock error")
	}

	store.lastBySession = map[string]*contracts.Receipt{}
	mock.ExpectBegin()
	mock.ExpectExec("SELECT pg_advisory_xact_lock").WithArgs("agent").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("FROM receipts WHERE executor_id").WithArgs("agent").WillReturnError(errors.New("last failed"))
	mock.ExpectRollback()
	if err := store.AppendCausal(ctx, "agent", func(*contracts.Receipt, uint64, string) (*contracts.Receipt, error) { return nil, nil }); err == nil {
		t.Fatal("expected last receipt error")
	}

	store.lastBySession = map[string]*contracts.Receipt{}
	mock.ExpectBegin()
	mock.ExpectExec("SELECT pg_advisory_xact_lock").WithArgs("agent").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("FROM receipts WHERE executor_id").WithArgs("agent").WillReturnRows(sqlmock.NewRows(storePostgresReceiptColumns()))
	mock.ExpectRollback()
	if err := store.AppendCausal(ctx, "agent", func(*contracts.Receipt, uint64, string) (*contracts.Receipt, error) {
		return nil, errors.New("builder failed")
	}); err == nil {
		t.Fatal("expected builder error")
	}

	store.lastBySession = map[string]*contracts.Receipt{}
	mock.ExpectBegin()
	mock.ExpectExec("SELECT pg_advisory_xact_lock").WithArgs("agent").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("FROM receipts WHERE executor_id").WithArgs("agent").WillReturnRows(sqlmock.NewRows(storePostgresReceiptColumns()))
	mock.ExpectExec("INSERT INTO receipts").WillReturnError(errors.New("insert failed"))
	mock.ExpectRollback()
	if err := store.AppendCausal(ctx, "agent", func(*contracts.Receipt, uint64, string) (*contracts.Receipt, error) {
		return storeCoverageReceipt("receipt-insert-fail", "decision-insert-fail", "agent", 1, now), nil
	}); err == nil {
		t.Fatal("expected insert error")
	}

	store.lastBySession = map[string]*contracts.Receipt{}
	mock.ExpectBegin()
	mock.ExpectExec("SELECT pg_advisory_xact_lock").WithArgs("agent").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("FROM receipts WHERE executor_id").WithArgs("agent").WillReturnRows(sqlmock.NewRows(storePostgresReceiptColumns()))
	mock.ExpectExec("INSERT INTO receipts").WithArgs(storeAnySQLArgs(19)...).WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit().WillReturnError(errors.New("commit failed"))
	if err := store.AppendCausal(ctx, "agent", func(*contracts.Receipt, uint64, string) (*contracts.Receipt, error) {
		return storeCoverageReceipt("receipt-commit-fail", "decision-commit-fail", "agent", 1, now), nil
	}); err == nil {
		t.Fatal("expected commit error")
	}
}

func TestCoverageBuildNextCausalReceiptBranches(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	if _, err := buildNextCausalReceipt("agent", nil, func(*contracts.Receipt, uint64, string) (*contracts.Receipt, error) {
		return nil, errors.New("builder failed")
	}); err == nil {
		t.Fatal("expected builder error")
	}
	if _, err := buildNextCausalReceipt("agent", nil, func(*contracts.Receipt, uint64, string) (*contracts.Receipt, error) {
		return nil, nil
	}); err == nil {
		t.Fatal("expected nil receipt error")
	}
	if got, err := buildNextCausalReceipt("agent", nil, func(*contracts.Receipt, uint64, string) (*contracts.Receipt, error) {
		return storeCoverageReceipt("receipt-empty-executor", "decision", "", 1, now), nil
	}); err != nil || got.ExecutorID != "agent" {
		t.Fatalf("expected default executor, got %+v err=%v", got, err)
	}
	for name, build := range map[string]CausalReceiptBuilder{
		"wrong executor": func(*contracts.Receipt, uint64, string) (*contracts.Receipt, error) {
			return storeCoverageReceipt("receipt", "decision", "other", 1, now), nil
		},
		"wrong lamport": func(*contracts.Receipt, uint64, string) (*contracts.Receipt, error) {
			return storeCoverageReceipt("receipt", "decision", "agent", 2, now), nil
		},
		"wrong prev hash": func(*contracts.Receipt, uint64, string) (*contracts.Receipt, error) {
			r := storeCoverageReceipt("receipt", "decision", "agent", 1, now)
			r.PrevHash = "wrong"
			return r, nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := buildNextCausalReceipt("agent", nil, build); err == nil {
				t.Fatal("expected causal validation error")
			}
		})
	}

	previous := storeCoverageReceipt("previous", "decision-prev", "agent", 5, now)
	got, err := buildNextCausalReceipt("agent", previous, func(previous *contracts.Receipt, lamport uint64, prevHash string) (*contracts.Receipt, error) {
		if previous == nil || lamport != 6 || prevHash == "" {
			t.Fatalf("unexpected previous branch inputs previous=%+v lamport=%d prev=%q", previous, lamport, prevHash)
		}
		next := storeCoverageReceipt("next", "decision-next", "agent", lamport, now.Add(time.Second))
		next.PrevHash = prevHash
		return next, nil
	})
	if err != nil || got.LamportClock != 6 || got.PrevHash == "" {
		t.Fatalf("unexpected previous branch result %+v err=%v", got, err)
	}
}

func newStoreCoverageSQLMock(t *testing.T) (*sql.DB, sqlmock.Sqlmock, func()) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	return db, mock, func() {
		t.Helper()
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("sqlmock expectations: %v", err)
		}
		_ = db.Close()
	}
}

func storeAnySQLArgs(count int) []driver.Value {
	args := make([]driver.Value, count)
	for i := range args {
		args[i] = sqlmock.AnyArg()
	}
	return args
}

func storeCoverageReceipt(receiptID, decisionID, executorID string, lamport uint64, timestamp time.Time) *contracts.Receipt {
	return &contracts.Receipt{
		ReceiptID:           receiptID,
		DecisionID:          decisionID,
		EffectID:            "effect",
		ExternalReferenceID: "external",
		Status:              "OK",
		BlobHash:            "blob",
		OutputHash:          "output",
		Timestamp:           timestamp,
		ExecutorID:          executorID,
		Metadata:            map[string]any{"source": "coverage"},
		Signature:           "signature",
		MerkleRoot:          "merkle",
		PrevHash:            "",
		LamportClock:        lamport,
		ArgsHash:            "args",
	}
}

func storePostgresReceiptColumns() []string {
	return []string{
		"receipt_id",
		"decision_id",
		"effect_id",
		"external_reference_id",
		"status",
		"blob_hash",
		"output_hash",
		"timestamp",
		"executor_id",
		"metadata",
		"signature",
		"merkle_root",
		"prev_hash",
		"lamport_clock",
		"args_hash",
		"log_id",
		"leaf_index",
		"transparency",
	}
}

func storePostgresReceiptRows(receipt *contracts.Receipt, metadata []byte) *sqlmock.Rows {
	if metadata == nil {
		metadata = []byte(`null`)
	}
	return sqlmock.NewRows(storePostgresReceiptColumns()).
		AddRow(
			receipt.ReceiptID,
			receipt.DecisionID,
			receipt.EffectID,
			receipt.ExternalReferenceID,
			receipt.Status,
			receipt.BlobHash,
			receipt.OutputHash,
			receipt.Timestamp,
			receipt.ExecutorID,
			metadata,
			receipt.Signature,
			receipt.MerkleRoot,
			receipt.PrevHash,
			int64(receipt.LamportClock),
			receipt.ArgsHash,
			receipt.LogID,
			int64(receipt.LeafIndex),
			storePostgresTransparencyValue(receipt),
		)
}

func storePostgresTransparencyValue(receipt *contracts.Receipt) any {
	if receipt.Transparency == nil {
		return nil
	}
	encoded, err := encodeTransparencyAnchor(receipt)
	if err != nil {
		return nil
	}
	return encoded
}
