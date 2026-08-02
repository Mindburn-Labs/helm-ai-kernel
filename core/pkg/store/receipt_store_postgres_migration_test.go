package store

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

func TestPostgresReceiptMigrationBackfillsOrRejectsV5DecisionHash(t *testing.T) {
	postgresURL := os.Getenv("HELM_TEST_POSTGRES_URL")
	if postgresURL == "" {
		t.Skip("set HELM_TEST_POSTGRES_URL to run the Postgres receipt migration proof")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	schema := fmt.Sprintf("helm_receipt_v5_migration_%d", time.Now().UnixNano())
	db, err := sql.Open("postgres", postgresURLWithSearchPath(t, postgresURL, schema))
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.ExecContext(ctx, `CREATE SCHEMA IF NOT EXISTS `+schema); err != nil {
		t.Fatalf("create test schema: %v", err)
	}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		_, _ = db.ExecContext(cleanupCtx, `DROP SCHEMA IF EXISTS `+schema+` CASCADE`)
	}()

	// This is the historical shape needed by the V5 migration: metadata was
	// already durable, but decision_hash was not yet a dedicated column.
	if _, err := db.ExecContext(ctx, `CREATE TABLE receipts (
		receipt_id TEXT PRIMARY KEY,
		decision_id TEXT NOT NULL,
		execution_intent_id TEXT,
		status TEXT NOT NULL,
		timestamp TIMESTAMPTZ NOT NULL,
		executor_id TEXT NOT NULL DEFAULT '',
		metadata JSONB,
		prev_hash TEXT NOT NULL DEFAULT '',
		lamport_clock BIGINT NOT NULL DEFAULT 0,
		signature_version TEXT NOT NULL DEFAULT '',
		session_id TEXT NOT NULL DEFAULT ''
	)`); err != nil {
		t.Fatalf("create pre-004 receipts table: %v", err)
	}

	timestamp := time.Unix(1700000000, 0).UTC()
	if _, err := db.ExecContext(ctx, `INSERT INTO receipts (
		receipt_id, decision_id, execution_intent_id, status, timestamp, executor_id,
		metadata, signature_version, session_id
	) VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9)`,
		"r-v5-recoverable", "d-v5-recoverable", "effect", "ALLOW", timestamp, "executor",
		`{"decision_hash":"sha256:trusted"}`, contracts.ReceiptSignatureV5, "session-recoverable"); err != nil {
		t.Fatalf("insert recoverable historical receipt: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO receipts (
		receipt_id, decision_id, execution_intent_id, status, timestamp, executor_id,
		signature_version, session_id
	) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		"r-v5-unrecoverable", "d-v5-unrecoverable", "effect", "ALLOW", timestamp, "executor",
		contracts.ReceiptSignatureV5, "session-unrecoverable"); err != nil {
		t.Fatalf("insert unrecoverable historical receipt: %v", err)
	}

	migration, err := os.ReadFile(filepath.Join("migrations", "004_add_receipt_decision_hash.sql"))
	if err != nil {
		t.Fatalf("read 004 receipt migration: %v", err)
	}
	if _, err := db.ExecContext(ctx, string(migration)); err != nil {
		t.Fatalf("apply 004 receipt migration: %v", err)
	}

	var recoveredHash string
	if err := db.QueryRowContext(ctx, `SELECT decision_hash FROM receipts WHERE receipt_id = $1`, "r-v5-recoverable").Scan(&recoveredHash); err != nil {
		t.Fatalf("read recovered decision hash: %v", err)
	}
	if recoveredHash != "sha256:trusted" {
		t.Fatalf("durable migration decision_hash = %q, want trusted metadata value", recoveredHash)
	}

	appendSequenceMigration, err := os.ReadFile(filepath.Join("migrations", "005_add_receipt_append_sequence.sql"))
	if err != nil {
		t.Fatalf("read 005 receipt migration: %v", err)
	}
	if _, err := db.ExecContext(ctx, string(appendSequenceMigration)); err != nil {
		t.Fatalf("apply 005 receipt migration: %v", err)
	}
	for wantSequence, receiptID := range map[int64]string{
		1: "r-v5-recoverable",
		2: "r-v5-unrecoverable",
	} {
		var gotSequence int64
		if err := db.QueryRowContext(ctx, `SELECT append_sequence FROM receipts WHERE receipt_id = $1`, receiptID).Scan(&gotSequence); err != nil {
			t.Fatalf("read append sequence for %s: %v", receiptID, err)
		}
		if gotSequence != wantSequence {
			t.Fatalf("append sequence for %s = %d, want %d", receiptID, gotSequence, wantSequence)
		}
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO receipts (
		receipt_id, decision_id, status, timestamp, executor_id, prev_hash, lamport_clock
	) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		"r-v5-after-append-migration", "d-v5-after-append-migration", "ALLOW", timestamp, "executor", "", 1); err != nil {
		t.Fatalf("insert post-005 receipt: %v", err)
	}
	var newSequence int64
	if err := db.QueryRowContext(ctx, `SELECT append_sequence FROM receipts WHERE receipt_id = $1`, "r-v5-after-append-migration").Scan(&newSequence); err != nil {
		t.Fatalf("read post-005 append sequence: %v", err)
	}
	if newSequence != 3 {
		t.Fatalf("post-005 append sequence = %d, want 3", newSequence)
	}

	store := NewPostgresReceiptStore(db)
	if err := store.Init(ctx); err != nil {
		t.Fatalf("initialize current receipt store after migration: %v", err)
	}
	recovered, err := store.GetByReceiptID(ctx, "r-v5-recoverable")
	if err != nil || recovered.DecisionHash != recoveredHash {
		t.Fatalf("recoverable V5 receipt = %+v err=%v", recovered, err)
	}
	if _, err := store.GetByReceiptID(ctx, "r-v5-unrecoverable"); err == nil || !strings.Contains(err.Error(), "004_add_receipt_decision_hash.sql") {
		t.Fatalf("unrecoverable V5 receipt did not fail closed with migration guidance: %v", err)
	}
	if _, err := db.ExecContext(ctx, `SELECT setval('receipts_append_sequence_seq', 42, true)`); err != nil {
		t.Fatalf("advance append sequence before restart: %v", err)
	}
	if err := store.Init(ctx); err != nil {
		t.Fatalf("initialize receipt store after advanced sequence: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO receipts (receipt_id, decision_id, status, timestamp) VALUES ($1, $2, $3, $4)`, "r-after-sequence-restart", "d-after-sequence-restart", "ALLOW", timestamp); err != nil {
		t.Fatalf("insert after sequence restart: %v", err)
	}
	var afterRestartSequence int64
	if err := db.QueryRowContext(ctx, `SELECT append_sequence FROM receipts WHERE receipt_id = $1`, "r-after-sequence-restart").Scan(&afterRestartSequence); err != nil {
		t.Fatalf("read append sequence after restart: %v", err)
	}
	if afterRestartSequence != 43 {
		t.Fatalf("append sequence after restart = %d, want 43 without rewind", afterRestartSequence)
	}
}

func TestPostgresTenantCursorContinuesWithLateSignedSessionGenesisAfterAppendSequenceMigration(t *testing.T) {
	postgresURL := os.Getenv("HELM_TEST_POSTGRES_URL")
	if postgresURL == "" {
		t.Skip("set HELM_TEST_POSTGRES_URL to run the Postgres receipt cursor migration proof")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	schema := fmt.Sprintf("helm_receipt_cursor_v5_migration_%d", time.Now().UnixNano())
	db, err := sql.Open("postgres", postgresURLWithSearchPath(t, postgresURL, schema))
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.ExecContext(ctx, `CREATE SCHEMA IF NOT EXISTS `+schema); err != nil {
		t.Fatalf("create test schema: %v", err)
	}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		_, _ = db.ExecContext(cleanupCtx, `DROP SCHEMA IF EXISTS `+schema+` CASCADE`)
	}()

	receiptStore := NewPostgresReceiptStore(db)
	if err := receiptStore.Init(ctx); err != nil {
		t.Fatalf("initialize post-005 receipt store: %v", err)
	}
	signer, err := helmcrypto.NewEd25519Signer("postgres-unicode-tenant-cursor")
	if err != nil {
		t.Fatalf("new receipt signer: %v", err)
	}

	const tenantID = "организация-猫"
	issuedAt := time.Date(2026, 8, 2, 0, 0, 0, 123456000, time.UTC)
	appendReceipt := func(sessionID, receiptID string, timestamp time.Time) *contracts.Receipt {
		t.Helper()
		var issued *contracts.Receipt
		err := receiptStore.AppendCausalScoped(ctx, tenantID, sessionID, func(_ *contracts.Receipt, lamport uint64, prevHash string) (*contracts.Receipt, error) {
			issued = storeCoverageReceipt(receiptID, "decision-"+receiptID, sessionID, lamport, timestamp)
			issued.PrevHash = prevHash
			if err := signer.SignReceipt(issued); err != nil {
				return nil, err
			}
			return issued, nil
		})
		if err != nil {
			t.Fatalf("append %s: %v", receiptID, err)
		}
		return issued
	}

	first := appendReceipt("session-a", "receipt-unicode-a", issuedAt)
	second := appendReceipt("session-a", "receipt-unicode-b", issuedAt.Add(time.Second))
	page, err := receiptStore.ListByTenantCursor(ctx, tenantID, TenantReceiptCursor{}, 2)
	if err != nil || len(page) != 2 || page[0].ReceiptID != first.ReceiptID || page[1].ReceiptID != second.ReceiptID {
		t.Fatalf("first unicode tenant cursor page = %+v err=%v", page, err)
	}

	lateGenesis := appendReceipt("session-b", "receipt-unicode-c", issuedAt.Add(-time.Hour))
	if lateGenesis.LamportClock != 1 || lateGenesis.PrevHash != "" {
		t.Fatalf("late signed-session genesis = %+v, want Lamport 1 and empty previous hash", lateGenesis)
	}
	continued, err := receiptStore.ListByTenantCursor(ctx, tenantID, TenantReceiptCursor{
		LamportClock: second.LamportClock,
		Timestamp:    second.Timestamp,
		ReceiptID:    second.ReceiptID,
	}, 1)
	if err != nil || len(continued) != 1 || continued[0].ReceiptID != lateGenesis.ReceiptID {
		t.Fatalf("unicode tenant cursor omitted late signed-session genesis: receipts=%+v err=%v", continued, err)
	}
	if valid, err := signer.VerifyReceipt(continued[0]); err != nil || !valid {
		t.Fatalf("reloaded late signed-session genesis signature: valid=%v err=%v", valid, err)
	}
}

func TestPostgresReceiptChainHashMigrationPreservesIssuedPredecessorAcrossReload(t *testing.T) {
	postgresURL := os.Getenv("HELM_TEST_POSTGRES_URL")
	if postgresURL == "" {
		t.Skip("set HELM_TEST_POSTGRES_URL to run the Postgres receipt chain hash migration proof")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	schema := fmt.Sprintf("helm_receipt_chain_hash_migration_%d", time.Now().UnixNano())
	db, err := sql.Open("postgres", postgresURLWithSearchPath(t, postgresURL, schema))
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.ExecContext(ctx, `CREATE SCHEMA IF NOT EXISTS `+schema); err != nil {
		t.Fatalf("create test schema: %v", err)
	}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		_, _ = db.ExecContext(cleanupCtx, `DROP SCHEMA IF EXISTS `+schema+` CASCADE`)
	}()

	firstStore := NewPostgresReceiptStore(db)
	if err := firstStore.Init(ctx); err != nil {
		t.Fatalf("initialize pre-006 receipt store: %v", err)
	}
	if _, err := db.ExecContext(ctx, `ALTER TABLE receipts DROP COLUMN chain_hash`); err != nil {
		t.Fatalf("remove chain_hash to model pre-006 store: %v", err)
	}
	migration, err := os.ReadFile(filepath.Join("migrations", "006_add_receipt_chain_hash.sql"))
	if err != nil {
		t.Fatalf("read 006 receipt migration: %v", err)
	}
	if _, err := db.ExecContext(ctx, string(migration)); err != nil {
		t.Fatalf("apply 006 receipt migration: %v", err)
	}

	const tenantID = "tenant-chain-hash"
	const sessionID = "session-chain-hash"
	issuedAt := time.Date(2026, 8, 2, 0, 0, 0, 123456000, time.UTC)
	var first *contracts.Receipt
	if err := firstStore.AppendCausalScoped(ctx, tenantID, sessionID, func(_ *contracts.Receipt, lamport uint64, prevHash string) (*contracts.Receipt, error) {
		first = storeCoverageReceipt("receipt-chain-first", "decision-chain-first", sessionID, lamport, issuedAt)
		first.PrevHash = prevHash
		return first, nil
	}); err != nil {
		t.Fatalf("append first receipt: %v", err)
	}
	firstHash, err := contracts.ReceiptChainHash(first)
	if err != nil {
		t.Fatalf("hash first receipt at issuance: %v", err)
	}
	var storedHash string
	if err := db.QueryRowContext(ctx, `SELECT chain_hash FROM receipts WHERE receipt_id = $1`, first.ReceiptID).Scan(&storedHash); err != nil {
		t.Fatalf("read persisted chain hash: %v", err)
	}
	if storedHash != firstHash {
		t.Fatalf("persisted chain hash = %q, want issued hash %q", storedHash, firstHash)
	}
	reloaded, err := firstStore.GetByReceiptID(ctx, first.ReceiptID)
	if err != nil {
		t.Fatalf("reload persisted receipt: %v", err)
	}
	reloadedHash, err := contracts.ReceiptChainHash(reloaded)
	if err != nil || reloadedHash != firstHash {
		t.Fatalf("reloaded receipt chain hash = %q err=%v, want %q", reloadedHash, err, firstHash)
	}
	if reloaded.EmergencyActivationID != first.EmergencyActivationID || reloaded.SafeDepState != first.SafeDepState {
		t.Fatalf("reloaded receipt lost hash-bound safe-deprecation fields: %+v", reloaded)
	}

	secondStore := NewPostgresReceiptStore(db)
	var second *contracts.Receipt
	if err := secondStore.AppendCausalScoped(ctx, tenantID, sessionID, func(previous *contracts.Receipt, lamport uint64, prevHash string) (*contracts.Receipt, error) {
		if previous == nil || previous.ReceiptID != first.ReceiptID {
			t.Fatalf("reloaded predecessor = %+v, want first receipt", previous)
		}
		if prevHash != firstHash {
			t.Fatalf("successor prev_hash = %q, want issued chain hash %q", prevHash, firstHash)
		}
		second = storeCoverageReceipt("receipt-chain-second", "decision-chain-second", sessionID, lamport, issuedAt.Add(time.Second))
		second.PrevHash = prevHash
		return second, nil
	}); err != nil {
		t.Fatalf("append successor after reload: %v", err)
	}
	if second == nil || second.PrevHash != firstHash {
		t.Fatalf("successor = %+v, want prev_hash %q", second, firstHash)
	}
}
